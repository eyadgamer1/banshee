"""A1 — Async scan engine.

Owns the run lifecycle: expand targets -> scope-filter -> (dry-run plan | discover ->
fingerprint) -> assemble ScanResult. Discoverers and Fingerprinters are injected
(see core.interfaces); the engine never imports concrete modules, so each can be
built and tested in isolation.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from scanner.core.budget import StealthBudget
from scanner.core.interfaces import AuditLogger, Discoverer, Fingerprinter
from scanner.core.models import Host, HostState, ScanConfig, ScanResult, Service
from scanner.core.scope import ScopeGuard, ScopeViolationError

ProgressHook = Callable[[str, dict[str, object]], None]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class RunContext:
    """Concrete ScanContext handed to every injected component."""

    def __init__(self, scope: ScopeGuard, budget: StealthBudget, audit: AuditLogger) -> None:
        self._scope = scope
        self._budget = budget
        self._audit = audit

    @property
    def scope(self) -> ScopeGuard:
        return self._scope

    @property
    def budget(self) -> StealthBudget:
        return self._budget

    @property
    def audit(self) -> AuditLogger:
        return self._audit


def expand_target(token: str) -> list[str]:
    """Expand one target token into concrete IP strings.

    Supports: single IP, CIDR (1.2.3.0/24), last-octet range (1.2.3.10-20),
    and full range (1.2.3.10-1.2.3.20). Hostnames are returned as-is for the
    async resolver step. Never performs network I/O.
    """
    token = token.strip()
    if not token:
        return []
    # CIDR
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
            return [str(ip) for ip in net.hosts()] or [str(net.network_address)]
        except ValueError:
            return [token]
    # range
    if "-" in token:
        left, right = token.rsplit("-", 1)
        try:
            start = ipaddress.ip_address(left)
            if "." in right or ":" in right:
                end = ipaddress.ip_address(right)
            else:  # last-octet shorthand
                prefix = left.rsplit(".", 1)[0]
                end = ipaddress.ip_address(f"{prefix}.{right}")
            if int(end) < int(start):
                return [token]
            return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        except ValueError:
            return [token]
    return [token]


class ScanEngine:
    """Drives a single scan from ScanConfig to ScanResult."""

    def __init__(
        self,
        scope: ScopeGuard,
        budget: StealthBudget,
        discoverers: Sequence[Discoverer],
        fingerprinters: Sequence[Fingerprinter],
        progress: ProgressHook | None = None,
    ) -> None:
        self.scope = scope
        self.budget = budget
        self.discoverers = list(discoverers)
        self.fingerprinters = list(fingerprinters)
        self.progress = progress
        self.ctx = RunContext(scope, budget, scope.audit)

    def _emit(self, event: str, **fields: object) -> None:
        if self.progress is not None:
            self.progress(event, fields)

    async def _resolve(self, tokens: list[str]) -> list[str]:
        """Resolve any non-IP tokens to IPs via getaddrinfo (best-effort)."""
        loop = asyncio.get_running_loop()
        out: list[str] = []
        for tok in tokens:
            try:
                ipaddress.ip_address(tok)
                out.append(tok)
                continue
            except ValueError:
                pass
            try:
                infos = await loop.getaddrinfo(tok, None)
                resolved = {str(info[4][0]) for info in infos}
                self.scope.audit.log("resolve", host=tok, ips=sorted(resolved))
                out.extend(sorted(resolved))
            except (socket.gaierror, OSError):
                self.scope.audit.log("resolve_fail", host=tok)
        return out

    async def run(self, cfg: ScanConfig) -> ScanResult:
        result = ScanResult(config=cfg, banner=self.scope.banner, started_at=_utcnow())
        self.scope.audit.log("scan_start", mode=cfg.mode.value, targets=cfg.targets)

        expanded: list[str] = []
        for tok in cfg.targets:
            expanded.extend(expand_target(tok))
        expanded = await self._resolve(expanded)
        # de-dup, preserve order
        seen: set[str] = set()
        deduped: list[str] = []
        for ip in expanded:
            if ip not in seen:
                seen.add(ip)
                deduped.append(ip)
        expanded = deduped
        result.stats.targets_requested = len(expanded)

        in_scope, out_scope = self.scope.filter_targets(expanded)
        result.stats.targets_in_scope = len(in_scope)
        result.stats.targets_out_of_scope = len(out_scope)
        self._emit("scope", in_scope=len(in_scope), out_of_scope=len(out_scope))

        # Contract (E5): if every resolved target is out of scope, this is an explicit
        # attempt to scan unauthorized hosts — refuse loudly rather than silently scan
        # nothing. A partial CIDR overlap (some in-scope) still proceeds on the allowed
        # subset; an all-DNS-failure (nothing resolved) yields an empty result, not a
        # violation.
        if expanded and not in_scope:
            self.scope.audit.log("scope_violation", out_of_scope=out_scope[:10])
            raise ScopeViolationError(
                ", ".join(out_scope[:3]) + ("..." if len(out_scope) > 3 else ""),
                "no requested target is inside the scope allowlist",
            )

        if len(in_scope) > self.scope.max_hosts_per_scan:
            self.scope.audit.log(
                "host_cap", requested=len(in_scope), cap=self.scope.max_hosts_per_scan
            )
            in_scope = in_scope[: self.scope.max_hosts_per_scan]

        if cfg.dry_run:
            result.hosts = [Host(ip=ip, state=HostState.UNKNOWN) for ip in in_scope]
            result.finished_at = _utcnow()
            self.scope.audit.log("dry_run", planned=len(in_scope))
            self._emit("done", dry_run=True, planned=len(in_scope))
            return result

        hosts = await self._discover(in_scope)
        if cfg.fingerprint and self.fingerprinters:
            await self._fingerprint(list(hosts.values()))

        result.hosts = sorted(hosts.values(), key=lambda h: ipaddress.ip_address(h.ip))
        result.stats.hosts_up = len(result.up_hosts)
        result.stats.services_found = sum(len(h.services) for h in result.hosts)
        result.stats.findings = sum(len(h.findings) for h in result.hosts)
        result.stats.packets_sent = self.budget.packets_sent
        result.finished_at = _utcnow()
        self.scope.audit.log("scan_done", hosts_up=result.stats.hosts_up)
        self._emit("done", hosts_up=result.stats.hosts_up)
        return result

    async def _discover(self, targets: list[str]) -> dict[str, Host]:
        hosts: dict[str, Host] = {}
        for disc in self.discoverers:
            self._emit("discover_start", discoverer=disc.name)
            found = await disc.discover(targets, self.ctx)
            for h in found:
                if h.ip in hosts:
                    self._merge(hosts[h.ip], h)
                else:
                    hosts[h.ip] = h
                self._emit("host", ip=h.ip, state=h.state.value)
        return hosts

    async def _fingerprint(self, hosts: list[Host]) -> None:
        up = [h for h in hosts if h.state == HostState.UP]
        sem = self.budget.make_semaphore()

        async def one(host: Host) -> None:
            async with sem:
                for fp in self.fingerprinters:
                    await fp.fingerprint(host, self.ctx)
                    self._emit("fingerprint", ip=host.ip, by=fp.name)

        await asyncio.gather(*(one(h) for h in up))

    @staticmethod
    def _merge(into: Host, other: Host) -> None:
        """Fold a duplicate discovery of the same IP into the existing host.

        Services and findings are de-duplicated so that two discoverers seeing the
        same IP (e.g. the passive sniffer and the TCP sweep both reporting :80) do
        not inflate service/finding counts or list a port twice.
        """
        if other.state == HostState.UP:
            into.state = HostState.UP
        into.mac = into.mac or other.mac
        into.hostname = into.hostname or other.hostname
        into.vendor = into.vendor or other.vendor
        into.os_guess = into.os_guess or other.os_guess
        into.device_type = into.device_type or other.device_type
        # names: keep existing keys, only add new ones (don't clobber stronger sources)
        for key, value in other.names.items():
            into.names.setdefault(key, value)
        _merge_services(into, other.services)
        seen_findings = {f.id for f in into.findings}
        into.findings.extend(f for f in other.findings if f.id not in seen_findings)
        into.last_seen = _utcnow()


def _merge_services(into: Host, incoming: list[Service]) -> None:
    """Add services from `incoming` not already present, keyed by (port, proto)."""
    existing = {(s.port, s.proto) for s in into.services}
    for svc in incoming:
        key = (svc.port, svc.proto)
        if key not in existing:
            into.services.append(svc)
            existing.add(key)
