"""A3 — active host discovery via TCP connect.

Portable, unprivileged liveness: attempt async TCP connects to a small set of
common ports. An accepted connect proves the host is up *and* yields a CONFIRMED
open service; a connection-refused also proves the host is up (something answered)
but the port is closed. Timeouts and unreachable errors are treated as no signal.

Honors the StealthBudget (max-detect-risk 0 => zero packets, enforced via `can_send`)
and the ScopeGuard (never touch an out-of-scope IP — defense in depth, since the
engine already scope-filters; and never exceed its `max_ports_per_host` cap). No raw
sockets, no admin required.

Probes are drained by a fixed-size worker pool rather than one task per (host, port),
so a `-p-` sweep of a /24 stays flat in memory instead of building millions of tasks.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

from scanner.core.models import (
    ConfidenceTier,
    Host,
    HostState,
    PortState,
    Proto,
    Service,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from scanner.core.interfaces import ScanContext

# Small, high-signal default probe set: web, remote-admin, file-sharing, db.
PROBE_PORTS: tuple[int, ...] = (80, 443, 22, 445, 3389, 139, 135, 8080, 23, 53)

# Minimal well-known service names for ports we probe (display only).
_WELL_KNOWN: dict[int, str] = {
    22: "ssh",
    23: "telnet",
    53: "domain",
    80: "http",
    135: "msrpc",
    139: "netbios-ssn",
    443: "https",
    445: "microsoft-ds",
    3389: "ms-wbt-server",
    8080: "http-alt",
}

# Per-port probe outcomes.
_OPEN = "open"
_REFUSED = "refused"
_DEAD = "dead"

# Banner read budget. Short on purpose: a server that speaks first does so
# immediately, and one that does not should cost us almost nothing to find out.
_BANNER_BYTES = 256
_BANNER_TIMEOUT_S = 2.0

# Ceiling on simultaneously-live probe tasks. The budget's concurrency bounds how
# many sockets may be open at once; this bounds how many *coroutine objects* exist,
# which is a separate resource. Materialising one task per (host, port) up front —
# 254 hosts x 65535 ports is ~16.6M — costs gigabytes before a single connect.
_MAX_WORKERS = 1024


class TcpSweepDiscoverer:
    """A3 — TCP-connect ping sweep. Unprivileged, cross-platform."""

    name = "tcp-sweep"
    feature_id = "A3"

    def __init__(self, ports: Sequence[int] = PROBE_PORTS) -> None:
        self.ports = tuple(ports)

    async def discover(self, targets: Sequence[str], ctx: ScanContext) -> list[Host]:
        # max-detect-risk 0 => the budget forbids active probes: send nothing.
        if not ctx.budget.can_send():
            ctx.audit.log("discover_skip", discoverer=self.name, reason="passive")
            return []

        in_scope = [ip for ip in targets if ctx.scope.is_in_scope(ip)]
        ports = self._effective_ports(ctx)
        if not in_scope or not ports:
            ctx.audit.log("discover_done", discoverer=self.name, up=0)
            return []

        # (host, port) pairs are produced lazily and drained by a fixed worker pool, so
        # peak memory is O(workers), not O(hosts x ports). Advancing the shared generator
        # is a plain `next()` with no await inside it, so it is atomic for the event loop.
        work = ((ip, port) for ip in in_scope for port in ports)
        results: dict[str, dict[int, tuple[str, str | None]]] = {ip: {} for ip in in_scope}

        async def worker() -> None:
            for ip, port in work:
                outcome, banner = await self._probe_port(ip, port, ctx)
                results[ip][port] = (outcome, banner)

        # Worker count *is* the socket-concurrency bound the semaphore used to provide.
        workers = min(max(1, ctx.budget.concurrency), _MAX_WORKERS, len(in_scope) * len(ports))
        await asyncio.gather(*(worker() for _ in range(workers)))

        hosts = [h for h in (self._build_host(ip, results[ip]) for ip in in_scope) if h is not None]
        ctx.audit.log("discover_done", discoverer=self.name, up=len(hosts))
        return hosts

    def _effective_ports(self, ctx: ScanContext) -> tuple[int, ...]:
        """Apply the scope file's `max_ports_per_host` cap to this run's probe set."""
        cap = ctx.scope.max_ports_per_host
        if cap > 0 and len(self.ports) > cap:
            ctx.audit.log(
                "port_cap",
                discoverer=self.name,
                requested=len(self.ports),
                cap=cap,
            )
            return self.ports[:cap]
        return self.ports

    def _build_host(self, ip: str, probed: dict[int, tuple[str, str | None]]) -> Host | None:
        banners = {port: banner for port, (outcome, banner) in probed.items() if outcome == _OPEN}
        open_ports = list(banners)
        alive = any(outcome in (_OPEN, _REFUSED) for outcome, _ in probed.values())
        if not alive:
            return None

        host = Host(ip=ip, state=HostState.UP, confidence=ConfidenceTier.CONFIRMED)
        for port in sorted(open_ports):
            host.services.append(
                Service(
                    port=port,
                    proto=Proto.TCP,
                    state=PortState.OPEN,
                    name=_WELL_KNOWN.get(port),
                    banner=banners.get(port),
                    confidence=ConfidenceTier.CONFIRMED,
                    source=self.feature_id,
                )
            )
        return host

    async def _probe_port(self, ip: str, port: int, ctx: ScanContext) -> tuple[str, str | None]:
        if not ctx.budget.can_send():
            return _DEAD, None
        await ctx.budget.throttle()
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=ctx.budget.timeout_s)
        except ConnectionRefusedError:
            return _REFUSED, None  # host answered; port closed -> still proves liveness
        except (TimeoutError, OSError):
            return _DEAD, None
        banner = await self._read_banner(reader)
        await self._close(writer)
        return _OPEN, banner

    @staticmethod
    async def _read_banner(reader: asyncio.StreamReader) -> str | None:
        """Read a server-speaks-first greeting, if the service offers one.

        Sends nothing — this only reads from a connection that is already open, so
        it costs no extra packet and does not change the scan's detection profile.
        Protocols that wait for the client (HTTP) simply time out and yield None,
        which is the honest answer: we did not ask, so we did not learn.
        """
        try:
            raw = await asyncio.wait_for(reader.read(_BANNER_BYTES), timeout=_BANNER_TIMEOUT_S)
        except (TimeoutError, OSError, asyncio.IncompleteReadError):
            return None
        if not raw:
            return None
        return raw.decode("utf-8", errors="replace").strip() or None

    @staticmethod
    async def _close(writer: asyncio.StreamWriter) -> None:
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
