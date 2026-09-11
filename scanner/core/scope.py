"""E5 — Scope guard. The authoritative safety boundary.

Nothing in this tool may touch a target that is not inside the scope.yaml
allowlist (and not in the denylist). The guard is consulted by the engine
before any discoverer/fingerprinter runs, and every decision is audit-logged.

LLM may *propose*; this guard *enforces*. There is no override flag.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from collections.abc import Iterable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

DEFAULT_BANNER = "AUTHORIZED TARGETS ONLY"

log = logging.getLogger(__name__)


class ScopeViolationError(Exception):
    """Raised when a target falls outside the authorized scope."""

    def __init__(self, target: str, reason: str = "not in allowlist") -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"Scope violation: {target} — {reason}")


class AuditLog:
    """Append-only JSONL audit trail. Records every scope decision and action."""

    def __init__(self, path: str | None) -> None:
        self.path = Path(path) if path else None
        self._buffer: list[dict[str, object]] = []
        self._warned = False

    def log(self, event: str, **fields: object) -> None:
        entry: dict[str, object] = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            **fields,
        }
        self._buffer.append(entry)
        if self.path is not None:
            try:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
            except OSError as exc:
                # An unwritable audit path must not abort a scan mid-flight with a
                # traceback — the run is still authorized and still enforced. Warn
                # once and keep the in-memory buffer, so the operator learns the
                # trail is not landing instead of losing the whole scan to it.
                if not self._warned:
                    self._warned = True
                    log.warning("audit log %s is not writable (%s); continuing", self.path, exc)

    @property
    def entries(self) -> list[dict[str, object]]:
        return list(self._buffer)


def _positive_limit(data: dict[str, object], key: str, default: int, path: str | Path) -> int:
    """Read a positive integer limit from the scope file, or refuse the file.

    A limit of 0 or a negative number is not a meaningful cap — it reads as
    "allow nothing", which no caller implements — and it was previously accepted
    silently, so a typo'd scope file looked enforced while capping nothing at all.
    A limit is a safety control, so a broken one fails the load instead of being
    quietly replaced by a default the operator never chose.
    """
    raw = data.get(key, default)
    if not isinstance(raw, int | str | float) or isinstance(raw, bool):
        raise ValueError(f"{path}: {key} must be a positive integer, got {raw!r}")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{path}: {key} must be a positive integer, got {raw!r}") from None
    if value < 1:
        raise ValueError(f"{path}: {key} must be at least 1, got {value}")
    return value


class ScopeGuard:
    """Loads scope.yaml and enforces the allowlist/denylist boundary."""

    def __init__(
        self,
        allowlist: Iterable[str],
        denylist: Iterable[str] = (),
        banner: str = DEFAULT_BANNER,
        max_hosts_per_scan: int = 1024,
        max_ports_per_host: int = 1000,
        audit: AuditLog | None = None,
    ) -> None:
        self.allow: list[IPNetwork] = [ipaddress.ip_network(c, strict=False) for c in allowlist]
        self.deny: list[IPNetwork] = [ipaddress.ip_network(c, strict=False) for c in denylist]
        self.banner = banner
        self.max_hosts_per_scan = max_hosts_per_scan
        self.max_ports_per_host = max_ports_per_host
        self.audit = audit or AuditLog(None)

    @classmethod
    def from_file(cls, path: str | Path, audit: AuditLog | None = None) -> ScopeGuard:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls(
            allowlist=data.get("allowlist", []),
            denylist=data.get("denylist", []),
            banner=data.get("banner", DEFAULT_BANNER),
            max_hosts_per_scan=_positive_limit(data, "max_hosts_per_scan", 1024, path),
            max_ports_per_host=_positive_limit(data, "max_ports_per_host", 1000, path),
            audit=audit,
        )

    def _addr(self, target: str) -> IPAddress | None:
        try:
            return ipaddress.ip_address(target)
        except ValueError:
            return None

    def is_in_scope(self, target: str) -> bool:
        """True iff target is an IP inside an allow net and outside every deny net."""
        addr = self._addr(target)
        if addr is None:
            return False
        if any(addr in net for net in self.deny):
            return False
        return any(addr in net for net in self.allow)

    def check(self, target: str) -> None:
        """Raise ScopeViolationError if target is out of scope. Always audited."""
        addr = self._addr(target)
        if addr is None:
            self.audit.log("scope_reject", target=target, reason="unresolved")
            raise ScopeViolationError(target, "could not resolve to an IP address")
        if any(addr in net for net in self.deny):
            self.audit.log("scope_reject", target=target, reason="denylist")
            raise ScopeViolationError(target, "matched denylist")
        if not any(addr in net for net in self.allow):
            self.audit.log("scope_reject", target=target, reason="not in allowlist")
            raise ScopeViolationError(target, "not in allowlist")
        self.audit.log("scope_accept", target=target)

    def filter_targets(self, targets: Iterable[str]) -> tuple[list[str], list[str]]:
        """Partition expanded targets into (in_scope, out_of_scope) without raising."""
        in_scope: list[str] = []
        out_scope: list[str] = []
        for t in targets:
            (in_scope if self.is_in_scope(t) else out_scope).append(t)
        if out_scope:
            self.audit.log("scope_filtered_out", count=len(out_scope), samples=out_scope[:5])
        return in_scope, out_scope
