"""A3 — active host discovery via TCP connect.

Portable, unprivileged liveness: attempt async TCP connects to a small set of
common ports. An accepted connect proves the host is up *and* yields a CONFIRMED
open service; a connection-refused also proves the host is up (something answered)
but the port is closed. Timeouts and unreachable errors are treated as no signal.

Honors the StealthBudget (PASSIVE mode => zero packets, enforced via `can_send`)
and the ScopeGuard (never touch an out-of-scope IP — defense in depth, since the
engine already scope-filters). No raw sockets, no admin required.
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


class TcpSweepDiscoverer:
    """A3 — TCP-connect ping sweep. Unprivileged, cross-platform."""

    name = "tcp-sweep"
    feature_id = "A3"

    def __init__(self, ports: Sequence[int] = PROBE_PORTS) -> None:
        self.ports = tuple(ports)

    async def discover(self, targets: Sequence[str], ctx: ScanContext) -> list[Host]:
        # PASSIVE / max-detect-risk 0 => the budget forbids active probes: send nothing.
        if not ctx.budget.can_send():
            ctx.audit.log("discover_skip", discoverer=self.name, reason="passive")
            return []

        in_scope = [ip for ip in targets if ctx.scope.is_in_scope(ip)]
        sem = ctx.budget.make_semaphore()

        async def scan(ip: str) -> Host | None:
            return await self._scan_host(ip, ctx, sem)

        found = await asyncio.gather(*(scan(ip) for ip in in_scope))
        hosts = [h for h in found if h is not None]
        ctx.audit.log("discover_done", discoverer=self.name, up=len(hosts))
        return hosts

    async def _scan_host(self, ip: str, ctx: ScanContext, sem: asyncio.Semaphore) -> Host | None:
        async def probe(port: int) -> tuple[int, str, str | None]:
            async with sem:
                outcome, banner = await self._probe_port(ip, port, ctx)
                return port, outcome, banner

        results = await asyncio.gather(*(probe(p) for p in self.ports))
        banners = {port: banner for port, outcome, banner in results if outcome == _OPEN}
        open_ports = [port for port, outcome, _ in results if outcome == _OPEN]
        alive = any(outcome in (_OPEN, _REFUSED) for _, outcome, _ in results)
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
