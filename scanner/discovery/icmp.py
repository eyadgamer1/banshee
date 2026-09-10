"""A3 (privileged extension) — ICMP echo ping.

Best-effort raw-socket liveness. Raw ICMP sockets require privilege on every
mainstream OS; when one cannot be opened (unprivileged shell, sandbox, platform
restriction) this discoverer logs the reason and degrades to a clean no-op so the
TCP sweep can still carry the scan. Honors the budget and scope like every probe.

A single raw socket receives *all* host ICMP replies, so each echo carries a
distinct sequence number. Attribution requires **both** that (id, seq) match a probe
we actually sent *and* that the reply's source address is the host that probe was
sent to: (id, seq) alone is guessable by anything sharing the broadcast domain, so
matching on it would let one rogue device forge "up/CONFIRMED" for every address in
the sweep. id and seq are drawn from a CSPRNG so they are not guessable either.
"""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
import socket
import struct
from typing import TYPE_CHECKING

from scanner.core.models import ConfidenceTier, Host, HostState

if TYPE_CHECKING:
    from collections.abc import Sequence

    from scanner.core.interfaces import ScanContext

_ICMP_ECHO_REQUEST = 8
_ICMP_ECHO_REPLY = 0
_IP_MIN_HEADER = 20
_ICMP_HEADER = struct.Struct("!BBHHH")  # type, code, checksum, id, seq


def icmp_checksum(data: bytes) -> int:
    """RFC 1071 internet checksum over `data` (one's-complement 16-bit sum)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _build_echo(ident: int, seq: int, payload: bytes = b"banshee-discovery") -> bytes:
    header = _ICMP_HEADER.pack(_ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    checksum = icmp_checksum(header + payload)
    header = _ICMP_HEADER.pack(_ICMP_ECHO_REQUEST, 0, checksum, ident, seq)
    return header + payload


def _parse_reply(packet: bytes) -> tuple[int, int] | None:
    """Return (id, seq) of an ICMP echo reply, or None if it is not one."""
    ihl = (packet[0] & 0x0F) * 4 if packet else 0
    if ihl < _IP_MIN_HEADER or len(packet) < ihl + _ICMP_HEADER.size:
        return None
    icmp_type, _, _, ident, seq = _ICMP_HEADER.unpack_from(packet, ihl)
    if icmp_type != _ICMP_ECHO_REPLY:
        return None
    return ident, seq


def _norm_ip(value: str) -> str:
    """Canonical form of an address string, so two spellings of one host compare equal."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


class IcmpPingDiscoverer:
    """A3 — ICMP echo sweep. Privileged; no-ops gracefully without a raw socket."""

    name = "icmp-ping"
    feature_id = "A3"

    async def discover(self, targets: Sequence[str], ctx: ScanContext) -> list[Host]:
        if not ctx.budget.can_send():
            ctx.audit.log("discover_skip", discoverer=self.name, reason="passive")
            return []

        in_scope = [ip for ip in targets if ctx.scope.is_in_scope(ip)]
        if not in_scope:
            return []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except (PermissionError, OSError) as exc:
            # Expected on unprivileged hosts — the TCP sweep covers liveness instead.
            ctx.audit.log("icmp_unavailable", discoverer=self.name, reason=str(exc))
            return []

        try:
            return await self._sweep(sock, in_scope, ctx)
        finally:
            sock.close()

    async def _sweep(
        self, sock: socket.socket, targets: list[str], ctx: ScanContext
    ) -> list[Host]:
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        # Unpredictable id/seq: os.getpid() and a 0,1,2,... index are trivially
        # guessable by anything on the wire. Source verification below is the
        # load-bearing check, but there is no reason to hand out free identifiers.
        rng = secrets.SystemRandom()
        ident = rng.randrange(1, 0x10000)
        base = rng.randrange(0x10000)
        stride = rng.randrange(1, 0x10000) | 1  # odd => walks all 65536 seqs before repeating
        seq_to_ip: dict[int, str] = {}

        for index, ip in enumerate(targets):
            if not ctx.budget.can_send():
                break
            seq = (base + index * stride) & 0xFFFF
            if seq in seq_to_ip:
                # >65535 targets in one sweep exhausts the sequence space. Skip rather
                # than let two targets share an identifier and blur attribution.
                ctx.audit.log("icmp_seq_exhausted", ip=ip)
                continue
            await ctx.budget.throttle()
            try:
                await loop.sock_sendto(sock, _build_echo(ident, seq), (ip, 0))
            except OSError as exc:
                ctx.audit.log("icmp_send_fail", ip=ip, reason=str(exc))
                continue
            # Only a probe that actually went out is attributable.
            seq_to_ip[seq] = ip

        alive: set[str] = set()
        unattributable = 0
        deadline = loop.time() + ctx.budget.timeout_s
        while seq_to_ip and loop.time() < deadline:
            remaining = deadline - loop.time()
            try:
                packet, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 1024), timeout=remaining
                )
            except (TimeoutError, OSError):
                break
            parsed = _parse_reply(packet)
            if parsed is None or parsed[0] != ident:
                continue
            expected = seq_to_ip.get(parsed[1])
            source = str(addr[0]) if addr else ""
            if expected is None or _norm_ip(expected) != _norm_ip(source):
                # Either a sequence number we never sent, or the right sequence number
                # from the wrong host — a spoofed/racing reply, not evidence of life.
                unattributable += 1
                continue
            del seq_to_ip[parsed[1]]
            alive.add(expected)

        if unattributable:
            ctx.audit.log(
                "icmp_reply_unattributable", discoverer=self.name, dropped=unattributable
            )
        ctx.audit.log("discover_done", discoverer=self.name, up=len(alive))
        return [
            Host(ip=ip, state=HostState.UP, confidence=ConfidenceTier.CONFIRMED) for ip in alive
        ]
