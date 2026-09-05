"""B6 — name resolution: reverse DNS, mDNS, and NetBIOS.

Every method here puts a packet on the wire, so each is gated by the budget:
when the budget forbids active probes (``can_send()`` False) this fingerprinter is a complete no-op.

  * reverse DNS — the portable workhorse, via the system resolver.
  * mDNS        — best-effort reverse PTR over 224.0.0.251:5353 (link-local).
  * NetBIOS     — best-effort node-status (NBSTAT) over UDP 137 (Windows LANs).

The mDNS/NetBIOS wire codecs are pure functions (unit-tested); their live socket
paths are wrapped to fail soft, since neither is guaranteed on any given network.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import TYPE_CHECKING

from scanner.core.models import ConfidenceTier

if TYPE_CHECKING:
    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

_MDNS_ADDR = ("224.0.0.251", 5353)
_NETBIOS_PORT = 137
_DNS_PTR = 12
_DNS_IN = 1
_NBSTAT_TYPE = 0x0021
_NB_QUESTION_LEN = 34  # 0x20 length byte + 32 encoded bytes + 0x00 terminator


# --- DNS wire codec (shared by reverse-PTR over mDNS) ---


def encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        raw = label.encode("ascii", "replace")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name; return (name, offset-after-name)."""
    labels: list[str] = []
    pos = offset
    end = offset
    jumped = False
    while pos < len(data):
        length = data[pos]
        if length & 0xC0 == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                break
            if not jumped:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            jumped = True
            continue
        if length == 0:
            if not jumped:
                end = pos + 1
            break
        pos += 1
        labels.append(data[pos : pos + length].decode("ascii", "replace"))
        pos += length
    return ".".join(labels), end


def reverse_ptr_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def build_ptr_query(name: str, txid: int = 0) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0, 1, 0, 0, 0)
    return header + encode_qname(name) + struct.pack("!HH", _DNS_PTR, _DNS_IN)


def parse_first_ptr(resp: bytes) -> str | None:
    """Return the target of the first PTR answer in a DNS response, else None."""
    if len(resp) < 12:
        return None
    qdcount, ancount = struct.unpack_from("!HH", resp, 4)
    pos = 12
    for _ in range(qdcount):
        _, pos = decode_name(resp, pos)
        pos += 4  # qtype + qclass
    for _ in range(ancount):
        _, pos = decode_name(resp, pos)
        if pos + 10 > len(resp):
            return None
        rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", resp, pos)
        pos += 10
        if rtype == _DNS_PTR:
            name, _ = decode_name(resp, pos)
            return name.removesuffix(".") or None
        pos += rdlen
    return None


# --- NetBIOS NBSTAT codec ---


def encode_netbios_name(name: str, suffix: int = 0x20, pad: int = 0x20) -> bytes:
    """First-level NetBIOS name encoding (RFC 1001 §4.1).

    A name is 16 bytes (15 + 1-byte suffix), space-padded for ordinary names. The
    wildcard query name "*" is the exception: ``pad=0x00, suffix=0x00`` yields
    ``b"*" + b"\\x00" * 15`` before nibble encoding.
    """
    raw = name.encode("ascii", "replace")[:15].ljust(15, bytes([pad])) + bytes([suffix])
    out = bytearray([0x20])
    for byte in raw:
        out.append((byte >> 4) + 0x41)
        out.append((byte & 0x0F) + 0x41)
    out.append(0x00)
    return bytes(out)


def build_nbstat_query(txid: int = 0x4150) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0, 1, 0, 0, 0)
    question = encode_netbios_name("*", suffix=0x00, pad=0x00)
    return header + question + struct.pack("!HH", _NBSTAT_TYPE, _DNS_IN)


def parse_nbstat_reply(resp: bytes) -> str | None:
    """Extract the unique workstation name from an NBSTAT response, else None."""
    pos = 12 + _NB_QUESTION_LEN + 4  # header + question name + qtype/qclass
    if pos >= len(resp):
        return None
    pos += 2 if resp[pos] & 0xC0 == 0xC0 else _NB_QUESTION_LEN  # answer name
    pos += 8  # type(2) + class(2) + ttl(4)
    if pos + 3 > len(resp):
        return None
    pos += 2  # rdlength
    count = resp[pos]
    pos += 1
    for _ in range(count):
        if pos + 18 > len(resp):
            break
        entry = resp[pos : pos + 15]
        suffix = resp[pos + 15]
        flags = struct.unpack_from("!H", resp, pos + 16)[0]
        pos += 18
        is_group = bool(flags & 0x8000)
        if suffix == 0x00 and not is_group:
            name = entry.decode("ascii", "replace").strip()
            return name or None
    return None


# --- async probes ---


async def _reverse_dns(ip: str, timeout: float) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        host, _ = await asyncio.wait_for(
            loop.getnameinfo((ip, 0), socket.NI_NAMEREQD), timeout=timeout
        )
    except (TimeoutError, OSError):
        return None
    return host if host and host != ip else None


async def _udp_query(packet: bytes, addr: tuple[str, int], timeout: float) -> bytes | None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        await loop.sock_sendto(sock, packet, addr)
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), timeout=timeout)
        return data
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()


class NameResolver:
    """B6 — populates host.names {rdns, mdns, netbios} and a best hostname."""

    name = "name-resolve"
    feature_id = "B6"

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:
        if not ctx.budget.can_send():
            return host
        timeout = ctx.budget.timeout_s

        await ctx.budget.throttle()
        rdns = await _reverse_dns(host.ip, timeout)
        if rdns is not None:
            host.names["rdns"] = rdns

        if ctx.budget.can_send():
            await ctx.budget.throttle()
            mdns = await self._mdns(host.ip, timeout)
            if mdns is not None:
                host.names["mdns"] = mdns

        if ctx.budget.can_send():
            await ctx.budget.throttle()
            netbios = await self._netbios(host.ip, timeout)
            if netbios is not None:
                host.names["netbios"] = netbios

        resolved = host.names.get("rdns") or host.names.get("mdns") or host.names.get("netbios")
        if resolved is not None and host.hostname is None:
            host.hostname = resolved
            if host.confidence == ConfidenceTier.POTENTIAL:
                host.confidence = ConfidenceTier.PROBABLE
        ctx.audit.log("name_resolve", ip=host.ip, names=dict(host.names))
        return host

    @staticmethod
    async def _mdns(ip: str, timeout: float) -> str | None:
        resp = await _udp_query(build_ptr_query(reverse_ptr_name(ip)), _MDNS_ADDR, timeout)
        return parse_first_ptr(resp) if resp else None

    @staticmethod
    async def _netbios(ip: str, timeout: float) -> str | None:
        resp = await _udp_query(build_nbstat_query(), (ip, _NETBIOS_PORT), timeout)
        return parse_nbstat_reply(resp) if resp else None
