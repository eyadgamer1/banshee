"""B4 — TLS JA4 fingerprinting.

Passively captures TLS ClientHello packets on in-scope hosts and computes a
JA4 fingerprint (simplified version: TLS version + cipher count + extension
list hash). This is a passive enricher — no probes sent.

JA4 format (simplified): tls_version-num_ciphers-num_extensions-cipher_hash-ext_hash

Degrades to a no-op if scapy is unavailable or capture permission is absent.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

log = logging.getLogger(__name__)

# TLS content type for handshake
_TLS_HANDSHAKE = 22
_CLIENT_HELLO = 1


def _ja4(tls_ver: int, ciphers: list[int], extensions: list[int]) -> str:
    """Compute a simplified JA4-style fingerprint string."""
    version_map = {0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}
    ver_str = version_map.get(tls_ver, f"{tls_ver:04x}")
    cipher_str = ",".join(f"{c:04x}" for c in sorted(ciphers))
    ext_str = ",".join(f"{e:04x}" for e in sorted(extensions))
    c_hash = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]
    e_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
    return f"t{ver_str}_{len(ciphers):02d}_{len(extensions):02d}_{c_hash}_{e_hash}"


def _parse_client_hello(data: bytes) -> tuple[int, list[int], list[int]] | None:
    """Parse a raw TLS ClientHello record; return (version, ciphers, extensions)."""
    if len(data) < 6:
        return None
    if data[0] != _TLS_HANDSHAKE:
        return None
    if data[5] != _CLIENT_HELLO:
        return None
    try:
        offset = 9  # skip record header (5) + handshake header (4)
        if offset + 2 > len(data):
            return None
        client_version = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2 + 32  # skip version + random
        # session id
        if offset >= len(data):
            return None
        sid_len = data[offset]
        offset += 1 + sid_len
        # cipher suites
        if offset + 2 > len(data):
            return None
        cs_len = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        ciphers = []
        for _ in range(cs_len // 2):
            if offset + 2 > len(data):
                break
            ciphers.append(int.from_bytes(data[offset : offset + 2], "big"))
            offset += 2
        # compression
        if offset >= len(data):
            return None
        comp_len = data[offset]
        offset += 1 + comp_len
        # extensions
        extensions: list[int] = []
        if offset + 2 <= len(data):
            ext_total = int.from_bytes(data[offset : offset + 2], "big")
            offset += 2
            end = offset + ext_total
            while offset + 4 <= end and offset + 4 <= len(data):
                ext_type = int.from_bytes(data[offset : offset + 2], "big")
                ext_len = int.from_bytes(data[offset + 2 : offset + 4], "big")
                extensions.append(ext_type)
                offset += 4 + ext_len
        return client_version, ciphers, extensions
    except Exception:
        return None


class TlsJa4Fingerprinter:
    """B4 — captures ClientHello packets and attaches JA4 fingerprint to host."""

    name = "tls-ja4-fingerprinter"
    feature_id = "B4"

    def __init__(self, iface: str | None = None, timeout: float = 5.0) -> None:
        self._iface = iface
        self._timeout = timeout

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:
        """Listen for TLS from this host for a short window."""
        if not ctx.budget.can_send():
            return host
        # Only attempt if host has port 443 or other TLS ports open
        tls_ports = {443, 8443, 8080, 636, 993, 995, 465, 587}
        has_tls = any(p in tls_ports for p in host.open_ports)
        if not has_tls:
            return host

        loop = asyncio.get_running_loop()
        try:
            ja4 = await asyncio.wait_for(
                loop.run_in_executor(None, self._sniff_sync, host.ip),
                timeout=self._timeout + 2,
            )
        except Exception as exc:  # TimeoutError is an Exception subclass — covers both
            log.debug("B4 TLS sniff for %s failed: %s", host.ip, exc)
            return host

        if ja4:
            if not host.names.get("ja4"):
                host.names["ja4"] = ja4
        return host

    def _sniff_sync(self, ip: str) -> str | None:
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.sendrecv import sniff
        except Exception:
            return None

        found: list[str] = []

        def _handle(pkt: Any) -> None:
            try:
                if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                    return
                if str(pkt[IP].src) != ip:
                    return
                raw = bytes(pkt[TCP].payload)
                parsed = _parse_client_hello(raw)
                if parsed:
                    version, ciphers, exts = parsed
                    found.append(_ja4(version, ciphers, exts))
            except Exception:
                pass

        bpf = f"tcp and host {ip} and (port 443 or port 8443 or port 993)"
        try:
            sniff(filter=bpf, prn=_handle, timeout=self._timeout, iface=self._iface, store=False)
        except Exception as exc:
            log.debug("B4 sniff error: %s", exc)
        return found[0] if found else None
