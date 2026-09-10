"""B4 — TLS server fingerprinting (JA4S-style).

BANSHEE opens its own TLS connection to an in-scope target and fingerprints
what the *server* chooses in response: negotiated protocol version, cipher
suite, and ALPN protocol. That is ordinary active scanning of an authorized
host — the only traffic involved is traffic this scanner elicited.

This replaces an earlier implementation that ran a scapy `sniff()` filter on
the wire and fingerprinted ClientHellos it happened to observe. That captured
third parties' TLS sessions to the target — traffic BANSHEE never elicited and
no allowlist authorized — which this project forbids outright. Nothing here
captures; the handshake is ours.

Fingerprint format (JA4S-inspired, not byte-identical to the JA4S spec):

    t<version><alpn>_<cipher-hash>      e.g. ``t13h2_5f0d24c7a1b9``

  * ``version``     — 13/12/11/10/s3 for the negotiated protocol
  * ``alpn``        — first and last character of the ALPN the server picked
                      ("h2", "h1" for http/1.1), "00" when it picked none
  * ``cipher-hash`` — first 12 hex of sha256 over the negotiated cipher name

The real JA4S also encodes the ServerHello extension count and a hash of the
extension list. Python's stdlib TLS API does not expose either, and reading
them would mean hand-rolling a handshake, so those fields are omitted rather
than faked. The result is still stable per server stack and comparable across
hosts in a scan, which is what the classifier and the report use it for.

Degrades to a no-op when the host has no TLS port open, the budget forbids
active probes, or the handshake fails (plaintext port, client-cert required,
protocol too old for the local OpenSSL, ...).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import ssl
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

log = logging.getLogger(__name__)

# Implicit-TLS ports, in probe preference order. STARTTLS ports (25/110/143/587)
# are deliberately absent: they need a protocol-specific upgrade command, and a
# bare TLS handshake there just fails.
_TLS_PORTS: tuple[int, ...] = (443, 8443, 993, 995, 465, 636, 989, 990, 5061, 9443, 8883)

# Offered so the server's *choice* carries information. Order is our preference;
# the server picks.
_ALPN_OFFER = ["h2", "http/1.1"]

_VERSION_CODES = {
    "TLSv1.3": "13",
    "TLSv1.2": "12",
    "TLSv1.1": "11",
    "TLSv1": "10",
    "SSLv3": "s3",
}


def _alpn_code(alpn: str | None) -> str:
    """Two-character ALPN code, JA4-style: first + last char, "00" if none."""
    if not alpn:
        return "00"
    return f"{alpn[0]}{alpn[-1]}"


def _ja4s(version: str | None, cipher: str | None, alpn: str | None) -> str | None:
    """Build the fingerprint from what the server negotiated."""
    if not version or not cipher:
        return None
    ver = _VERSION_CODES.get(version, "00")
    cipher_hash = hashlib.sha256(cipher.encode()).hexdigest()[:12]
    return f"t{ver}{_alpn_code(alpn)}_{cipher_hash}"


def _client_context() -> ssl.SSLContext:
    """A deliberately permissive client context — we fingerprint, never trust.

    Certificates are not validated and hostnames are not checked: targets are
    addressed by IP, self-signed certs are the norm on appliances, and a failed
    validation would cost us the fingerprint we came for. Nothing from this
    connection is used as a trust decision — only the parameters the server
    selected are read, and then the socket is closed.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(ValueError, ssl.SSLError):
        # Let old appliances answer too; a strict local OpenSSL may refuse.
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    with contextlib.suppress(NotImplementedError, ssl.SSLError):
        ctx.set_alpn_protocols(_ALPN_OFFER)
    return ctx


async def _handshake(ip: str, port: int) -> str | None:
    """Complete one TLS handshake with the target; return its JA4S string."""
    reader, writer = await asyncio.open_connection(ip, port, ssl=_client_context())
    del reader
    try:
        sslobj = writer.get_extra_info("ssl_object")
        if sslobj is None:
            return None
        cipher = sslobj.cipher()
        return _ja4s(sslobj.version(), cipher[0] if cipher else None,
                     sslobj.selected_alpn_protocol())
    finally:
        writer.close()
        # A server that drops the connection rather than answering our
        # close_notify is normal here and must not mask the fingerprint.
        with contextlib.suppress(Exception):
            await writer.wait_closed()


class TlsJa4Fingerprinter:
    """B4 — negotiates TLS with the target and records a JA4S-style fingerprint."""

    name = "tls-ja4s-fingerprinter"
    feature_id = "B4"

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:
        if not ctx.budget.can_send():
            return host
        port = self._pick_port(host)
        if port is None:
            return host

        # One TCP connection + handshake; paced and counted like every other
        # active probe.
        await ctx.budget.throttle()
        timeout = ctx.budget.timeout_s or self._timeout
        try:
            ja4s = await asyncio.wait_for(_handshake(host.ip, port), timeout=timeout)
        except Exception as exc:  # TimeoutError is an Exception subclass — covers both
            log.debug("B4 TLS handshake with %s:%d failed: %s", host.ip, port, exc)
            return host

        if ja4s and not host.names.get("ja4s"):
            host.names["ja4s"] = ja4s
            log.debug("B4 %s:%d ja4s=%s", host.ip, port, ja4s)
        return host

    @staticmethod
    def _pick_port(host: Host) -> int | None:
        """First open port that speaks implicit TLS, or None."""
        open_ports = set(host.open_ports)
        for port in _TLS_PORTS:
            if port in open_ports:
                return port
        return None
