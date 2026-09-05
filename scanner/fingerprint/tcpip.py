"""B3 — TCP/IP stack fingerprinting via TTL + window-size heuristics.

Sends a SYN to a known-open port and inspects the SYN-ACK's IP TTL and TCP
window size. Combines with any prior TTL observations to infer the OS family.

Degrades to a no-op when:
  - scapy raw-socket permission is unavailable
  - budget disallows active probing (max-detect-risk 0)
  - no open port is known for the host yet

This is a lightweight approximation — sufficient for device-type disambiguation
without a full nmap p0f database.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

log = logging.getLogger(__name__)

# (os_guess, device_hint) keyed by (ttl_bucket, window_bucket)
# TTL buckets: 64, 128, 255 (initial values after router hops are ignored for now)
# Window buckets: small (<8k), medium (8k-32k), large (>32k)
_OS_TABLE: dict[tuple[int, str], tuple[str, str]] = {
    (64, "large"): ("Linux", "server/workstation"),
    (64, "medium"): ("Linux", "embedded/IoT"),
    (64, "small"): ("Linux", "IoT"),
    (128, "large"): ("Windows", "workstation/server"),
    (128, "medium"): ("Windows", "workstation"),
    (128, "small"): ("Windows", "embedded"),
    # TTL=255 is initial value for Cisco IOS, FreeBSD, macOS, Solaris, AND many
    # cloud load balancers (AWS Global Accelerator, ALB/NLB, Vercel edge). A large
    # TCP window strongly suggests a modern OS or cloud LB rather than IOS/classic
    # router, so we use an ambiguous label. Small window stays router-biased.
    (255, "large"):  ("network device / FreeBSD / cloud-LB", "router/switch/lb"),
    (255, "medium"): ("network device / FreeBSD", "router/switch"),
    (255, "small"):  ("Cisco IOS / network device", "router/switch"),
}


def _ttl_bucket(ttl: int) -> int:
    """Round observed TTL up to the nearest common initial value."""
    for threshold in (64, 128, 255):
        if ttl <= threshold:
            return threshold
    return 255


def _win_bucket(window: int) -> str:
    if window < 8192:
        return "small"
    if window < 32768:
        return "medium"
    return "large"


class TcpIpFingerprinter:
    """B3 — infers OS family from SYN-ACK TTL + window size."""

    name = "tcpip-fingerprinter"
    feature_id = "B3"

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:
        if not ctx.budget.can_send():
            return host
        if not host.open_ports:
            return host  # nothing to probe

        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(
                None, self._probe_sync, host.ip, host.open_ports[0]
            )
        except Exception as exc:
            log.debug("B3 probe %s failed: %s", host.ip, exc)
            return host

        if result:
            ttl, window = result
            tb = _ttl_bucket(ttl)
            wb = _win_bucket(window)
            entry = _OS_TABLE.get((tb, wb))
            if entry and not host.os_guess:
                host.os_guess = entry[0]
                if not host.device_type:
                    host.device_type = entry[1]
        return host

    def _probe_sync(self, ip: str, port: int) -> tuple[int, int] | None:
        """Send SYN, wait for SYN-ACK, return (ttl, window). Needs raw sockets."""
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.sendrecv import sr1
        except Exception:
            return None

        try:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp and resp.haslayer(TCP):
                ttl = resp[IP].ttl if resp.haslayer(IP) else 64
                window = resp[TCP].window
                # Send RST to clean up
                rst = IP(dst=ip) / TCP(dport=port, flags="R", seq=resp[TCP].ack)
                sr1(rst, timeout=1, verbose=0)
                return int(ttl), int(window)
        except Exception as exc:
            log.debug("B3 raw socket error for %s:%d — %s", ip, port, exc)
        return None
