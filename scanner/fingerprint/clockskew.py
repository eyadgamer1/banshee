"""B7 — TCP timestamp clock-skew fingerprinting.

Sends a SYN to an open port and reads the TCP timestamp option from the SYN-ACK.
By comparing the remote clock's TSval against local time we can estimate the
remote host's uptime and detect VM/container environments (skew > threshold).

Skew categories:
  near-zero  → VM or NTP-synced host (< 1 ppm)
  normal     → physical machine, NTP drift (1–200 ppm)
  high       → no NTP, clock drift (200–2000 ppm)
  extreme    → wrapped counter or spoofed timestamp

Only runs if mode != PASSIVE and an open TCP port is known.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

log = logging.getLogger(__name__)

_PROBE_PORTS = [80, 443, 22, 8080, 8443, 3389, 23, 21]

# Real servers drift ≤2000 ppm from a nominal tick rate; anything beyond this is two
# different physical nodes answering (anycast) rather than a single drifting clock.
_ANYCAST_PPM_THRESHOLD = 2000.0
# Two consecutive interval Hz estimates disagreeing by more than this fraction means
# different nodes answered the probes — anycast.
_ANYCAST_HZ_DISAGREE = 0.4
# If our own two wall-clock probe intervals differ by more than this fraction, the
# path jitter is large enough to explain the Hz disagreement on its own, so no
# anycast conclusion can be drawn from it.
_WALL_JITTER_LIMIT = 0.25


class ClockSkewFingerprinter:
    name = "clock-skew"
    feature_id = "B7"

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:
        if not ctx.budget.allow_active_probes:
            return host
        port = self._pick_port(host)
        if port is None:
            return host
        skew_ppm = await _probe_skew(host.ip, port)
        if skew_ppm is None:
            return host

        # Sentinel -1.0 means anycast CDN detected (two probes hit different nodes)
        if skew_ppm == -1.0:
            host.names["clock_skew_cat"] = "anycast-cdn"
            from scanner.core.models import ConfidenceTier, Finding, Severity
            host.findings.append(Finding(
                id=f"B7-anycast-{host.ip.replace('.', '_')}",
                title="Anycast/CDN detected — clock skew unreliable",
                severity=Severity.INFO,
                confidence=ConfidenceTier.PROBABLE,
                description=(
                    "Two TCP timestamp probes returned TSval counters from different "
                    "scales, indicating each probe landed on a different anycast edge "
                    "node. Clock skew cannot be computed. Host is likely a CDN or "
                    "anycast-distributed service."
                ),
                source="B7",
            ))
            log.debug("B7 %s anycast-cdn detected", host.ip)
            return host

        category = _categorize(skew_ppm)
        host.names["clock_skew_ppm"] = str(int(skew_ppm))
        host.names["clock_skew_cat"] = category
        if category == "near-zero":
            # Likely VM — add a low-severity note
            from scanner.core.models import ConfidenceTier, Finding, Severity
            host.findings.append(Finding(
                id=f"B7-vm-{host.ip.replace('.', '_')}",
                title="Clock skew suggests VM or container",
                severity=Severity.INFO,
                confidence=ConfidenceTier.PROBABLE,
                description=(
                    f"TCP timestamp clock skew is near-zero ({int(skew_ppm)} ppm), "
                    "which is typical for VMs with synchronised clocks."
                ),
                source="B7",
            ))
        log.debug("B7 %s skew=%d ppm cat=%s", host.ip, int(skew_ppm), category)
        return host

    def _pick_port(self, host: Host) -> int | None:
        for p in _PROBE_PORTS:
            if p in host.open_ports:
                return p
        return host.open_ports[0] if host.open_ports else None


async def _probe_skew(ip: str, port: int) -> float | None:
    """Return clock skew in ppm, or None if unavailable."""
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _probe_sync, ip, port)


def _probe_sync(ip: str, port: int) -> float | None:
    """Three-probe clock skew: measure how fast remote TSval ticks vs wall clock.

    Returns ppm skew, the -1.0 anycast sentinel, or None if unavailable.
    """
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.sendrecv import sr1

        def _syn(ts: int) -> tuple[float, int | None]:
            pkt = IP(dst=ip) / TCP(
                dport=port,
                flags="S",
                options=[("Timestamp", (ts, 0))],
            )
            ans = sr1(pkt, timeout=2, verbose=0)
            t_recv = time.time()
            if ans is None or not ans.haslayer(TCP):
                return t_recv, None
            tcp_layer = ans[TCP]
            if tcp_layer.flags & 0x04:  # RST — no TSval in RST
                return t_recv, None
            for opt_name, opt_val in (tcp_layer.options or []):
                if opt_name == "Timestamp":
                    return t_recv, int(opt_val[0])
            return t_recv, None

        # Three-probe majority vote: reduces anycast false positives caused by two
        # consecutive probes accidentally landing on the same physical node.
        # We compute Hz estimates from two consecutive intervals (1→2, 2→3).
        # If both agree within 40%, we have a consistent clock → not anycast.
        # If they disagree wildly, different nodes answered → anycast sentinel.
        ts1 = int(time.time() * 100) & 0xFFFFFFFF
        t1, r1 = _syn(ts1)
        if r1 is None:
            return None

        time.sleep(0.3)

        ts2 = int(time.time() * 100) & 0xFFFFFFFF
        t2, r2 = _syn(ts2)
        if r2 is None:
            return None

        time.sleep(0.3)

        ts3 = int(time.time() * 100) & 0xFFFFFFFF
        t3, r3 = _syn(ts3)
        # If probe 3 fails (r3 is None) we fall back to the two-probe estimate below.

        wall12 = t2 - t1
        wall23 = t3 - t2 if r3 is not None else None

        if wall12 <= 0.01:
            return None

        remote12 = (r2 - r1) & 0xFFFFFFFF
        if remote12 == 0:
            return None

        hz12 = remote12 / wall12

        if r3 is not None and wall23 is not None and wall23 > 0.01:
            remote23 = (r3 - r2) & 0xFFFFFFFF
            hz23 = remote23 / wall23 if remote23 > 0 else hz12
            # If the two intervals produce wildly different Hz estimates, different
            # physical nodes responded — mark anycast regardless of magnitude.
            hz_max = max(hz12, hz23)
            if hz_max > 0 and abs(hz12 - hz23) / hz_max > _ANYCAST_HZ_DISAGREE:
                # ...unless our own measurement is too noisy to tell. Over a
                # long-haul WAN path, RTT jitter alone skews the two interval
                # estimates past the threshold, which made single-homed hosts
                # abroad report as anycast. When the wall-clock intervals we
                # measured disagree that much themselves, the input is unreliable
                # and the honest answer is "unknown", not "anycast".
                wall_max = max(wall12, wall23)
                jittery = wall_max > 0 and abs(wall12 - wall23) / wall_max > _WALL_JITTER_LIMIT
                if jittery:
                    log.debug(
                        "B7 %s: skew inconclusive, wall intervals %.3fs vs %.3fs",
                        ip, wall12, wall23,
                    )
                    return None
                return -1.0  # sentinel: anycast CDN detected (inconsistent clocks)
            remote_hz = (hz12 + hz23) / 2
        else:
            remote_hz = hz12

        # Anycast detection via magnitude: real servers drift ≤2000 ppm from nominal.
        # Anything wildly outside a known tick-rate bucket is unrelated TSval counters.
        for nominal_hz in (100.0, 250.0, 1000.0):
            if abs(remote_hz - nominal_hz) / nominal_hz < 0.5:
                skew_ppm = abs(remote_hz - nominal_hz) / nominal_hz * 1e6
                if skew_ppm > _ANYCAST_PPM_THRESHOLD:
                    return -1.0  # sentinel: anycast CDN detected
                return skew_ppm

        # Unknown tick rate — likely anycast or non-standard stack
        if remote_hz > 2000 or remote_hz < 10:
            return -1.0  # sentinel: anycast CDN detected

        return None

    except Exception as exc:
        log.debug("B7 probe failed %s:%d: %s", ip, port, exc)
        return None


def _categorize(ppm: float) -> str:
    if ppm < 1:
        return "near-zero"
    if ppm < 200:
        return "normal"
    if ppm < 2000:
        return "high"
    return "extreme"
