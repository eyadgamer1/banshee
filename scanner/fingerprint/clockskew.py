"""B7 — TCP timestamp clock-skew fingerprinting.

Sends SYNs to an open port and reads the TCP timestamp option from each
SYN-ACK. Comparing how fast the remote TSval counter advances against our own
wall clock estimates the remote tick rate, and its deviation from the nearest
nominal rate is reported as skew in ppm.

Skew categories:
  unresolved → deviation is inside the measurement's own resolution; no claim
  near-zero  → VM or NTP-synced host (< 1 ppm, resolvable only when the
               sampling window is long enough to see it — see `_resolution_ppm`)
  normal     → physical machine, NTP drift (1–200 ppm)
  high       → no NTP, clock drift (200–2000 ppm)
  extreme    → wrapped counter or spoofed timestamp

Both the anycast threshold and the category floor are derived from the
resolution of the measurement that produced them: a three-SYN sample can only
resolve skew down to roughly one TSval tick over the sampling interval, and a
threshold tighter than that flags ordinary single-homed servers as anycast.

Every packet goes through `ctx.budget.throttle()`, so probes are paced by the
configured timing template and counted in the audit trail like every other
active probe. Only runs when the budget allows active probes and an open TCP
port is known.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

log = logging.getLogger(__name__)

_PROBE_PORTS = [80, 443, 22, 8080, 8443, 3389, 23, 21]

# Minimum spacing between timestamp probes. Resolution is inversely
# proportional to this interval (a 100 Hz counter advances only ~30 ticks in
# 0.3 s, so ±1 tick of quantization is already ~33,000 ppm), so the window is
# kept at a full second and anything finer than the resulting resolution is
# reported as "unresolved" rather than as a skew figure.
_PROBE_INTERVAL_S = 1.0
# Real clocks do not drift beyond this; a measurement can never be more
# permissive than the physics, only less (see `_anycast_threshold_ppm`).
_MIN_ANYCAST_PPM = 2000.0
# How many times the quantization error a deviation must exceed before it is
# read as two different nodes rather than measurement noise.
_RESOLUTION_SAFETY = 3.0
# Nominal TSval tick rates and the *non-overlapping* windows that map onto
# them. Boundaries are the geometric midpoints between neighbouring rates
# (sqrt(100*250) = 158.1, sqrt(250*1000) = 500) so a measured rate lands in
# exactly one bucket; the previous ±50% windows overlapped on (125, 150] and
# always resolved to 100 Hz because it happened to be tested first.
_NOMINAL_HZ_WINDOWS: tuple[tuple[float, float, float], ...] = (
    (100.0, 50.0, 158.1),
    (250.0, 158.1, 500.0),
    (1000.0, 500.0, 2000.0),
)
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
        if not ctx.budget.can_send():
            return host
        port = self._pick_port(host)
        if port is None:
            return host
        measured = await _probe_skew(host.ip, port, ctx)
        if measured is None:
            return host
        skew_ppm, resolution_ppm = measured

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

        category = _categorize(skew_ppm, resolution_ppm)
        host.names["clock_skew_ppm"] = str(int(skew_ppm))
        host.names["clock_skew_cat"] = category
        host.names["clock_skew_resolution_ppm"] = str(int(resolution_ppm))
        if category == "near-zero":
            # Only reachable when the sample actually resolves below 1 ppm; a
            # deviation the measurement cannot distinguish from zero is
            # "unresolved", not evidence of a synchronised VM clock.
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
        log.debug(
            "B7 %s skew=%d ppm (resolution %d ppm) cat=%s",
            host.ip, int(skew_ppm), int(resolution_ppm), category,
        )
        return host

    def _pick_port(self, host: Host) -> int | None:
        for p in _PROBE_PORTS:
            if p in host.open_ports:
                return p
        return host.open_ports[0] if host.open_ports else None


def _resolution_ppm(nominal_hz: float, interval_s: float) -> float:
    """Smallest skew this sample could distinguish, in ppm.

    Each TSval read is quantized to a whole tick, so a rate estimated from two
    reads carries up to two ticks of error over the sampling interval.
    """
    if nominal_hz <= 0 or interval_s <= 0:
        return float("inf")
    return 2.0 / (nominal_hz * interval_s) * 1e6


def _anycast_threshold_ppm(nominal_hz: float, interval_s: float) -> float:
    """Deviation above which the two probes cannot be one drifting clock.

    Never tighter than the measurement can actually resolve: at 100 Hz over a
    1 s window the quantization error alone is ~20,000 ppm, so the old flat
    2,000 ppm threshold fired for essentially every host it measured.
    """
    return max(_MIN_ANYCAST_PPM, _RESOLUTION_SAFETY * _resolution_ppm(nominal_hz, interval_s))


async def _probe_skew(ip: str, port: int, ctx: ScanContext) -> tuple[float, float] | None:
    """Return (ppm skew or the -1.0 anycast sentinel, resolution ppm), or None.

    Three-probe majority vote: reduces anycast false positives caused by two
    consecutive probes accidentally landing on the same physical node. Hz
    estimates come from two consecutive intervals (1->2, 2->3). If both agree
    within 40%, we have a consistent clock -> not anycast. If they disagree
    wildly, different nodes answered -> anycast sentinel.

    The probes are driven from here rather than from a single blocking helper
    so each SYN can pass through the stealth budget first: `throttle()` both
    paces the packet and counts it.
    """
    loop = asyncio.get_running_loop()
    samples: list[tuple[float, int]] = []

    for _ in range(3):
        if not ctx.budget.can_send():
            break
        if samples:
            # Keep our own minimum sampling window on top of whatever pacing
            # the budget imposes — at -T3 and above its delay is 0 ms, which
            # would collapse the interval and with it the resolution.
            gap = _PROBE_INTERVAL_S - (time.monotonic() - samples[-1][0])
            if gap > 0:
                await asyncio.sleep(gap)
        await ctx.budget.throttle()
        ts = int(time.time() * 100) & 0xFFFFFFFF
        try:
            t_recv, tsval = await loop.run_in_executor(None, _syn_probe, ip, port, ts)
        except Exception as exc:
            log.debug("B7 probe failed %s:%d: %s", ip, port, exc)
            return None
        if tsval is None:
            break
        samples.append((t_recv, tsval))

    if len(samples) < 2:
        return None

    (t1, r1), (t2, r2) = samples[0], samples[1]
    wall12 = t2 - t1
    if wall12 <= 0.01:
        return None
    remote12 = (r2 - r1) & 0xFFFFFFFF
    if remote12 == 0:
        return None
    hz12 = remote12 / wall12

    interval = wall12
    remote_hz = hz12
    if len(samples) == 3:
        t3, r3 = samples[2]
        wall23 = t3 - t2
        if wall23 > 0.01:
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
                return -1.0, 0.0  # sentinel: anycast CDN detected (inconsistent clocks)
            remote_hz = (hz12 + hz23) / 2
            interval = min(wall12, wall23)

    # Map the measured rate onto exactly one nominal tick rate, then judge the
    # deviation against what this sample could actually resolve.
    for nominal_hz, lo, hi in _NOMINAL_HZ_WINDOWS:
        if lo <= remote_hz < hi:
            skew_ppm = abs(remote_hz - nominal_hz) / nominal_hz * 1e6
            resolution = _resolution_ppm(nominal_hz, interval)
            if skew_ppm > _anycast_threshold_ppm(nominal_hz, interval):
                return -1.0, 0.0  # sentinel: anycast CDN detected
            return skew_ppm, resolution

    # Outside every known tick rate — unrelated TSval counters, not a clock.
    if remote_hz > 2000 or remote_hz < 10:
        return -1.0, 0.0  # sentinel: anycast CDN detected

    return None


def _syn_probe(ip: str, port: int, ts: int) -> tuple[float, int | None]:
    """Send one timestamped SYN; return (monotonic receive time, remote TSval).

    TSval is None when nothing usable came back. Blocking (scapy), so this is
    called from an executor — one packet per call, so the caller can budget it.
    """
    t_recv = time.monotonic()
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.sendrecv import sr1

        pkt = IP(dst=ip) / TCP(
            dport=port,
            flags="S",
            options=[("Timestamp", (ts, 0))],
        )
        ans = sr1(pkt, timeout=2, verbose=0)
        t_recv = time.monotonic()
        if ans is None or not ans.haslayer(TCP):
            return t_recv, None
        tcp_layer = ans[TCP]
        # Require SYN+ACK (0x12) explicitly — not just "not a RST". A RST
        # or any other stray packet scapy happens to pair with this probe
        # must not be read as a real handshake response with a trustworthy
        # TSval; excluding only RST let anything else through.
        if int(tcp_layer.flags) & 0x12 != 0x12:
            return t_recv, None
        for opt_name, opt_val in (tcp_layer.options or []):
            if opt_name == "Timestamp":
                return t_recv, int(opt_val[0])
    except Exception as exc:
        log.debug("B7 probe failed %s:%d: %s", ip, port, exc)
    return t_recv, None


def _categorize(ppm: float, resolution_ppm: float) -> str:
    if ppm <= resolution_ppm:
        # Below the noise floor of this sample — indistinguishable from a
        # perfectly nominal clock, which is not the same claim as "near-zero".
        return "unresolved"
    if ppm < 1:
        return "near-zero"
    if ppm < 200:
        return "normal"
    if ppm < 2000:
        return "high"
    return "extreme"
