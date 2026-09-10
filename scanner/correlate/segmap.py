"""C2 — Network segmentation map.

Groups discovered hosts into logical segments based on subnet membership, then
identifies bridge hosts: hosts *observed* on more than one segment, i.e. the same
MAC answering at two IPs in different networks.

Segments are derived deterministically from IP/prefix — no LLM, no packets.
`group_by_segment` is the shared primitive: correlate/graph.py uses it so the
attack graph and this map agree on what "same segment" means.

Output: SegmentMap with segments + bridge hosts + a finding per bridge.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.models import ScanResult

log = logging.getLogger(__name__)

# Common subnet prefix lengths to try when grouping
_CANDIDATE_PREFIXES = [24, 23, 22, 16]


@dataclass
class Segment:
    network: str          # e.g. "192.168.1.0/24"
    hosts: list[str] = field(default_factory=list)   # IP strings


@dataclass
class SegmentMap:
    segments: list[Segment] = field(default_factory=list)
    bridges: list[str] = field(default_factory=list)  # IPs in >1 segment

    def to_dict(self) -> dict[str, object]:
        return {
            "segments": [{"network": s.network, "hosts": s.hosts} for s in self.segments],
            "bridges": self.bridges,
        }


def _best_prefix(ips: list[str]) -> int:
    """Pick the tightest prefix that produces ≥2 segments (or fallback /24)."""
    for prefix in _CANDIDATE_PREFIXES:
        nets: set[str] = set()
        for ip in ips:
            try:
                nets.add(str(ipaddress.ip_interface(f"{ip}/{prefix}").network))
            except ValueError:
                pass
        if len(nets) >= 2:
            return prefix
    return 24


def _segment_key(ip: str, prefix: int) -> str:
    try:
        return str(ipaddress.ip_interface(f"{ip}/{prefix}").network)
    except ValueError:
        return "unknown"


def group_by_segment(ips: Sequence[str]) -> dict[str, list[str]]:
    """{segment network: [ip, ...]} using the shared prefix heuristic.

    Pure — attaches nothing and mutates nothing, so another correlator can ask
    "are these two hosts on the same segment?" without triggering C2 findings.
    """
    prefix = _best_prefix(list(ips))
    groups: dict[str, list[str]] = {}
    for ip in ips:
        groups.setdefault(_segment_key(ip, prefix), []).append(ip)
    return groups


def segment_of(ips: Sequence[str]) -> dict[str, str]:
    """{ip: segment network} for every IP in `ips`."""
    return {ip: net for net, members in group_by_segment(ips).items() for ip in members}


def build_segment_map(result: ScanResult) -> SegmentMap:
    """Build the segmentation map and attach bridge findings to hosts."""
    ips = [h.ip for h in result.hosts]
    if not ips:
        return SegmentMap()

    groups = group_by_segment(ips)
    segments = sorted(
        (Segment(network=net, hosts=list(members)) for net, members in groups.items()),
        key=lambda s: s.network,
    )
    seg_of = {ip: net for net, members in groups.items() for ip in members}

    # A bridge is a host OBSERVED on more than one segment: one MAC answering at
    # two IPs that land in different networks. That is the "host with multiple
    # IPs" criterion this module always documented but never implemented. The old
    # code instead flagged any host the classifier labelled router / access-point
    # / "switch" — "switch" is not a label the classifier can emit (dead branch),
    # and a single-homed router was asserted as a bridge at PROBABLE on
    # classification alone, an observation the scan never made.
    by_mac: dict[str, set[str]] = {}
    for host in result.hosts:
        if host.mac:
            by_mac.setdefault(host.mac.lower(), set()).add(host.ip)

    peers: dict[str, list[str]] = {}
    for addrs in by_mac.values():
        if len(addrs) < 2 or len({seg_of.get(ip, "unknown") for ip in addrs}) < 2:
            continue
        for ip in addrs:
            peers[ip] = sorted(addrs - {ip})
    bridges = sorted(peers)

    from scanner.core.models import ConfidenceTier, Finding, Severity

    # Findings are idempotent — guard against a duplicate C2 finding on re-run.
    gateway_types = {"router", "access-point"}
    for host in result.hosts:
        if host.ip in peers:
            finding_id = f"C2-bridge-{host.ip.replace('.', '_')}"
            if any(f.id == finding_id for f in host.findings):
                continue
            other = ", ".join(peers[host.ip])
            host.findings.append(Finding(
                id=finding_id,
                title="Segment bridge: same MAC observed on two segments",
                severity=Severity.MEDIUM,
                confidence=ConfidenceTier.PROBABLE,
                description=(
                    f"{host.ip} shares MAC {host.mac} with {other}, which falls in a "
                    f"different segment of the {len(segments)} detected. A multi-homed "
                    "host spans the boundary, so compromising it can enable lateral "
                    "movement between those segments."
                ),
                evidence=f"mac={host.mac} also_seen_at={other}",
                source="C2",
            ))
        elif host.device_type in gateway_types:
            # Classification only. The scan saw one interface, so it cannot claim
            # this device bridges anything — it is a lead to check, at POTENTIAL.
            finding_id = f"C2-gateway-{host.ip.replace('.', '_')}"
            if any(f.id == finding_id for f in host.findings):
                continue
            host.findings.append(Finding(
                id=finding_id,
                title=f"Gateway-class device ({host.device_type})",
                severity=Severity.LOW,
                confidence=ConfidenceTier.POTENTIAL,
                description=(
                    f"{host.ip} is classified as a {host.device_type}, a device class that "
                    "usually connects segments. Only one interface was observed, so this "
                    "scan did not confirm it bridges any of the "
                    f"{len(segments)} detected segments — verify on the device itself."
                ),
                source="C2",
            ))

    smap = SegmentMap(segments=segments, bridges=bridges)
    log.info("C2 segments: %d segments, %d bridges", len(segments), len(bridges))
    return smap
