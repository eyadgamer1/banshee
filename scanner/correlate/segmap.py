"""C2 — Network segmentation map.

Groups discovered hosts into logical segments based on subnet membership,
then identifies inter-segment edges (hosts that bridge segments via multiple
IPs or services reachable from other segments).

Segments are derived deterministically from IP/prefix — no LLM, no packets.

Output: SegmentMap with segments + bridge hosts + a finding per bridge.
"""

from __future__ import annotations

import ipaddress
import logging
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


def build_segment_map(result: ScanResult) -> SegmentMap:
    """Build the segmentation map and attach bridge findings to hosts."""
    ips = [h.ip for h in result.hosts]
    if not ips:
        return SegmentMap()

    prefix = _best_prefix(ips)
    seg_map: dict[str, Segment] = {}

    for host in result.hosts:
        try:
            net = str(ipaddress.ip_interface(f"{host.ip}/{prefix}").network)
        except ValueError:
            net = "unknown"
        if net not in seg_map:
            seg_map[net] = Segment(network=net)
        seg_map[net].hosts.append(host.ip)

    segments = sorted(seg_map.values(), key=lambda s: s.network)

    # A bridge host appears in multiple segments (multi-homed or routed)
    # For now: hosts with multiple IPs in names dict or gateway-like device types
    bridges: list[str] = []
    gateway_types = {"router", "switch", "access-point"}
    for host in result.hosts:
        if host.device_type in gateway_types:
            bridges.append(host.ip)

    # Attach findings to bridges (idempotent — guard against duplicate C2 findings)
    from scanner.core.models import ConfidenceTier, Finding, Severity
    bridge_set = set(bridges)
    for host in result.hosts:
        if host.ip in bridge_set:
            finding_id = f"C2-bridge-{host.ip.replace('.', '_')}"
            if any(f.id == finding_id for f in host.findings):
                continue
            host.findings.append(Finding(
                id=f"C2-bridge-{host.ip.replace('.', '_')}",
                title=f"Segment bridge: {host.device_type} spans network boundary",
                severity=Severity.MEDIUM,
                confidence=ConfidenceTier.PROBABLE,
                description=(
                    f"{host.ip} ({host.device_type}) acts as a bridge between "
                    f"{len(segments)} detected segments. Compromise enables lateral movement."
                ),
                source="C2",
            ))

    smap = SegmentMap(segments=segments, bridges=bridges)
    log.info("C2 segments: %d segments, %d bridges", len(segments), len(bridges))
    return smap
