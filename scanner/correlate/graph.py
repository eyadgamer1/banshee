"""C1 — Attack-path graph.

Builds a directed graph of candidate lateral-movement paths between in-scope
hosts based on observed services. No exploitation — purely structural reasoning
from what was enumerated.

Graph nodes: IP addresses (hosts)
Graph edges: (src_ip, dst_ip, reason) — "src *could* reach dst via <service>"

What an edge is and is not
--------------------------
BANSHEE probes from the scanner, never between two scanned hosts, so it never
observes host-to-host reachability. An edge here therefore means "dst exposes a
pivot-worthy service and src sits in the same segment", not "src can reach dst":
segmentation, host firewalls and VLAN ACLs are all invisible to this scan. The
findings this module attaches say exactly that, at POTENTIAL.

Two bounds keep the construction from blowing up (it used to be an unconditional
all-pairs cross-product — 1000 up hosts x 5 pivot ports is ~5M edge objects, and
the finding pass rescanned that list per host, ~5e9 comparisons, so a /22 looked
like a hang after probing finished):

  * edges are only drawn inside a segment (correlate/segmap.group_by_segment),
  * the total edge count is capped at `_MAX_EDGES`.

Findings and pivot detection are computed from small per-host indexes rather
than by rescanning the edge list, so they stay correct and O(H*P) even when the
edge list is capped.

Edge rules (deterministic, no LLM):
  SMB (445/139)    → lateral movement possible via file shares
  RDP (3389)       → remote access vector
  SSH (22)         → remote shell / tunnelling
  WinRM (5985/6)   → Windows remote management
  HTTP(S) (80/443) → web app attack surface
  DB ports         → direct DB access (3306/5432/1433/27017)
  Telnet (23)      → clear-text remote access (high risk)

Output: list of AttackEdge dataclasses + a summary finding per exposed host.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scanner.core.models import ConfidenceTier, Finding, Severity
from scanner.correlate.segmap import group_by_segment

if TYPE_CHECKING:
    from scanner.core.models import ScanResult

log = logging.getLogger(__name__)

# Port → (service label, severity bump if reachable from another host)
_PIVOT_PORTS: dict[int, tuple[str, Severity]] = {
    22:    ("SSH",    Severity.MEDIUM),
    23:    ("Telnet", Severity.HIGH),
    80:    ("HTTP",   Severity.LOW),
    443:   ("HTTPS",  Severity.LOW),
    445:   ("SMB",    Severity.HIGH),
    139:   ("NetBIOS",Severity.MEDIUM),
    3389:  ("RDP",    Severity.HIGH),
    5985:  ("WinRM",  Severity.HIGH),
    5986:  ("WinRM",  Severity.HIGH),
    3306:  ("MySQL",  Severity.HIGH),
    5432:  ("PgSQL",  Severity.HIGH),
    1433:  ("MSSQL",  Severity.HIGH),
    27017: ("MongoDB",Severity.HIGH),
}

# Ceiling on materialised edges. The edge list is a presentation/serialisation
# artifact (the CLI prints a count, the ReAct tool shows the first 30); the
# findings do not read it, so capping it costs nothing analytically and keeps a
# large flat network from allocating millions of objects.
_MAX_EDGES = 20_000


@dataclass
class AttackEdge:
    src: str
    dst: str
    service: str
    port: int
    severity: Severity


@dataclass
class AttackGraph:
    edges: list[AttackEdge] = field(default_factory=list)
    # Set when `_MAX_EDGES` stopped edge materialisation; `omitted_edges` counts
    # the candidates that were not built. Findings are unaffected.
    truncated: bool = False
    omitted_edges: int = 0
    # Computed structurally rather than by intersecting the (possibly capped)
    # edge list — see `pivot_targets`.
    pivots: list[str] = field(default_factory=list)

    def reachable_from(self, ip: str) -> list[AttackEdge]:
        return [e for e in self.edges if e.src == ip]

    def pivot_targets(self) -> list[str]:
        """IPs that are both source and destination (multi-hop pivots)."""
        if self.pivots:
            return list(self.pivots)
        srcs = {e.src for e in self.edges}
        dsts = {e.dst for e in self.edges}
        return sorted(srcs & dsts)

    def to_dict(self) -> list[dict[str, str]]:
        return [
            {
                "src": e.src,
                "dst": e.dst,
                "service": e.service,
                "port": str(e.port),
                "severity": e.severity.value,
            }
            for e in self.edges
        ]


def _exposures(
    hosts: list[str], open_ports: dict[str, list[int]]
) -> dict[str, list[tuple[int, str, Severity]]]:
    """{ip: [(port, label, severity), ...]} for pivot-worthy open ports only."""
    index: dict[str, list[tuple[int, str, Severity]]] = {}
    for ip in hosts:
        listed = [
            (port, *_PIVOT_PORTS[port])
            for port in sorted(open_ports.get(ip, []))
            if port in _PIVOT_PORTS
        ]
        if listed:
            index[ip] = listed
    return index


def build_attack_graph(result: ScanResult) -> AttackGraph:
    """Build the attack graph and attach exposure findings to hosts."""
    up_hosts = [h for h in result.hosts if h.open_ports]
    graph = AttackGraph()
    if len(up_hosts) < 2:
        return graph

    ips = [h.ip for h in up_hosts]
    open_ports = {h.ip: list(h.open_ports) for h in up_hosts}

    # Same-segment membership, from the C2 primitive, so the two correlators
    # agree on what "same segment" means.
    segment_members = group_by_segment(ips)
    segment_of = {ip: net for net, members in segment_members.items() for ip in members}
    peer_count = {ip: len(segment_members[segment_of[ip]]) - 1 for ip in ips}

    exposures = _exposures(ips, open_ports)

    # `budget` bounds the work, not just the output: once it is spent the loop
    # stops iterating and the remaining candidates are counted arithmetically, so
    # this stays O(min(_MAX_EDGES, H*P) + H) instead of walking H^2*P pairs.
    budget = _MAX_EDGES
    for dst, listed in exposures.items():
        members = segment_members[segment_of[dst]]
        want = (len(members) - 1) * len(listed)
        if budget <= 0:
            graph.truncated = True
            graph.omitted_edges += want
            continue
        if want > budget:
            graph.truncated = True
            graph.omitted_edges += want - budget
        for port, label, sev in listed:
            if budget <= 0:
                break
            for src in members:
                if src == dst:
                    continue
                if budget <= 0:
                    break
                graph.edges.append(
                    AttackEdge(src=src, dst=dst, service=label, port=port, severity=sev)
                )
                budget -= 1

    if graph.truncated:
        log.warning(
            "C1 attack graph capped at %d edges (%d candidate edges not materialised); "
            "pivot findings are unaffected",
            _MAX_EDGES,
            graph.omitted_edges,
        )

    # A pivot is an exposed host that shares its segment with at least one other
    # host — i.e. it is both a destination and a candidate source. Derived from
    # the indexes above, never by rescanning `graph.edges`.
    graph.pivots = sorted(ip for ip in exposures if peer_count[ip] > 0)
    pivots = set(graph.pivots)

    _sev_order = list(Severity)
    for host in result.hosts:
        if host.ip not in pivots:
            continue
        # Idempotent: build_attack_graph is also called by the agentic pivot
        # tool, so guard against appending a duplicate C1 finding.
        finding_id = f"C1-pivot-{host.ip.replace('.', '_')}"
        if any(f.id == finding_id for f in host.findings):
            continue
        listed = exposures[host.ip]
        services = ", ".join(sorted({label for _, label, _ in listed}))
        max_sev = max(
            (sev for _, _, sev in listed),
            key=lambda s: _sev_order.index(s),
            default=Severity.LOW,
        )
        peers = peer_count[host.ip]
        host.findings.append(Finding(
            id=finding_id,
            title=f"Pivot-worthy services exposed: {services}",
            severity=max_sev,
            # POTENTIAL, not PROBABLE: the exposure is observed, the reachability
            # is not. This scan only ever probed from the scanner, so it cannot
            # claim any of those peers can actually reach this host.
            confidence=ConfidenceTier.POTENTIAL,
            description=(
                f"{host.ip} exposes {services}. {peers} other discovered host(s) share "
                f"its {segment_of[host.ip]} segment and are therefore candidate sources "
                "for lateral movement. Host-to-host reachability was never tested — "
                "firewalls, VLAN ACLs and host policy are invisible to this scan — so "
                "this is a topology-derived lead, not an observed path."
            ),
            evidence=(
                f"segment={segment_of[host.ip]} segment_peers={peers} "
                f"ports={','.join(str(port) for port, _, _ in listed)}"
            ),
            source="C1",
        ))

    return graph
