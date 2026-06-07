"""C1 — Attack-path graph.

Builds a directed graph of potential lateral-movement paths between in-scope
hosts based on observed services. No exploitation — purely structural reasoning
from what was enumerated.

Graph nodes: IP addresses (hosts)
Graph edges: (src_ip, dst_ip, reason) — "src can reach dst via <service>"

Edge rules (deterministic, no LLM):
  SMB (445/139)    → lateral movement possible via file shares
  RDP (3389)       → remote access vector
  SSH (22)         → remote shell / tunnelling
  WinRM (5985/6)   → Windows remote management
  HTTP(S) (80/443) → web app attack surface
  DB ports         → direct DB access (3306/5432/1433/27017)
  Telnet (23)      → clear-text remote access (high risk)

Output: list of AttackEdge namedtuples + a summary finding per risky host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scanner.core.models import ConfidenceTier, Finding, Severity

if TYPE_CHECKING:
    from scanner.core.models import ScanResult

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

    def reachable_from(self, ip: str) -> list[AttackEdge]:
        return [e for e in self.edges if e.src == ip]

    def pivot_targets(self) -> list[str]:
        """IPs that are both source and destination (multi-hop pivots)."""
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


def build_attack_graph(result: ScanResult) -> AttackGraph:
    """Build the attack graph and attach pivot findings to hosts."""
    up_hosts = [h for h in result.hosts if h.open_ports]
    graph = AttackGraph()

    for dst_host in up_hosts:
        for port in dst_host.open_ports:
            if port not in _PIVOT_PORTS:
                continue
            label, sev = _PIVOT_PORTS[port]
            # Every other up host could potentially reach this service
            for src_host in up_hosts:
                if src_host.ip == dst_host.ip:
                    continue
                graph.edges.append(AttackEdge(
                    src=src_host.ip,
                    dst=dst_host.ip,
                    service=label,
                    port=port,
                    severity=sev,
                ))

    # Attach findings to pivot hosts. Idempotent: build_attack_graph is also called
    # by the agentic pivot tool, so guard against appending a duplicate C1 finding.
    pivots = set(graph.pivot_targets())
    for host in result.hosts:
        if host.ip in pivots:
            finding_id = f"C1-pivot-{host.ip.replace('.', '_')}"
            if any(f.id == finding_id for f in host.findings):
                continue
            inbound = [e for e in graph.edges if e.dst == host.ip]
            services = ", ".join(sorted({e.service for e in inbound}))
            _sev_order = list(Severity)
            max_sev = max(
                (e.severity for e in inbound),
                key=lambda s: _sev_order.index(s),
                default=Severity.LOW,
            )
            host.findings.append(Finding(
                id=f"C1-pivot-{host.ip.replace('.', '_')}",
                title=f"Potential pivot target: {services}",
                severity=max_sev,
                confidence=ConfidenceTier.PROBABLE,
                description=(
                    f"{host.ip} exposes {services} and is reachable from "
                    f"{len(inbound)} other hosts — a likely lateral-movement target."
                ),
                source="C1",
            ))

    return graph
