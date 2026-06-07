"""C5 — SSVC (Stakeholder-Specific Vulnerability Categorization) prioritization.

Implements a simplified SSVC decision tree to classify each finding into an
action priority: IMMEDIATE, OUT_OF_CYCLE, SCHEDULED, or DEFER.

Decision inputs (all local, no network):
  - Exploitation state (KEV = active, EPSS >= 0.5 = PoC probable, else none)
  - Technical impact (severity mapping)
  - Exposure (service reachable from network)
  - Mission impact (critical service heuristic: SSH/RDP/HTTP on servers)

Reference: https://ssvc.io/
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.models import Finding, Host, ScanResult


class SsvcPriority(StrEnum):
    IMMEDIATE = "IMMEDIATE"       # act within 24h
    OUT_OF_CYCLE = "OUT_OF_CYCLE" # act within 1 week
    SCHEDULED = "SCHEDULED"       # next patch cycle
    DEFER = "DEFER"               # track but no action now


def _exploitation_state(finding: Finding) -> str:
    """none | poc | active"""
    ev = (finding.evidence or "").upper()
    if "KEV:" in ev:
        return "active"
    if "EPSS=" in ev:
        # parse score
        import re
        m = re.search(r"EPSS=(\d+\.\d+)", ev)
        if m and float(m.group(1)) >= 0.5:
            return "poc"
    return "none"


def _technical_impact(finding: Finding) -> str:
    """total | partial"""
    from scanner.core.models import Severity
    return "total" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "partial"


def _mission_impact(host: Host) -> str:
    """critical | support | minimal"""
    critical_ports = {22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443}
    if any(p in critical_ports for p in host.open_ports):
        return "critical"
    if host.device_type in ("server", "router", "nas"):
        return "support"
    return "minimal"


def _decide(exploit: str, impact: str, mission: str) -> SsvcPriority:
    """Simplified SSVC tree (supplier decision point omitted)."""
    if exploit == "active":
        if impact == "total":
            return SsvcPriority.IMMEDIATE
        return SsvcPriority.OUT_OF_CYCLE
    if exploit == "poc":
        if impact == "total" and mission == "critical":
            return SsvcPriority.OUT_OF_CYCLE
        return SsvcPriority.SCHEDULED
    # No known exploit
    if impact == "total" and mission == "critical":
        return SsvcPriority.SCHEDULED
    return SsvcPriority.DEFER


def prioritize_result(result: ScanResult) -> dict[str, SsvcPriority]:
    """Return {finding.id: SsvcPriority} for all findings. Mutates finding.evidence."""
    priorities: dict[str, SsvcPriority] = {}
    for host in result.hosts:
        mission = _mission_impact(host)
        for finding in host.findings:
            exploit = _exploitation_state(finding)
            impact = _technical_impact(finding)
            priority = _decide(exploit, impact, mission)
            priorities[finding.id] = priority
            finding.ssvc_priority = priority.value
            finding.evidence = (finding.evidence or "") + f" [SSVC={priority.value}]"
    return priorities
