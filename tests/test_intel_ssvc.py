"""C5 SSVC — local prioritisation decision tree."""

from __future__ import annotations

from scanner.core.models import (
    Finding,
    Host,
    HostState,
    PortState,
    Proto,
    ScanConfig,
    ScanResult,
    Service,
    Severity,
)
from scanner.intel.ssvc import SsvcPriority, _decide, prioritize_result


def test_active_exploit_total_impact_is_immediate():
    assert _decide("active", "total", "critical") == SsvcPriority.IMMEDIATE


def test_active_exploit_partial_is_out_of_cycle():
    assert _decide("active", "partial", "support") == SsvcPriority.OUT_OF_CYCLE


def test_poc_total_critical_is_out_of_cycle():
    assert _decide("poc", "total", "critical") == SsvcPriority.OUT_OF_CYCLE


def test_poc_partial_is_scheduled():
    assert _decide("poc", "partial", "minimal") == SsvcPriority.SCHEDULED


def test_no_exploit_low_impact_defers():
    assert _decide("none", "partial", "minimal") == SsvcPriority.DEFER


def test_no_exploit_total_critical_is_scheduled():
    assert _decide("none", "total", "critical") == SsvcPriority.SCHEDULED


def test_prioritize_result_tags_findings():
    host = Host(
        ip="10.0.0.5",
        state=HostState.UP,
        services=[Service(port=443, proto=Proto.TCP, state=PortState.OPEN)],
        findings=[Finding(id="F1", title="x", severity=Severity.HIGH)],
    )
    r = ScanResult(config=ScanConfig(), hosts=[host])
    out = prioritize_result(r)
    assert out["F1"] in set(SsvcPriority)
    assert host.findings[0].ssvc_priority == out["F1"].value
    assert "SSVC=" in (host.findings[0].evidence or "")
