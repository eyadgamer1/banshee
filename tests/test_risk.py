"""C7 risk — confidence-tier policy."""

from __future__ import annotations

from scanner.core.models import (
    ConfidenceTier,
    Finding,
    Host,
    HostState,
    PortState,
    Proto,
    ScanConfig,
    ScanResult,
    Service,
)
from scanner.risk import host_tier, tier_result


def test_down_host_is_potential():
    h = Host(ip="10.0.0.1", state=HostState.DOWN)
    assert host_tier(h) == ConfidenceTier.POTENTIAL


def test_confirmed_service_makes_confirmed():
    h = Host(
        ip="10.0.0.1",
        state=HostState.UP,
        services=[Service(port=80, confidence=ConfidenceTier.CONFIRMED)],
    )
    assert host_tier(h) == ConfidenceTier.CONFIRMED


def test_two_identity_signals_confirm():
    h = Host(ip="10.0.0.1", state=HostState.UP, mac="aa:bb:cc:dd:ee:ff", vendor="VMware")
    assert host_tier(h) == ConfidenceTier.CONFIRMED


def test_single_signal_probable():
    h = Host(ip="10.0.0.1", state=HostState.UP, mac="aa:bb:cc:dd:ee:ff")
    assert host_tier(h) == ConfidenceTier.PROBABLE


def test_no_signals_alive_is_potential():
    h = Host(ip="10.0.0.1", state=HostState.UP)
    assert host_tier(h) == ConfidenceTier.POTENTIAL


def test_tier_result_caps_llm_findings_to_potential():
    f = Finding(
        id="L1", title="llm guess", confidence=ConfidenceTier.CONFIRMED, is_llm_inferred=True
    )
    h = Host(ip="10.0.0.1", state=HostState.UP, findings=[f])
    r = ScanResult(config=ScanConfig(), hosts=[h])
    tier_result(r)
    assert h.findings[0].confidence == ConfidenceTier.POTENTIAL


def test_tier_result_recomputes_host_confidence():
    h = Host(
        ip="10.0.0.1",
        state=HostState.UP,
        confidence=ConfidenceTier.POTENTIAL,
        services=[Service(port=22, state=PortState.OPEN, proto=Proto.TCP,
                          confidence=ConfidenceTier.CONFIRMED)],
    )
    r = ScanResult(config=ScanConfig(), hosts=[h])
    tier_result(r)
    assert h.confidence == ConfidenceTier.CONFIRMED


def test_non_llm_finding_confidence_unchanged():
    f = Finding(id="A", title="real", confidence=ConfidenceTier.CONFIRMED, is_llm_inferred=False)
    h = Host(ip="10.0.0.1", state=HostState.UP, findings=[f])
    r = ScanResult(config=ScanConfig(), hosts=[h])
    tier_result(r)
    assert h.findings[0].confidence == ConfidenceTier.CONFIRMED
