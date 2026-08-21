"""D1/D4 LLM — offline fallbacks and ReAct action parsing (no Ollama needed)."""

from __future__ import annotations

import pytest

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
from scanner.llm.react import _static_summary, _tool_list_findings, _tool_list_hosts, run_react_loop
from scanner.llm.report import _build_scan_data, _fallback_report, generate_report


def sample() -> ScanResult:
    host = Host(
        ip="10.0.0.5",
        state=HostState.UP,
        hostname="vm1",
        services=[Service(port=22, proto=Proto.TCP, state=PortState.OPEN)],
        findings=[
            Finding(id="F1", title="Critical thing", severity=Severity.CRITICAL),
            Finding(id="F2", title="Minor thing", severity=Severity.LOW),
        ],
    )
    return ScanResult(config=ScanConfig(), hosts=[host])


def test_static_summary_counts_high_plus():
    text = _static_summary(sample())
    assert "Hosts: 1" in text
    assert "High+: 1" in text


def test_tool_list_hosts_renders():
    out = _tool_list_hosts(sample())
    assert "10.0.0.5" in out
    assert "hostname=vm1" in out


def test_tool_list_findings_renders():
    out = _tool_list_findings(sample())
    assert "CRITICAL" in out
    assert "Critical thing" in out


def test_build_scan_data_includes_severity_counts():
    data = _build_scan_data(sample())
    assert "Hosts discovered: 1" in data
    assert "critical=1" in data


def test_fallback_report_is_markdown_high_risk():
    md = _fallback_report(sample())
    assert "## Executive Summary" in md
    assert "Overall risk level: **High**" in md


def test_fallback_report_low_risk_when_no_findings():
    r = ScanResult(config=ScanConfig(), hosts=[Host(ip="10.0.0.1", state=HostState.UP)])
    assert "**Low**" in _fallback_report(r)


@pytest.mark.asyncio
async def test_run_react_loop_falls_back_when_ollama_down():
    # No Ollama running in CI — must return the static summary, never raise.
    out = await run_react_loop(sample())
    assert isinstance(out, str)
    assert out  # non-empty


@pytest.mark.asyncio
async def test_generate_report_falls_back_when_ollama_down():
    out = await generate_report(sample())
    assert "## Executive Summary" in out
