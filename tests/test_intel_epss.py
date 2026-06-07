"""C4 EPSS/KEV — CVE extraction and offline-safe enrichment."""

from __future__ import annotations

import pytest

from scanner.core.models import (
    Finding,
    Host,
    HostState,
    ScanConfig,
    ScanResult,
    Severity,
)
from scanner.intel.epss import _cves_in, _extract_cves, enrich_result


def test_cves_in_extracts_and_dedups():
    cves = _cves_in("CVE-2021-44228 and cve-2021-44228", "see CVE-2014-0160")
    assert cves == ["CVE-2021-44228", "CVE-2014-0160"]


def test_cves_in_empty():
    assert _cves_in("no cves here", "") == []


def test_extract_cves_across_findings():
    findings = [
        Finding(id="A", title="Log4Shell CVE-2021-44228"),
        Finding(id="B", title="x", description="Heartbleed CVE-2014-0160"),
        Finding(id="C", title="no cve"),
    ]
    cves = _extract_cves(findings)
    assert set(cves) == {"CVE-2021-44228", "CVE-2014-0160"}


@pytest.mark.asyncio
async def test_enrich_result_no_cves_is_noop():
    host = Host(ip="10.0.0.5", state=HostState.UP, findings=[Finding(id="F", title="no cve")])
    r = ScanResult(config=ScanConfig(), hosts=[host])
    await enrich_result(r)  # must not raise, must not call network
    assert host.findings[0].severity == Severity.INFO
    assert host.findings[0].evidence is None
