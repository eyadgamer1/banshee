"""B8 Negative-space fingerprint — anomaly findings + BUG4 suppression guard."""

from __future__ import annotations

import pytest

from scanner.core.models import ConfidenceTier, Host, HostState, PortState, Proto, Service
from scanner.fingerprint.negspace import NegativeSpaceFingerprinter

from .conftest import make_ctx, make_host


def fids(host: Host) -> set[str]:
    return {f.source + ":" + f.title for f in host.findings}


def has(host: Host, needle: str) -> bool:
    return any(needle in f.title for f in host.findings)


@pytest.mark.asyncio
async def test_ssh_no_banner_flagged():
    host = make_host(ip="10.0.0.5", ports=[22])
    await NegativeSpaceFingerprinter().fingerprint(host, make_ctx())
    assert has(host, "SSH open with no banner")


@pytest.mark.asyncio
async def test_ssh_with_banner_not_flagged():
    host = Host(
        ip="10.0.0.5",
        state=HostState.UP,
        services=[Service(port=22, proto=Proto.TCP, state=PortState.OPEN, banner="OpenSSH_9.0")],
    )
    await NegativeSpaceFingerprinter().fingerprint(host, make_ctx())
    assert not has(host, "SSH open with no banner")


@pytest.mark.asyncio
async def test_windows_ttl_without_windows_ports_flagged():
    host = make_host(ip="10.0.0.5", ports=[80, 443], os_guess="Windows")
    await NegativeSpaceFingerprinter().fingerprint(host, make_ctx())
    assert has(host, "Windows TTL but no Windows ports")


@pytest.mark.asyncio
async def test_windows_ttl_with_windows_ports_not_flagged():
    host = make_host(ip="10.0.0.5", ports=[445, 3389], os_guess="Windows")
    await NegativeSpaceFingerprinter().fingerprint(host, make_ctx())
    assert not has(host, "Windows TTL but no Windows ports")


@pytest.mark.asyncio
async def test_firewall_gaps_flagged_with_many_filtered():
    services = [
        Service(port=p, proto=Proto.TCP, state=PortState.FILTERED) for p in (81, 82, 83, 84, 85)
    ]
    host = Host(ip="10.0.0.5", state=HostState.UP, services=services)
    await NegativeSpaceFingerprinter().fingerprint(host, make_ctx())
    assert has(host, "Stateful firewall likely")


@pytest.mark.asyncio
async def test_web_only_host_suppresses_expected_ports_finding():
    # BUG4 regression: a Windows-archetype host exposing only web ports must not get
    # the "expected ports absent" finding (CDN edge / cloud LB false positive).
    host = make_host(ip="10.0.0.5", ports=[80, 443], os_guess="Windows")
    await NegativeSpaceFingerprinter().fingerprint(host, make_ctx())
    assert not has(host, "Expected ports absent")


@pytest.mark.asyncio
async def test_linux_server_missing_ssh_flagged_when_non_web_ports_present():
    # A linux-server with only a non-web port (e.g. 3306) and no SSH should still flag.
    host = make_host(ip="10.0.0.5", ports=[3306], os_guess="Linux")
    await NegativeSpaceFingerprinter().fingerprint(host, make_ctx())
    assert has(host, "Expected ports absent")


@pytest.mark.asyncio
async def test_all_findings_are_low_or_info_severity():
    host = make_host(ip="10.0.0.5", ports=[22, 80, 443], os_guess="Windows")
    await NegativeSpaceFingerprinter().fingerprint(host, make_ctx())
    for f in host.findings:
        assert f.severity.value in ("info", "low")
        assert f.confidence in (ConfidenceTier.POTENTIAL, ConfidenceTier.PROBABLE)
