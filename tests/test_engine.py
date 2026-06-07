"""A1 ScanEngine — target expansion, scope filtering, merge dedup, pipeline."""

from __future__ import annotations

import pytest

from scanner.core.engine import ScanEngine, expand_target
from scanner.core.models import (
    Finding,
    Host,
    HostState,
    PortState,
    Proto,
    ScanConfig,
    ScanMode,
    Service,
)
from scanner.core.scope import ScopeViolationError

from .conftest import make_budget, make_scope

# ----- expand_target ---------------------------------------------------------


def test_expand_single_ip():
    assert expand_target("10.0.0.5") == ["10.0.0.5"]


def test_expand_cidr():
    out = expand_target("10.0.0.0/30")
    assert out == ["10.0.0.1", "10.0.0.2"]


def test_expand_cidr_31_point_to_point():
    # RFC 3021: a /31 has two usable point-to-point addresses.
    assert expand_target("10.0.0.0/31") == ["10.0.0.0", "10.0.0.1"]


def test_expand_cidr_32_single_address():
    assert expand_target("10.0.0.5/32") == ["10.0.0.5"]


def test_expand_last_octet_range():
    assert expand_target("10.0.0.10-12") == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]


def test_expand_full_range():
    assert expand_target("10.0.0.254-10.0.1.1") == [
        "10.0.0.254",
        "10.0.0.255",
        "10.0.1.0",
        "10.0.1.1",
    ]


def test_expand_inverted_range_returned_as_is():
    assert expand_target("10.0.0.20-10") == ["10.0.0.20-10"]


def test_expand_hostname_passthrough():
    assert expand_target("host.lan") == ["host.lan"]


def test_expand_empty_token():
    assert expand_target("   ") == []


# ----- fakes -----------------------------------------------------------------


class FakeDiscoverer:
    name = "fake-disc"
    feature_id = "FAKE"

    def __init__(self, hosts: list[Host]) -> None:
        self._hosts = hosts

    async def discover(self, targets, ctx):  # noqa: ANN001
        return [h for h in self._hosts if h.ip in set(targets)]


class TagFingerprinter:
    name = "tag-fp"
    feature_id = "TAG"

    async def fingerprint(self, host: Host, ctx):  # noqa: ANN001
        host.os_guess = host.os_guess or "TaggedOS"
        return host


def engine(discoverers, fingerprinters=(), scope=None, budget=None):
    return ScanEngine(
        scope=scope or make_scope(),
        budget=budget or make_budget(mode=ScanMode.NORMAL, timing=4),
        discoverers=list(discoverers),
        fingerprinters=list(fingerprinters),
    )


# ----- run() -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_discovers_and_fingerprints():
    host = Host(ip="10.0.0.5", state=HostState.UP)
    eng = engine([FakeDiscoverer([host])], [TagFingerprinter()])
    result = await eng.run(ScanConfig(targets=["10.0.0.5"], mode=ScanMode.NORMAL, fingerprint=True))
    assert result.stats.hosts_up == 1
    assert result.hosts[0].os_guess == "TaggedOS"


@pytest.mark.asyncio
async def test_run_filters_out_of_scope_silently_when_some_in_scope():
    h1 = Host(ip="10.0.0.5", state=HostState.UP)
    eng = engine([FakeDiscoverer([h1])])
    # 8.8.8.8 is out of scope but 10.0.0.5 is in scope -> proceed on the subset
    result = await eng.run(ScanConfig(targets=["10.0.0.5", "8.8.8.8"], mode=ScanMode.NORMAL))
    assert result.stats.targets_in_scope == 1
    assert result.stats.targets_out_of_scope == 1
    assert [h.ip for h in result.hosts] == ["10.0.0.5"]


@pytest.mark.asyncio
async def test_run_raises_when_all_targets_out_of_scope():
    eng = engine([FakeDiscoverer([])])
    with pytest.raises(ScopeViolationError):
        await eng.run(ScanConfig(targets=["8.8.8.8"], mode=ScanMode.NORMAL))


@pytest.mark.asyncio
async def test_dry_run_plans_without_discovering():
    called = {"discover": False}

    class Spy(FakeDiscoverer):
        async def discover(self, targets, ctx):  # noqa: ANN001
            called["discover"] = True
            return []

    eng = engine([Spy([])])
    result = await eng.run(ScanConfig(targets=["10.0.0.1", "10.0.0.2"], dry_run=True))
    assert called["discover"] is False
    assert len(result.hosts) == 2
    assert all(h.state == HostState.UNKNOWN for h in result.hosts)


@pytest.mark.asyncio
async def test_dry_run_out_of_scope_still_raises():
    eng = engine([FakeDiscoverer([])])
    with pytest.raises(ScopeViolationError):
        await eng.run(ScanConfig(targets=["8.8.8.8"], dry_run=True))


@pytest.mark.asyncio
async def test_duplicate_ip_merge_dedupes_services():
    # Two discoverers report the same IP and the same port 80 -> one service only.
    h_a = Host(
        ip="10.0.0.5",
        state=HostState.UP,
        services=[Service(port=80, proto=Proto.TCP, state=PortState.OPEN)],
    )
    h_b = Host(
        ip="10.0.0.5",
        state=HostState.UP,
        services=[
            Service(port=80, proto=Proto.TCP, state=PortState.OPEN),  # duplicate
            Service(port=443, proto=Proto.TCP, state=PortState.OPEN),  # new
        ],
    )
    eng = engine([FakeDiscoverer([h_a]), FakeDiscoverer([h_b])])
    result = await eng.run(ScanConfig(targets=["10.0.0.5"], mode=ScanMode.NORMAL))
    merged = result.hosts[0]
    assert merged.open_ports == [80, 443]
    assert result.stats.services_found == 2  # not 3


@pytest.mark.asyncio
async def test_duplicate_ip_merge_dedupes_findings():
    f = Finding(id="DUP-1", title="dup")
    h_a = Host(ip="10.0.0.5", state=HostState.UP, findings=[f])
    h_b = Host(ip="10.0.0.5", state=HostState.UP, findings=[f.model_copy()])
    eng = engine([FakeDiscoverer([h_a]), FakeDiscoverer([h_b])])
    result = await eng.run(ScanConfig(targets=["10.0.0.5"], mode=ScanMode.NORMAL))
    assert result.stats.findings == 1


@pytest.mark.asyncio
async def test_run_dedupes_expanded_targets():
    h = Host(ip="10.0.0.1", state=HostState.UP)
    eng = engine([FakeDiscoverer([h])])
    # overlapping CIDR + explicit IP both yield 10.0.0.1
    result = await eng.run(ScanConfig(targets=["10.0.0.1", "10.0.0.0/30"], mode=ScanMode.NORMAL))
    assert result.stats.targets_requested == 2  # 10.0.0.1 and 10.0.0.2, de-duped


@pytest.mark.asyncio
async def test_host_cap_truncates():
    scope = make_scope()
    scope.max_hosts_per_scan = 1
    h1 = Host(ip="10.0.0.1", state=HostState.UP)
    h2 = Host(ip="10.0.0.2", state=HostState.UP)
    eng = engine([FakeDiscoverer([h1, h2])], scope=scope)
    result = await eng.run(ScanConfig(targets=["10.0.0.0/30"], mode=ScanMode.NORMAL))
    # The cap truncates the *scanned* set to 1 host (the stat still reports the
    # full in-scope count, which is the intended distinction).
    assert len(result.hosts) == 1


@pytest.mark.asyncio
async def test_packets_sent_recorded_from_budget():
    budget = make_budget(mode=ScanMode.NORMAL, timing=5)
    h = Host(ip="10.0.0.5", state=HostState.UP)
    eng = engine([FakeDiscoverer([h])], budget=budget)
    # simulate the discoverer having sent packets
    await budget.throttle()
    result = await eng.run(ScanConfig(targets=["10.0.0.5"], mode=ScanMode.NORMAL))
    assert result.stats.packets_sent >= 1
