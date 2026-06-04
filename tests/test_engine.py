"""A1 engine tests — target expansion, dry-run safety, DI pipeline."""

from __future__ import annotations

import pytest

from scanner.core.budget import StealthBudget
from scanner.core.engine import ScanEngine, expand_target
from scanner.core.interfaces import ScanContext
from scanner.core.models import Host, HostState, ScanConfig, ScanMode, Service
from scanner.core.scope import AuditLog, ScopeGuard


class FakeDiscoverer:
    name = "fake-disc"
    feature_id = "TEST"

    def __init__(self, up: set[str]) -> None:
        self.up = up
        self.seen: list[str] = []

    async def discover(self, targets: list[str], ctx: ScanContext) -> list[Host]:
        self.seen = list(targets)
        return [Host(ip=ip, state=HostState.UP) for ip in targets if ip in self.up]


class FakeFingerprinter:
    name = "fake-fp"
    feature_id = "TEST"

    def __init__(self) -> None:
        self.hits: list[str] = []

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:
        self.hits.append(host.ip)
        host.services.append(Service(port=80, name="http", source="TEST"))
        host.hostname = "fake.lan"
        return host


def _guard() -> ScopeGuard:
    return ScopeGuard(allowlist=["127.0.0.0/8", "10.0.0.0/8"], audit=AuditLog(None))


def _engine(cfg: ScanConfig, disc: FakeDiscoverer, fp: FakeFingerprinter) -> ScanEngine:
    return ScanEngine(_guard(), StealthBudget.from_config(cfg), [disc], [fp])


# --- target expansion ---


def test_expand_cidr() -> None:
    assert expand_target("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


def test_expand_single_ip() -> None:
    assert expand_target("10.0.0.5") == ["10.0.0.5"]


def test_expand_last_octet_range() -> None:
    assert expand_target("10.0.0.5-7") == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]


def test_expand_full_range() -> None:
    assert expand_target("10.0.0.254-10.0.1.1") == [
        "10.0.0.254",
        "10.0.0.255",
        "10.0.1.0",
        "10.0.1.1",
    ]


def test_expand_hostname_passthrough() -> None:
    assert expand_target("host.lan") == ["host.lan"]


# --- pipeline ---


@pytest.mark.asyncio
async def test_dry_run_sends_nothing() -> None:
    cfg = ScanConfig(targets=["10.0.0.0/30"], mode=ScanMode.NORMAL, dry_run=True)
    disc, fp = FakeDiscoverer(up={"10.0.0.1"}), FakeFingerprinter()
    result = await _engine(cfg, disc, fp).run(cfg)
    assert disc.seen == []  # discoverer never called
    assert fp.hits == []
    assert result.stats.packets_sent == 0
    assert len(result.hosts) == 2  # planned, state unknown
    assert all(h.state == HostState.UNKNOWN for h in result.hosts)


@pytest.mark.asyncio
async def test_full_pipeline_discovers_and_fingerprints() -> None:
    cfg = ScanConfig(targets=["10.0.0.0/29"], mode=ScanMode.NORMAL)
    disc, fp = FakeDiscoverer(up={"10.0.0.1", "10.0.0.3"}), FakeFingerprinter()
    result = await _engine(cfg, disc, fp).run(cfg)
    assert result.stats.hosts_up == 2
    assert sorted(fp.hits) == ["10.0.0.1", "10.0.0.3"]
    up = result.up_hosts
    assert all(h.hostname == "fake.lan" for h in up)
    assert all(80 in h.open_ports for h in up)


@pytest.mark.asyncio
async def test_out_of_scope_filtered_before_discovery() -> None:
    cfg = ScanConfig(targets=["10.0.0.1", "8.8.8.8"], mode=ScanMode.NORMAL)
    disc, fp = FakeDiscoverer(up={"10.0.0.1"}), FakeFingerprinter()
    result = await _engine(cfg, disc, fp).run(cfg)
    assert "8.8.8.8" not in disc.seen
    assert result.stats.targets_out_of_scope == 1
    assert result.stats.targets_in_scope == 1
