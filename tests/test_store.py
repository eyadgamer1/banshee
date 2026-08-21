"""A6 ScanStore + E2 rogue detector — persistence and baseline diffing."""

from __future__ import annotations

import pytest

from scanner.core.models import (
    ConfidenceTier,
    Finding,
    Host,
    HostState,
    PortState,
    Proto,
    ScanConfig,
    ScanResult,
    ScanStats,
    Service,
    Severity,
)
from scanner.store import RogueDetector, ScanStore


def sample_result() -> ScanResult:
    host = Host(
        ip="10.0.0.5",
        state=HostState.UP,
        mac="aa:bb:cc:dd:ee:ff",
        vendor="VMware",
        hostname="vm1",
        services=[Service(port=22, proto=Proto.TCP, state=PortState.OPEN,
                          confidence=ConfidenceTier.CONFIRMED, source="A3")],
        findings=[Finding(id="F1", title="t", severity=Severity.LOW, source="C1")],
    )
    return ScanResult(
        config=ScanConfig(targets=["10.0.0.5"]),
        hosts=[host],
        stats=ScanStats(hosts_up=1, services_found=1, findings=1),
    )


@pytest.mark.asyncio
async def test_save_result_returns_run_id(tmp_path):
    async with ScanStore(tmp_path / "pps.db") as store:
        run_id = await store.save_result(sample_result())
        assert isinstance(run_id, int)
        assert run_id >= 1


@pytest.mark.asyncio
async def test_known_macs_roundtrip(tmp_path):
    async with ScanStore(tmp_path / "pps.db") as store:
        await store.save_result(sample_result())
        macs = await store.get_known_macs()
        assert "aa:bb:cc:dd:ee:ff" in macs


@pytest.mark.asyncio
async def test_get_runs_lists_saved(tmp_path):
    async with ScanStore(tmp_path / "pps.db") as store:
        await store.save_result(sample_result())
        await store.save_result(sample_result())
        runs = await store.get_runs()
        assert len(runs) == 2


@pytest.mark.asyncio
async def test_save_persists_across_sessions(tmp_path):
    db = tmp_path / "pps.db"
    async with ScanStore(db) as store:
        await store.save_result(sample_result())
    async with ScanStore(db) as store2:
        macs = await store2.get_known_macs()
        assert "aa:bb:cc:dd:ee:ff" in macs


def test_rogue_detector_flags_unknown_mac():
    r = sample_result()
    rogues = RogueDetector().check(r, known_macs=set())
    assert len(rogues) == 1
    assert any(f.id.startswith("E2-") for f in r.hosts[0].findings)


def test_rogue_detector_ignores_known_mac():
    r = sample_result()
    rogues = RogueDetector().check(r, known_macs={"aa:bb:cc:dd:ee:ff"})
    assert rogues == []


def test_rogue_detector_skips_macless_hosts():
    r = ScanResult(config=ScanConfig(), hosts=[Host(ip="10.0.0.9", state=HostState.UP)])
    assert RogueDetector().check(r, known_macs=set()) == []
