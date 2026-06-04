"""D3 stealth-budget tests — intensity dial resolution + the passive guarantee."""

from __future__ import annotations

import pytest

from scanner.core.budget import StealthBudget
from scanner.core.models import ScanConfig, ScanMode


def _cfg(**kw: object) -> ScanConfig:
    return ScanConfig(targets=["127.0.0.1"], **kw)  # type: ignore[arg-type]


def test_passive_sends_zero_packets() -> None:
    b = StealthBudget.from_config(_cfg(mode=ScanMode.PASSIVE))
    assert b.allow_active_probes is False
    assert b.concurrency == 0
    assert b.can_send() is False


def test_normal_allows_active() -> None:
    b = StealthBudget.from_config(_cfg(mode=ScanMode.NORMAL))
    assert b.allow_active_probes is True
    assert b.concurrency > 0
    assert b.can_send() is True


def test_max_detect_risk_zero_forces_passive() -> None:
    b = StealthBudget.from_config(_cfg(mode=ScanMode.AGGRESSIVE, max_detect_risk=0))
    assert b.allow_active_probes is False
    assert b.can_send() is False


def test_aggressive_more_concurrent_than_stealth() -> None:
    stealth = StealthBudget.from_config(_cfg(mode=ScanMode.STEALTH))
    aggressive = StealthBudget.from_config(_cfg(mode=ScanMode.AGGRESSIVE))
    assert aggressive.concurrency > stealth.concurrency


def test_explicit_threads_override() -> None:
    b = StealthBudget.from_config(_cfg(mode=ScanMode.NORMAL, threads=7))
    assert b.concurrency == 7


def test_timing_template_affects_timeout() -> None:
    t0 = StealthBudget.from_config(_cfg(mode=ScanMode.NORMAL, timing=0, timeout_ms=0))
    t5 = StealthBudget.from_config(_cfg(mode=ScanMode.NORMAL, timing=5, timeout_ms=0))
    assert t0.connect_timeout_ms > t5.connect_timeout_ms


@pytest.mark.asyncio
async def test_throttle_counts_packets() -> None:
    b = StealthBudget.from_config(_cfg(mode=ScanMode.AGGRESSIVE, timing=5))
    await b.throttle()
    await b.throttle()
    assert b.packets_sent == 2
