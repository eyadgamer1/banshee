"""D3 StealthBudget — intensity dial resolution (regression for the timing bug)."""

from __future__ import annotations

import pytest

from scanner.core.budget import _TIMING, StealthBudget
from scanner.core.models import ScanConfig, ScanMode


def budget(**kw):
    return StealthBudget.from_config(ScanConfig(**kw))


def test_zero_risk_forbids_active_probes():
    b = budget(mode=ScanMode.NORMAL, max_detect_risk=0)
    assert b.allow_active_probes is False
    assert b.can_send() is False


def test_max_detect_risk_zero_forbids_active_even_in_aggressive():
    b = budget(mode=ScanMode.AGGRESSIVE, max_detect_risk=0)
    assert b.allow_active_probes is False
    assert b.can_send() is False


def test_normal_mode_allows_active():
    b = budget(mode=ScanMode.NORMAL, timing=4)
    assert b.allow_active_probes is True
    assert b.can_send() is True
    assert b.concurrency >= 1


@pytest.mark.parametrize("timing", [0, 1, 2, 3, 4, 5])
def test_timing_template_controls_connect_timeout(timing):
    # Regression: previously --timeout always defaulted to 3000 and masked the template.
    b = budget(mode=ScanMode.NORMAL, timing=timing)
    expected_ms = _TIMING[timing][2]
    assert b.connect_timeout_ms == expected_ms


def test_explicit_timeout_overrides_template():
    b = budget(mode=ScanMode.NORMAL, timing=1, timeout_ms=1234)
    assert b.connect_timeout_ms == 1234


def test_explicit_zero_retries_honoured():
    # Regression: --retries 0 used to fall back to the template default.
    b = budget(mode=ScanMode.NORMAL, timing=3, retries=0)
    assert b.retries == 0


def test_retries_inherits_template_when_unset():
    b = budget(mode=ScanMode.NORMAL, timing=1)
    assert b.retries == _TIMING[1][3]


def test_threads_override_concurrency():
    b = budget(mode=ScanMode.NORMAL, timing=4, threads=3)
    assert b.concurrency == 3


def test_aggressive_scales_concurrency_above_normal():
    normal = budget(mode=ScanMode.NORMAL, timing=4)
    aggressive = budget(mode=ScanMode.AGGRESSIVE, timing=4)
    assert aggressive.concurrency > normal.concurrency


def test_timeout_s_property():
    b = budget(mode=ScanMode.NORMAL, timing=3, timeout_ms=2000)
    assert b.timeout_s == pytest.approx(2.0)


@pytest.mark.asyncio
async def test_throttle_counts_packets():
    b = budget(mode=ScanMode.AGGRESSIVE, timing=5)  # zero delay
    start = b.packets_sent
    await b.throttle()
    await b.throttle()
    assert b.packets_sent == start + 2


def test_make_semaphore_minimum_one():
    b = budget(mode=ScanMode.STEALTH, timing=0)  # lowest concurrency
    sem = b.make_semaphore()
    assert sem._value >= 1  # never a deadlocking zero-permit semaphore
