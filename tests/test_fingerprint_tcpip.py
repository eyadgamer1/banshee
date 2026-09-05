"""B3 TCP/IP stack fingerprint — TTL/window buckets and OS table (incl. BUG5)."""

from __future__ import annotations

import pytest

from scanner.core.models import ScanMode
from scanner.fingerprint.tcpip import _OS_TABLE, TcpIpFingerprinter, _ttl_bucket, _win_bucket

from .conftest import make_budget, make_ctx, make_host


@pytest.mark.parametrize(
    "ttl,expected",
    [(64, 64), (53, 64), (1, 64), (128, 128), (117, 128), (255, 255), (240, 255), (200, 255)],
)
def test_ttl_bucket_rounds_up_to_initial_value(ttl, expected):
    assert _ttl_bucket(ttl) == expected


@pytest.mark.parametrize(
    "window,expected",
    [(0, "small"), (1024, "small"), (8191, "small"), (8192, "medium"), (16000, "medium"),
     (32767, "medium"), (32768, "large"), (65535, "large")],
)
def test_win_bucket_thresholds(window, expected):
    assert _win_bucket(window) == expected


def test_os_table_linux_64():
    assert _OS_TABLE[(64, "large")][0] == "Linux"


def test_os_table_windows_128():
    assert _OS_TABLE[(128, "large")][0] == "Windows"


def test_os_table_255_large_is_cloud_lb_not_cisco():
    # BUG5 regression: TTL=255 + large window must NOT be "Cisco IOS".
    label = _OS_TABLE[(255, "large")][0]
    assert "cloud-LB" in label
    assert "Cisco" not in label


def test_os_table_255_small_stays_cisco():
    assert "Cisco" in _OS_TABLE[(255, "small")][0]


@pytest.mark.asyncio
async def test_fingerprint_noop_when_budget_forbids_active():
    fp = TcpIpFingerprinter()
    ctx = make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=0, max_detect_risk=0))
    host = make_host(ports=[80])
    await fp.fingerprint(host, ctx)
    assert host.os_guess is None  # never probed


@pytest.mark.asyncio
async def test_fingerprint_noop_without_open_ports():
    fp = TcpIpFingerprinter()
    ctx = make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=4))
    host = make_host(ports=[])
    await fp.fingerprint(host, ctx)
    assert host.os_guess is None


@pytest.mark.asyncio
async def test_fingerprint_maps_probe_result(monkeypatch):
    fp = TcpIpFingerprinter()
    ctx = make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=4))
    host = make_host(ports=[443])
    monkeypatch.setattr(fp, "_probe_sync", lambda ip, port: (64, 65535))
    await fp.fingerprint(host, ctx)
    assert host.os_guess == "Linux"
    assert host.device_type == "server/workstation"


@pytest.mark.asyncio
async def test_fingerprint_does_not_overwrite_existing_os(monkeypatch):
    fp = TcpIpFingerprinter()
    ctx = make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=4))
    host = make_host(ports=[443], os_guess="PreSet")
    monkeypatch.setattr(fp, "_probe_sync", lambda ip, port: (128, 65535))
    await fp.fingerprint(host, ctx)
    assert host.os_guess == "PreSet"
