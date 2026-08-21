"""B12 pcap discoverer + B3/B4 fingerprinter selection (offline)."""

from __future__ import annotations

import pytest

from scanner.core.models import ScanConfig, ScanMode
from scanner.discovery.pcap import PcapDiscoverer
from scanner.fingerprint import get_fingerprinters

from .conftest import make_ctx


@pytest.mark.asyncio
async def test_pcap_missing_file_returns_empty():
    disc = PcapDiscoverer("no/such/file.pcap")
    hosts = await disc.discover(["0.0.0.0/0"], make_ctx())
    assert hosts == []


def test_passive_mode_skips_raw_socket_fingerprinters():
    fps = get_fingerprinters(ScanConfig(mode=ScanMode.PASSIVE, names=True))
    names = {f.name for f in fps}
    assert "tcpip-fingerprinter" not in names  # B3 needs raw sockets
    assert "clock-skew" not in names  # B7 active
    assert "oui-vendor" in names  # B1 passive always runs
    assert "negative-space" in names  # B8 analytical always runs


def test_normal_mode_includes_active_fingerprinters():
    fps = get_fingerprinters(ScanConfig(mode=ScanMode.NORMAL, names=True))
    names = {f.name for f in fps}
    assert "tcpip-fingerprinter" in names
    assert "clock-skew" in names


def test_no_names_flag_drops_resolver():
    fps = get_fingerprinters(ScanConfig(mode=ScanMode.NORMAL, names=False))
    assert "name-resolve" not in {f.name for f in fps}


def test_classify_flag_adds_classifier():
    without = {f.name for f in get_fingerprinters(ScanConfig(mode=ScanMode.NORMAL, classify=False))}
    with_ = {f.name for f in get_fingerprinters(ScanConfig(mode=ScanMode.NORMAL, classify=True))}
    assert "device-classifier" not in without
    assert "device-classifier" in with_
