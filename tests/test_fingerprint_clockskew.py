"""B7 clock-skew — categorisation and anycast sentinel handling (BUG6)."""

from __future__ import annotations

import pytest

from scanner.core.models import ScanMode
from scanner.fingerprint.clockskew import ClockSkewFingerprinter, _categorize

from .conftest import make_budget, make_ctx, make_host


@pytest.mark.parametrize(
    "ppm,expected",
    [(0.0, "near-zero"), (0.5, "near-zero"), (1, "normal"), (199, "normal"),
     (200, "high"), (1999, "high"), (2000, "extreme"), (50000, "extreme")],
)
def test_categorize_boundaries(ppm, expected):
    assert _categorize(ppm) == expected


def test_pick_port_prefers_known_probe_ports():
    fp = ClockSkewFingerprinter()
    host = make_host(ports=[3389, 443])
    # 443 ranks before 3389 in _PROBE_PORTS order
    assert fp._pick_port(host) == 443


def test_pick_port_none_without_ports():
    fp = ClockSkewFingerprinter()
    assert fp._pick_port(make_host(ports=[])) is None


@pytest.mark.asyncio
async def test_fingerprint_noop_in_passive():
    fp = ClockSkewFingerprinter()
    ctx = make_ctx(budget=make_budget(mode=ScanMode.PASSIVE, timing=0))
    host = make_host(ports=[443])
    await fp.fingerprint(host, ctx)
    assert "clock_skew_cat" not in host.names


@pytest.mark.asyncio
async def test_fingerprint_anycast_sentinel(monkeypatch):
    import scanner.fingerprint.clockskew as ck

    async def fake_probe(ip, port):
        return -1.0  # anycast sentinel

    monkeypatch.setattr(ck, "_probe_skew", fake_probe)
    fp = ClockSkewFingerprinter()
    host = make_host(ip="10.0.0.5", ports=[443])
    await fp.fingerprint(host, make_ctx())
    assert host.names["clock_skew_cat"] == "anycast-cdn"
    assert any("Anycast" in f.title for f in host.findings)


@pytest.mark.asyncio
async def test_fingerprint_high_skew_categorised(monkeypatch):
    import scanner.fingerprint.clockskew as ck

    async def fake_probe(ip, port):
        return 800.0

    monkeypatch.setattr(ck, "_probe_skew", fake_probe)
    fp = ClockSkewFingerprinter()
    host = make_host(ip="10.0.0.5", ports=[443])
    await fp.fingerprint(host, make_ctx())
    assert host.names["clock_skew_cat"] == "high"
    assert host.names["clock_skew_ppm"] == "800"


@pytest.mark.asyncio
async def test_fingerprint_near_zero_flags_vm(monkeypatch):
    import scanner.fingerprint.clockskew as ck

    async def fake_probe(ip, port):
        return 0.0

    monkeypatch.setattr(ck, "_probe_skew", fake_probe)
    fp = ClockSkewFingerprinter()
    host = make_host(ip="10.0.0.5", ports=[443])
    await fp.fingerprint(host, make_ctx())
    assert host.names["clock_skew_cat"] == "near-zero"
    assert any("VM" in f.title or "container" in f.title for f in host.findings)


@pytest.mark.asyncio
async def test_fingerprint_none_result_adds_nothing(monkeypatch):
    import scanner.fingerprint.clockskew as ck

    async def fake_probe(ip, port):
        return None

    monkeypatch.setattr(ck, "_probe_skew", fake_probe)
    fp = ClockSkewFingerprinter()
    host = make_host(ip="10.0.0.5", ports=[443])
    await fp.fingerprint(host, make_ctx())
    assert "clock_skew_cat" not in host.names
    assert host.findings == []
