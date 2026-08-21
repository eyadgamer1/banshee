"""A3 discovery — TCP-connect sweep, ICMP codec, and discoverer selection."""

from __future__ import annotations

import asyncio

import pytest

from scanner.core.models import ScanConfig, ScanMode
from scanner.discovery import get_discoverers
from scanner.discovery.icmp import _build_echo, _parse_reply, icmp_checksum
from scanner.discovery.tcp_sweep import TcpSweepDiscoverer

from .conftest import make_budget, make_ctx

# ----- TCP sweep -------------------------------------------------------------


@pytest.mark.asyncio
async def test_tcp_sweep_passive_sends_nothing():
    disc = TcpSweepDiscoverer(ports=[80])
    ctx = make_ctx(budget=make_budget(mode=ScanMode.PASSIVE, timing=0))
    hosts = await disc.discover(["10.0.0.5"], ctx)
    assert hosts == []


@pytest.mark.asyncio
async def test_tcp_sweep_detects_open_port(monkeypatch):
    disc = TcpSweepDiscoverer(ports=[80, 443])
    ctx = make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=4))

    class FakeWriter:
        def close(self):
            pass

        async def wait_closed(self):
            return None

    async def fake_open(ip, port):
        if port == 80:
            return (object(), FakeWriter())
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    hosts = await disc.discover(["10.0.0.5"], ctx)
    assert len(hosts) == 1
    assert hosts[0].open_ports == [80]
    assert hosts[0].state.value == "up"


@pytest.mark.asyncio
async def test_tcp_sweep_refused_still_proves_liveness(monkeypatch):
    disc = TcpSweepDiscoverer(ports=[80])
    ctx = make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=4))

    async def fake_open(ip, port):
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    hosts = await disc.discover(["10.0.0.5"], ctx)
    assert len(hosts) == 1  # refused = host answered = up
    assert hosts[0].open_ports == []


@pytest.mark.asyncio
async def test_tcp_sweep_dead_host_not_returned(monkeypatch):
    disc = TcpSweepDiscoverer(ports=[80])
    ctx = make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=4))

    async def fake_open(ip, port):
        raise TimeoutError

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    hosts = await disc.discover(["10.0.0.5"], ctx)
    assert hosts == []


@pytest.mark.asyncio
async def test_tcp_sweep_skips_out_of_scope(monkeypatch):
    disc = TcpSweepDiscoverer(ports=[80])
    ctx = make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=4))

    seen: list[str] = []

    async def fake_open(ip, port):
        seen.append(ip)
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    # 8.8.8.8 is out of scope; defense-in-depth filter must drop it
    await disc.discover(["10.0.0.5", "8.8.8.8"], ctx)
    assert "8.8.8.8" not in seen


# ----- ICMP codec ------------------------------------------------------------


def test_icmp_checksum_known_value():
    # checksum of all-zero header is 0xFFFF (one's complement of 0)
    assert icmp_checksum(b"\x00\x00\x00\x00") == 0xFFFF


def test_icmp_checksum_handles_odd_length():
    # must not raise on odd-length input (padding)
    assert isinstance(icmp_checksum(b"\x01\x02\x03"), int)


def test_build_echo_and_parse_reply_roundtrip():
    pkt = _build_echo(ident=0x1234, seq=7)
    # simulate an IP+ICMP echo *reply*: 20-byte IP header + ICMP with type 0
    ip_header = bytes([0x45]) + b"\x00" * 19
    icmp_reply = bytes([0, 0]) + pkt[2:4] + (0x1234).to_bytes(2, "big") + (7).to_bytes(2, "big")
    parsed = _parse_reply(ip_header + icmp_reply)
    assert parsed == (0x1234, 7)


def test_parse_reply_rejects_non_reply_type():
    ip_header = bytes([0x45]) + b"\x00" * 19
    echo_request = bytes([8, 0]) + b"\x00\x00" + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
    assert _parse_reply(ip_header + echo_request) is None


def test_parse_reply_rejects_truncated():
    assert _parse_reply(b"\x45\x00") is None


# ----- discoverer selection --------------------------------------------------


def test_passive_mode_only_sniffer():
    discs = get_discoverers(ScanConfig(mode=ScanMode.PASSIVE))
    names = {d.name for d in discs}
    assert names == {"passive-sniffer"}


def test_normal_mode_adds_active():
    discs = get_discoverers(ScanConfig(mode=ScanMode.NORMAL))
    names = {d.name for d in discs}
    assert "tcp-sweep" in names
    assert "icmp-ping" in names


def test_pcap_mode_only_pcap():
    discs = get_discoverers(ScanConfig(mode=ScanMode.NORMAL, pcap="x.pcap"))
    assert [d.name for d in discs] == ["pcap"]
