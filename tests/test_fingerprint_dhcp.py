"""B2 DHCP — lease-file parsers (dnsmasq + ISC) and enrichment."""

from __future__ import annotations

import pytest

from scanner.fingerprint.dhcp import (
    DhcpFingerprinter,
    load_lease_table,
    parse_dnsmasq_leases,
    parse_isc_leases,
    parse_leases,
)

from .conftest import make_ctx, make_host

DNSMASQ = (
    "1700000000 aa:bb:cc:dd:ee:ff 10.0.0.50 laptop 01:aa:bb:cc:dd:ee:ff\n"
    "1700000001 11:22:33:44:55:66 10.0.0.51 * 01:11:22:33:44:55:66\n"
    "bad line here\n"
)

ISC = """
lease 10.0.0.60 {
  starts 5 2024/01/01 00:00:00;
  hardware ethernet de:ad:be:ef:00:11;
  client-hostname "desktop-x";
}
lease 10.0.0.61 {
  hardware ethernet de:ad:be:ef:00:22;
}
"""


def test_parse_dnsmasq_basic():
    table = parse_dnsmasq_leases(DNSMASQ)
    assert table["10.0.0.50"].mac == "aa:bb:cc:dd:ee:ff"
    assert table["10.0.0.50"].hostname == "laptop"


def test_parse_dnsmasq_star_hostname_cleaned():
    table = parse_dnsmasq_leases(DNSMASQ)
    assert table["10.0.0.51"].hostname is None  # "*" -> None


def test_parse_dnsmasq_ignores_malformed():
    table = parse_dnsmasq_leases(DNSMASQ)
    assert "bad" not in table
    assert len(table) == 2


def test_parse_isc_basic():
    table = parse_isc_leases(ISC)
    assert table["10.0.0.60"].mac == "de:ad:be:ef:00:11"
    assert table["10.0.0.60"].hostname == "desktop-x"


def test_parse_isc_missing_hostname():
    table = parse_isc_leases(ISC)
    assert table["10.0.0.61"].hostname is None


def test_parse_leases_autodetects_isc():
    assert parse_leases(ISC)["10.0.0.60"].mac == "de:ad:be:ef:00:11"


def test_parse_leases_autodetects_dnsmasq():
    assert parse_leases(DNSMASQ)["10.0.0.50"].hostname == "laptop"


def test_load_lease_table_from_files(tmp_path):
    p1 = tmp_path / "dnsmasq.leases"
    p1.write_text(DNSMASQ, encoding="utf-8")
    p2 = tmp_path / "dhcpd.leases"
    p2.write_text(ISC, encoding="utf-8")
    table = load_lease_table([str(p1), str(p2), str(tmp_path / "missing")])
    assert "10.0.0.50" in table
    assert "10.0.0.60" in table


@pytest.mark.asyncio
async def test_fingerprint_enriches_host(tmp_path):
    p = tmp_path / "dnsmasq.leases"
    p.write_text(DNSMASQ, encoding="utf-8")
    fp = DhcpFingerprinter(lease_paths=[str(p)])
    host = make_host(ip="10.0.0.50")
    await fp.fingerprint(host, make_ctx())
    assert host.hostname == "laptop"
    assert host.names.get("dhcp") == "laptop"
    assert host.mac == "aa:bb:cc:dd:ee:ff"


@pytest.mark.asyncio
async def test_fingerprint_noop_for_unknown_ip(tmp_path):
    p = tmp_path / "dnsmasq.leases"
    p.write_text(DNSMASQ, encoding="utf-8")
    fp = DhcpFingerprinter(lease_paths=[str(p)])
    host = make_host(ip="10.0.0.250")
    await fp.fingerprint(host, make_ctx())
    assert host.hostname is None
