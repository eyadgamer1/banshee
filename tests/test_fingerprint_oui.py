"""B1 OUI — MAC normalisation, prefix lookup, and ARP-table parsing."""

from __future__ import annotations

import pytest

from scanner.fingerprint.oui import (
    OuiFingerprinter,
    normalize_mac,
    oui_prefix,
    read_arp_table,
    vendor_for_mac,
)

from .conftest import make_ctx, make_host


def test_normalize_mac_lowercase_colons():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_oui_prefix_strips_separators_uppercases():
    assert oui_prefix("00:0c:29:ab:cd:ef") == "000C29"
    assert oui_prefix("b8-27-eb-00-11-22") == "B827EB"


def test_vendor_for_mac_known():
    assert vendor_for_mac("00:0c:29:11:22:33") == "VMware"
    assert vendor_for_mac("b8:27:eb:aa:bb:cc") == "Raspberry Pi"


def test_vendor_for_mac_unknown():
    assert vendor_for_mac("de:ad:be:ef:00:11") is None


def test_read_arp_table_never_raises():
    # Reads the real OS ARP cache; must return a dict regardless of platform.
    table = read_arp_table()
    assert isinstance(table, dict)


@pytest.mark.asyncio
async def test_fingerprint_sets_vendor_from_mac():
    fp = OuiFingerprinter()
    fp._arp = {"10.0.0.5": "00:0c:29:11:22:33"}  # pre-seed ARP cache, no syscall
    host = make_host(ip="10.0.0.5")
    await fp.fingerprint(host, make_ctx(budget=None))
    assert host.mac == "00:0c:29:11:22:33"
    assert host.vendor == "VMware"


@pytest.mark.asyncio
async def test_fingerprint_no_mac_no_vendor():
    fp = OuiFingerprinter()
    fp._arp = {}  # empty cache
    host = make_host(ip="10.0.0.99")
    await fp.fingerprint(host, make_ctx())
    assert host.mac is None
    assert host.vendor is None


@pytest.mark.asyncio
async def test_fingerprint_runs_with_zero_budget():
    # OUI is read-only (ARP cache) — must work even when no active packets are allowed.
    from scanner.core.models import ScanMode

    from .conftest import make_budget

    fp = OuiFingerprinter()
    fp._arp = {"10.0.0.5": "b8:27:eb:00:11:22"}
    host = make_host(ip="10.0.0.5")
    ctx = make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=0, max_detect_risk=0))
    await fp.fingerprint(host, ctx)
    assert host.vendor == "Raspberry Pi"
