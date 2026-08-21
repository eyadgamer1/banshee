"""B5 device classifier — weighted-vote device typing."""

from __future__ import annotations

import pytest

from scanner.fingerprint.classifier import DeviceClassifier, classify

from .conftest import make_ctx, make_host


def test_classify_router_from_vendor():
    h = make_host(vendor="Cisco Systems")
    assert classify(h) == "router"


def test_classify_printer_from_ports():
    h = make_host(ports=[9100, 631])
    assert classify(h) == "printer"


def test_classify_workstation_from_smb_ports():
    h = make_host(ports=[135, 139, 445])
    assert classify(h) == "workstation"


def test_classify_camera_from_rtsp_port():
    h = make_host(ports=[554])
    assert classify(h) == "camera"


def test_classify_unknown_with_no_signals():
    h = make_host()
    assert classify(h) == "unknown"


def test_classify_hostname_prefix_router():
    h = make_host()
    h.hostname = "gw-core-01"
    assert classify(h) == "router"


def test_vendor_outweighs_ports():
    # vendor 'printer' weight 3 beats a single web-port server vote weight 1
    h = make_host(ports=[80], vendor="Canon")
    assert classify(h) == "printer"


@pytest.mark.asyncio
async def test_fingerprint_sets_device_type():
    fp = DeviceClassifier()
    h = make_host(ports=[9100])
    await fp.fingerprint(h, make_ctx())  # classifier ignores ctx
    assert h.device_type == "printer"


@pytest.mark.asyncio
async def test_fingerprint_preserves_existing_device_type():
    fp = DeviceClassifier()
    h = make_host(ports=[9100], device_type="preset")
    await fp.fingerprint(h, make_ctx())
    assert h.device_type == "preset"
