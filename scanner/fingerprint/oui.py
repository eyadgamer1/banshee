"""B1 — OUI vendor identification (passive).

Resolves a host's MAC from the local ARP cache (no packets — reads the OS table)
and maps its 24-bit OUI prefix to a hardware vendor via a built-in IEEE table.
Only hosts on the local L2 segment have an ARP entry; everything else simply
yields no vendor. Being read-only, this runs in every mode and even at max-detect-risk 0.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from scanner.core.models import ConfidenceTier

if TYPE_CHECKING:
    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ARP_TIMEOUT_S = 5.0

# Curated subset of the IEEE OUI registry — enough to name common LAN hardware and
# flag virtualization. Prefix is the upper-case 24-bit OUI with no separators.
_OUI_TABLE: dict[str, str] = {
    "000C29": "VMware",
    "005056": "VMware",
    "000569": "VMware",
    "080027": "Oracle VirtualBox",
    "0003FF": "Microsoft (Hyper-V)",
    "00155D": "Microsoft (Hyper-V)",
    "525400": "QEMU/KVM",
    "001C42": "Parallels",
    "DCA632": "Raspberry Pi",
    "B827EB": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "2CCF67": "Raspberry Pi",
    "001451": "Apple",
    "3C0754": "Apple",
    "A4C361": "Apple",
    "F01898": "Apple",
    "ACBC32": "Apple",
    "001A11": "Google",
    "3C5AB4": "Google",
    "F4F5E8": "Google",
    "44650D": "Amazon",
    "FC65DE": "Amazon",
    "001788": "Philips Hue",
    "000E58": "Sonos",
    "B8E937": "Sonos",
    "001B63": "Cisco",
    "00000C": "Cisco",
    "0050F0": "Cisco",
    "F4CFE2": "Cisco",
    "0018F3": "ASUSTek",
    "AC220B": "ASUSTek",
    "001E2A": "Netgear",
    "A040A0": "Netgear",
    "00146C": "Netgear",
    "5051A9": "TP-Link",
    "EC086B": "TP-Link",
    "001F3F": "AVM (FRITZ!Box)",
    "DC9FDB": "Ubiquiti",
    "FCECDA": "Ubiquiti",
    "744401": "Ubiquiti",
    "B4FBE4": "Ubiquiti",
    "001CB3": "Apple",
    "F0DEF1": "Wistron",
    "5CCF7F": "Espressif (ESP8266)",
    "A020A6": "Espressif (ESP32)",
    "3C71BF": "Espressif",
    "001302": "Intel",
    "001B21": "Intel",
    "A0A8CD": "Intel",
    "001125": "IBM",
    "00163E": "Xensource",
    "001A4B": "Hewlett-Packard",
    "001E0B": "Hewlett-Packard",
    "3863BB": "Hewlett-Packard",
    "00188B": "Dell",
    "B083FE": "Dell",
    "F8BC12": "Dell",
    "001321": "Samsung",
    "5CF6DC": "Samsung",
    "001632": "Samsung",
    "8C8590": "Huawei",
    "00259E": "Huawei",
    "286ED4": "Huawei",
    "640980": "Xiaomi",
    "F8A45F": "Xiaomi",
}


def normalize_mac(mac: str) -> str:
    """Lower-case, colon-separated canonical form (``aa:bb:cc:dd:ee:ff``)."""
    return mac.strip().lower().replace("-", ":")


def oui_prefix(mac: str) -> str:
    """Upper-case 24-bit OUI of a MAC with separators stripped (``AABBCC``)."""
    hexed = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    return hexed[:6]


def vendor_for_mac(mac: str) -> str | None:
    """Map a MAC to a vendor via the built-in OUI table, or None if unknown."""
    return _OUI_TABLE.get(oui_prefix(mac))


def _read_proc_net_arp() -> dict[str, str]:
    arp = Path("/proc/net/arp")
    if not arp.exists():
        return {}
    table: dict[str, str] = {}
    for line in arp.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 4 and _MAC_RE.fullmatch(cols[3]) and cols[3] != "00:00:00:00:00:00":
            table[cols[0]] = normalize_mac(cols[3])
    return table


def _read_arp_command() -> dict[str, str]:
    try:
        proc = subprocess.run(  # noqa: S603,S607 - fixed argv, no shell, no user input
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=_ARP_TIMEOUT_S,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return {}
    table: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        mac_match = _MAC_RE.search(line)
        ip_match = _IP_RE.search(line)
        if mac_match and ip_match:
            table[ip_match.group(0)] = normalize_mac(mac_match.group(0))
    return table


def read_arp_table() -> dict[str, str]:
    """Snapshot the OS ARP cache as ``{ip: mac}``. Empty on any failure."""
    return _read_proc_net_arp() or _read_arp_command()


class OuiFingerprinter:
    """B1 — fills a host's MAC (from ARP cache) and vendor (from OUI table)."""

    name = "oui-vendor"
    feature_id = "B1"

    def __init__(self) -> None:
        self._arp: dict[str, str] | None = None
        self._lock = asyncio.Lock()

    async def _arp_table(self) -> dict[str, str]:
        if self._arp is None:
            async with self._lock:
                if self._arp is None:  # double-checked under lock
                    loop = asyncio.get_running_loop()
                    self._arp = await loop.run_in_executor(None, read_arp_table)
        return self._arp

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:
        if host.mac is None:
            mac = (await self._arp_table()).get(host.ip)
            if mac is not None:
                host.mac = mac
        if host.mac is not None and host.vendor is None:
            vendor = vendor_for_mac(host.mac)
            if vendor is not None:
                host.vendor = vendor
                if host.confidence == ConfidenceTier.POTENTIAL:
                    host.confidence = ConfidenceTier.PROBABLE
        ctx.audit.log("oui", ip=host.ip, mac=host.mac, vendor=host.vendor)
        return host
