"""B5 — Bayesian device-type classifier.

Combines evidence signals into a device-type label using a simple weighted
vote. This is a deterministic, offline classifier — no ML runtime required.

Signals used (higher weight = more authoritative):
  - OUI vendor string (weight 3)
  - DHCP hostname prefix (weight 2)
  - Open ports set (weight 2)
  - OS guess from B3 (weight 1)
  - mDNS service type (weight 1)

Device types emitted:
  router, switch, access-point, printer, camera, iot, server, workstation,
  mobile, nas, voip, unknown
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

# --- vendor → device hints ---
_VENDOR_HINTS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"cisco|juniper|mikrotik|ubiquiti|netgear|zyxel|draytek", re.I), "router", 3),
    (re.compile(r"aruba|ruckus|aerohive|meraki", re.I), "access-point", 3),
    (re.compile(r"hp.*print|canon|epson|brother|lexmark|xerox|konica", re.I), "printer", 3),
    (re.compile(r"axis|hikvision|dahua|avigilon|hanwha|bosch.*sec", re.I), "camera", 3),
    (re.compile(r"synology|qnap|netapp|western.dig|seagate.*nas", re.I), "nas", 3),
    (re.compile(r"yealink|polycom|grandstream|cisco.*voip|snom", re.I), "voip", 3),
    (re.compile(r"apple|samsung|huawei|xiaomi|oneplus|lg.*mobile", re.I), "mobile", 3),
    (re.compile(r"vmware|virtual.*box|kvm|proxmox|hyper.*v", re.I), "server", 2),
    (re.compile(r"raspberry|arduino|espressif|particle", re.I), "iot", 2),
]

# --- hostname prefix → hints ---
_HOST_HINTS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"^router|^gw|^gateway|^fw|^firewall", re.I), "router", 2),
    (re.compile(r"^ap[- _]|^wifi|^wlan|^wireless", re.I), "access-point", 2),
    (re.compile(r"^printer|^print|^hp.*lj|^canon.*mf", re.I), "printer", 2),
    (re.compile(r"^cam[- _]|^ipcam|^nvr|^dvr", re.I), "camera", 2),
    (re.compile(r"^nas|^storage|^synology|^qnap", re.I), "nas", 2),
    (re.compile(r"^voip|^phone|^sip|^pbx", re.I), "voip", 2),
    (re.compile(r"^android|^iphone|^ipad|^mobile", re.I), "mobile", 2),
    (re.compile(r"^server|^srv|^web|^db|^sql", re.I), "server", 2),
    (re.compile(r"^win|^desktop|^pc[- _]|^laptop", re.I), "workstation", 2),
]

# --- open ports → hints ---
_PORT_HINTS: list[tuple[frozenset[int], str, int]] = [
    (frozenset({80, 443, 8080, 8443}), "server", 1),
    (frozenset({22}), "server", 1),
    (frozenset({445, 135, 139}), "workstation", 2),
    (frozenset({3389}), "workstation", 2),
    (frozenset({9100, 631}), "printer", 3),
    (frozenset({554, 8554}), "camera", 3),
    (frozenset({5060, 5061}), "voip", 3),
    (frozenset({548, 2049}), "nas", 2),
    (frozenset({161}), "router", 1),
]

# --- OS guess → hints ---
_OS_HINTS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"windows", re.I), "workstation", 1),
    (re.compile(r"linux", re.I), "server", 1),
    (re.compile(r"ios|cisco", re.I), "router", 1),
]


def classify(host: Host) -> str:
    """Return the most likely device type label for a host."""
    votes: dict[str, int] = {}

    def vote(label: str, weight: int) -> None:
        votes[label] = votes.get(label, 0) + weight

    # Vendor signals
    if host.vendor:
        for pattern, label, weight in _VENDOR_HINTS:
            if pattern.search(host.vendor):
                vote(label, weight)

    # Hostname signals
    name = host.hostname or host.names.get("mdns") or host.names.get("netbios") or ""
    if name:
        for pattern, label, weight in _HOST_HINTS:
            if pattern.search(name):
                vote(label, weight)

    # Port signals
    open_ports = frozenset(host.open_ports)
    for port_set, label, weight in _PORT_HINTS:
        if port_set & open_ports:
            vote(label, weight)

    # OS guess signals
    if host.os_guess:
        for pattern, label, weight in _OS_HINTS:
            if pattern.search(host.os_guess):
                vote(label, weight)

    if not votes:
        return "unknown"
    return max(votes, key=lambda k: votes[k])


class DeviceClassifier:
    """B5 — assigns device_type to each host via weighted signal voting."""

    name = "device-classifier"
    feature_id = "B5"

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:
        if not host.device_type:
            host.device_type = classify(host)
        return host
