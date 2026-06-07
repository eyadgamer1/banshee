"""B2 — passive DHCP enrichment (graceful).

Reads hostname/MAC bindings from an existing DHCP lease database (dnsmasq or ISC
dhcpd) without emitting a single packet. When no lease file is present — the
common case on a workstation — it degrades to a clean no-op. A live DHCP sniffer
(scapy, privileged) is deferred to a later phase; the parsers here stay the shared
ingestion point.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from scanner.core.models import ConfidenceTier

if TYPE_CHECKING:
    from collections.abc import Sequence

    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

# Common lease-database locations, checked in order.
DEFAULT_LEASE_PATHS: tuple[str, ...] = (
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dnsmasq/dnsmasq.leases",
    "/var/lib/dhcp/dhcpd.leases",
    "/var/lib/dhcpd/dhcpd.leases",
)

_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_ISC_LEASE_RE = re.compile(r"lease\s+(\d{1,3}(?:\.\d{1,3}){3})\s*\{([^}]*)\}", re.DOTALL)
_ISC_MAC_RE = re.compile(r"hardware\s+ethernet\s+(" + _MAC_RE.pattern + r")\s*;")
_ISC_NAME_RE = re.compile(r'client-hostname\s+"([^"]*)"\s*;')


@dataclass(frozen=True)
class DhcpLease:
    ip: str
    mac: str | None = None
    hostname: str | None = None


def _clean_hostname(name: str | None) -> str | None:
    if name is None:
        return None
    name = name.strip()
    return name if name and name != "*" else None


def parse_dnsmasq_leases(text: str) -> dict[str, DhcpLease]:
    """Parse ``<expiry> <mac> <ip> <hostname> <clientid>`` dnsmasq lease lines."""
    table: dict[str, DhcpLease] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or not _MAC_RE.fullmatch(parts[1]):
            continue
        ip = parts[2]
        table[ip] = DhcpLease(
            ip=ip, mac=parts[1].lower(), hostname=_clean_hostname(parts[3])
        )
    return table


def parse_isc_leases(text: str) -> dict[str, DhcpLease]:
    """Parse ISC ``dhcpd.leases`` blocks; later blocks win for a repeated IP."""
    table: dict[str, DhcpLease] = {}
    for match in _ISC_LEASE_RE.finditer(text):
        ip, body = match.group(1), match.group(2)
        mac_match = _ISC_MAC_RE.search(body)
        name_match = _ISC_NAME_RE.search(body)
        table[ip] = DhcpLease(
            ip=ip,
            mac=mac_match.group(1).lower() if mac_match else None,
            hostname=_clean_hostname(name_match.group(1) if name_match else None),
        )
    return table


def parse_leases(text: str) -> dict[str, DhcpLease]:
    """Auto-detect ISC vs dnsmasq lease format and parse accordingly."""
    if "lease " in text and "{" in text:
        return parse_isc_leases(text)
    return parse_dnsmasq_leases(text)


def load_lease_table(paths: Sequence[str]) -> dict[str, DhcpLease]:
    """Merge all readable lease files into one ``{ip: DhcpLease}`` table."""
    table: dict[str, DhcpLease] = {}
    for path in paths:
        candidate = Path(path)
        if not candidate.is_file():
            continue
        try:
            table.update(parse_leases(candidate.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return table


class DhcpFingerprinter:
    """B2 — fills hostname/MAC from a local DHCP lease database. Passive."""

    name = "dhcp-passive"
    feature_id = "B2"

    def __init__(self, lease_paths: Sequence[str] = DEFAULT_LEASE_PATHS) -> None:
        self._paths = tuple(lease_paths)
        self._table: dict[str, DhcpLease] | None = None
        self._lock = asyncio.Lock()

    async def _leases(self) -> dict[str, DhcpLease]:
        if self._table is None:
            async with self._lock:
                if self._table is None:
                    loop = asyncio.get_running_loop()
                    self._table = await loop.run_in_executor(
                        None, load_lease_table, self._paths
                    )
        return self._table

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:
        lease = (await self._leases()).get(host.ip)
        if lease is None:
            return host
        if host.mac is None and lease.mac is not None:
            host.mac = lease.mac
        if lease.hostname is not None:
            host.names["dhcp"] = lease.hostname
            if host.hostname is None:
                host.hostname = lease.hostname
            if host.confidence == ConfidenceTier.POTENTIAL:
                host.confidence = ConfidenceTier.PROBABLE
        ctx.audit.log("dhcp", ip=host.ip, hostname=lease.hostname)
        return host
