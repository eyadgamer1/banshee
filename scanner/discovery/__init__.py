"""Discovery module — finds live hosts among in-scope targets (A2–A5).

Integration contract consumed by the CLI: `get_discoverers(cfg)` returns the
Discoverer instances appropriate for the requested scan mode.

P1: A3 TCP-connect sweep + ICMP echo.
P2: A2 passive sniffer (zero-packet, always prepended in PASSIVE mode).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scanner.discovery.icmp import IcmpPingDiscoverer
from scanner.discovery.pcap import PcapDiscoverer
from scanner.discovery.sniffer import PassiveSniffer
from scanner.discovery.tcp_sweep import TcpSweepDiscoverer

if TYPE_CHECKING:
    from scanner.core.interfaces import Discoverer
    from scanner.core.models import ScanConfig

__all__ = [
    "IcmpPingDiscoverer",
    "PassiveSniffer",
    "PcapDiscoverer",
    "TcpSweepDiscoverer",
    "get_discoverers",
]


def get_discoverers(cfg: ScanConfig) -> list[Discoverer]:
    """Return ordered discoverers for this run.

    If cfg.pcap is set, only the offline pcap discoverer runs.
    Otherwise PassiveSniffer always runs first, then active discoverers in non-passive modes.
    """
    from scanner.core.models import ScanMode

    if getattr(cfg, "pcap", None):
        return [PcapDiscoverer(cfg.pcap)]  # type: ignore[arg-type]
    discoverers: list[Discoverer] = [PassiveSniffer(iface=cfg.iface)]
    if cfg.mode != ScanMode.PASSIVE:
        discoverers.append(IcmpPingDiscoverer())
        discoverers.append(TcpSweepDiscoverer())
    return discoverers
