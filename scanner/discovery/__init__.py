"""Discovery module — finds live hosts among in-scope targets (A2–A5).

Integration contract consumed by the CLI: `get_discoverers(cfg)` returns the
active Discoverer instances for the run.

A3 TCP-connect sweep + ICMP echo. (The budget still enforces quiet: at
max-detect-risk 0 the discoverers send nothing.)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scanner.discovery.icmp import IcmpPingDiscoverer
from scanner.discovery.tcp_sweep import TcpSweepDiscoverer

if TYPE_CHECKING:
    from scanner.core.interfaces import Discoverer
    from scanner.core.models import ScanConfig

__all__ = [
    "IcmpPingDiscoverer",
    "TcpSweepDiscoverer",
    "get_discoverers",
]


def get_discoverers(cfg: ScanConfig) -> list[Discoverer]:
    """Return the ordered active discoverers for this run."""
    sweep = TcpSweepDiscoverer(cfg.ports) if cfg.ports else TcpSweepDiscoverer()
    return [IcmpPingDiscoverer(), sweep]
