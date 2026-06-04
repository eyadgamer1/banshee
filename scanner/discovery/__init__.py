"""Discovery module — finds live hosts among in-scope targets (A2–A5).

Integration contract consumed by the CLI: `get_discoverers(cfg)` returns the
Discoverer instances appropriate for the requested scan mode.

Wave 0 stub — agent-discovery (P1-1) replaces this with the A3 ping sweep.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.interfaces import Discoverer
    from scanner.core.models import ScanConfig


def get_discoverers(cfg: ScanConfig) -> list[Discoverer]:
    """Return ordered discoverers for this run. Empty until P1-1 lands."""
    return []
