"""Fingerprint module — enriches hosts with identity/service data (B1–B13).

Integration contract consumed by the CLI: `get_fingerprinters(cfg)` returns the
Fingerprinter instances enabled for this run.

Wave 0 stub — agent-fingerprint (P1-2) replaces this with B1 oui, B2 dhcp,
B6 name-resolve.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.interfaces import Fingerprinter
    from scanner.core.models import ScanConfig


def get_fingerprinters(cfg: ScanConfig) -> list[Fingerprinter]:
    """Return ordered fingerprinters for this run. Empty until P1-2 lands."""
    return []
