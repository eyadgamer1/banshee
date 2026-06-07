"""Report module — output writers (E3) and live terminal display (E4).

Integration contract consumed by the CLI:
  - `get_writers()` -> {format_name: ReportWriter}  (txt, json, xml, html, csv)
  - `render_result(console, result)` -> final human-readable summary
  - `live_status(console, enabled=...)` -> context manager yielding a progress hook

P1-3 replaces the Wave-0 stub with the full E3 writer suite and the E4-lite
rich display (spinner during the scan, table + findings afterwards).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scanner.report.dashboard import live_status, render_result
from scanner.report.writers import all_writers

if TYPE_CHECKING:
    from scanner.core.interfaces import ReportWriter

__all__ = ["get_writers", "live_status", "render_result"]


def get_writers() -> dict[str, ReportWriter]:
    """Return every available report writer keyed by format name."""
    return all_writers()
