"""Report module — output writers (E3) and live terminal display (E4).

Integration contract consumed by the CLI:
  - `get_writers()` -> {format_name: ReportWriter}
  - `render_result(console, result)` -> human-readable terminal summary

Wave 0 ships a minimal JSON writer + plain summary so the CLI runs end-to-end.
agent-report (P1-3) replaces this with txt/json/xml/html/csv writers and the
rich live dashboard.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console

    from scanner.core.interfaces import ReportWriter
    from scanner.core.models import ScanResult


class _JsonWriter:
    """Minimal JSON writer (Wave 0). Full E3 suite lands in P1-3."""

    format_name = "json"

    def write(self, result: ScanResult, path: Path) -> None:
        Path(path).write_text(result.model_dump_json(indent=2), encoding="utf-8")


def get_writers() -> dict[str, ReportWriter]:
    return {"json": _JsonWriter()}


def render_result(console: Console, result: ScanResult) -> None:
    """Plain terminal summary (Wave 0). Rich live table lands in P1-3."""
    console.print(f"[bold]{result.banner}[/bold]")
    console.print(
        f"hosts up: {result.stats.hosts_up}  "
        f"in-scope: {result.stats.targets_in_scope}  "
        f"out-of-scope: {result.stats.targets_out_of_scope}  "
        f"packets: {result.stats.packets_sent}"
    )
    for host in result.up_hosts:
        ports = ", ".join(str(p) for p in host.open_ports) or "-"
        console.print(f"  {host.ip:<16} {host.best_name:<24} ports[{ports}]")
