"""E4 — Full live dashboard.

Replaces the simple spinner (E4-lite) with a rich Live layout that shows:
  - Header: mode, timing, interface
  - Running host table (updates as hosts are discovered/fingerprinted)
  - Stats bar: hosts up / services / findings / packets

Activated automatically when the terminal is interactive and --silent/--quiet
are not set. Falls back to the E4-lite spinner when Live is unavailable.

Usage:
    with live_dashboard(console, cfg, enabled=True) as hook:
        result = await engine.run(cfg)
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Generator
from typing import TYPE_CHECKING

from rich.box import SIMPLE_HEAVY
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from rich.console import Console

    from scanner.core.models import ScanConfig, ScanResult
    from scanner.report.dashboard import ProgressHook


def _header_panel(cfg: ScanConfig) -> Panel:
    mode = cfg.mode.value
    timing = cfg.timing
    iface = cfg.iface or "default"
    content = Text(f"mode={mode}  -T{timing}  iface={iface}", justify="center")
    title = "[bold red]BANSHEE[/bold red] [dim]live scan[/dim]"
    return Panel(content, title=title, border_style="red")


def _host_table(hosts: dict[str, dict[str, object]]) -> Table:
    table = Table(box=SIMPLE_HEAVY, expand=True, show_header=True)
    for col in ("IP", "Name", "OS", "Ports", "Findings", "Status"):
        table.add_column(col, overflow="fold")
    for ip, h in sorted(hosts.items()):
        ports = str(h.get("ports", ""))
        findings = str(h.get("findings", 0))
        status = str(h.get("status", "discovering"))
        style = "green" if status == "done" else "yellow"
        table.add_row(
            ip, str(h.get("name", "")), str(h.get("os", "")), ports, findings,
            f"[{style}]{status}[/]",
        )
    return table


def _stats_bar(stats: dict[str, object]) -> Text:
    return Text(
        f"hosts up: {stats.get('up', 0)}  "
        f"services: {stats.get('services', 0)}  "
        f"findings: {stats.get('findings', 0)}  "
        f"elapsed: {stats.get('elapsed', '0s')}",
        justify="center",
    )


@contextlib.contextmanager
def live_dashboard(
    console: Console,
    cfg: ScanConfig,
    *,
    enabled: bool,
) -> Generator[ProgressHook, None, None]:
    """Full live dashboard context manager. Yields a ProgressHook."""
    if not enabled:
        # Reuse the lite noop
        def noop(event: str, fields: dict[str, object]) -> None:
            return None
        yield noop
        return

    hosts: dict[str, dict[str, object]] = {}
    stats: dict[str, object] = {"up": 0, "services": 0, "findings": 0}
    t_start = time.time()

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="hosts"),
        Layout(name="stats", size=3),
    )
    layout["header"].update(_header_panel(cfg))

    def _refresh() -> None:
        elapsed = f"{time.time() - t_start:.0f}s"
        stats["elapsed"] = elapsed
        layout["hosts"].update(Panel(_host_table(hosts), title="Hosts", border_style="dim"))
        layout["stats"].update(Panel(_stats_bar(stats), border_style="dim"))

    def hook(event: str, fields: dict[str, object]) -> None:
        ip = str(fields.get("ip", ""))
        if event == "host":
            if ip not in hosts:
                hosts[ip] = {
                    "status": "discovering", "name": "", "os": "", "ports": "", "findings": 0,
                }
            hosts[ip]["status"] = "up"
            stats["up"] = len(hosts)
        elif event == "fingerprint":
            if ip in hosts:
                hosts[ip]["status"] = "fingerprinting"
                if fields.get("os"):
                    hosts[ip]["os"] = str(fields["os"])
                if fields.get("ports"):
                    hosts[ip]["ports"] = str(fields["ports"])
        elif event == "done":
            if ip in hosts:
                hosts[ip]["status"] = "done"
                hosts[ip]["findings"] = int(str(fields.get("findings", 0)))
                svc = int(str(stats.get("services", 0))) + int(str(fields.get("services", 0)))
                fnd = int(str(stats.get("findings", 0))) + int(str(fields.get("findings", 0)))
                stats["services"] = svc
                stats["findings"] = fnd
        _refresh()

    _refresh()
    with Live(layout, console=console, refresh_per_second=4, screen=False):
        yield hook


def render_final(console: Console, result: ScanResult) -> None:
    """Print post-scan summary (delegates to dashboard.render_result)."""
    from scanner.report.dashboard import render_result
    render_result(console, result)
