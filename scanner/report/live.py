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


# ASCII-only spinner and colours — no block/braille glyphs, so the dashboard
# renders on a legacy cp1252 console without a UnicodeEncodeError.
_SPINNER = "|/-\\"
_STATUS_STYLE = {
    "discovering": "dim cyan",
    "up": "cyan",
    "fingerprinting": "yellow",
    "done": "bold green",
}


def _header_panel(cfg: ScanConfig, frame: str, elapsed: str) -> Panel:
    body = Text(justify="center")
    body.append(f"{frame} scanning", "bold red")
    body.append("    ")
    body.append(
        f"mode={cfg.mode.value}  -T{cfg.timing}  engine={cfg.engine}  "
        f"iface={cfg.iface or 'default'}  elapsed={elapsed}",
        "dim",
    )
    return Panel(
        body,
        title="[bold red]BANSHEE[/bold red] [dim]. live scan[/dim]",
        subtitle="[dim italic]she sees everything you left exposed[/dim italic]",
        border_style="red",
    )


def _host_table(hosts: dict[str, dict[str, object]]) -> Table:
    table = Table(box=SIMPLE_HEAVY, expand=True, show_header=True, header_style="bold")
    table.add_column("IP", style="bold cyan", no_wrap=True)
    table.add_column("Name", overflow="fold")
    table.add_column("OS")
    table.add_column("Ports", style="green")
    table.add_column("Findings", justify="right")
    table.add_column("Status", no_wrap=True)
    for ip, h in sorted(hosts.items()):
        status = str(h.get("status", "discovering"))
        style = _STATUS_STYLE.get(status, "white")
        fnd = int(str(h.get("findings", 0) or 0))
        fnd_txt = f"[red]{fnd}[/red]" if fnd else "[dim]0[/dim]"
        table.add_row(
            ip, str(h.get("name", "")), str(h.get("os", "")),
            str(h.get("ports", "")), fnd_txt, f"[{style}]{status}[/]",
        )
    return table


def _stats_bar(stats: dict[str, object], frame: str) -> Text:
    bar = Text(justify="center")
    bar.append(f"{frame} ", "red")
    bar.append("hosts up ", "dim")
    bar.append(f"{stats.get('up', 0)}    ", "bold cyan")
    bar.append("services ", "dim")
    bar.append(f"{stats.get('services', 0)}    ", "bold green")
    bar.append("findings ", "dim")
    bar.append(f"{stats.get('findings', 0)}    ", "bold red")
    bar.append("elapsed ", "dim")
    bar.append(str(stats.get("elapsed", "0s")), "bold")
    return bar


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
    def _refresh() -> None:
        elapsed = f"{time.time() - t_start:.0f}s"
        stats["elapsed"] = elapsed
        frame = _SPINNER[int((time.time() - t_start) * 8) % len(_SPINNER)]
        layout["header"].update(_header_panel(cfg, frame, elapsed))
        layout["hosts"].update(
            Panel(_host_table(hosts), title=f"Hosts ({len(hosts)})", border_style="cyan")
        )
        layout["stats"].update(Panel(_stats_bar(stats, frame), border_style="dim"))

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
