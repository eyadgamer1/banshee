"""E4-lite — terminal presentation.

Two pieces, both rich-based:

  * `render_result` — the final summary: a banner, a stats line, a host table, and
    (when present) a findings table. This is the primary, deterministically-tested
    output.
  * `live_status`   — a context manager yielding a progress hook for the engine. It
    drives a transient spinner that narrates discovery/fingerprint events as they
    happen. Disabled (no-op hook) for silent/quiet/non-interactive runs.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from rich.box import SIMPLE_HEAVY
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

if TYPE_CHECKING:
    from rich.console import Console

    from scanner.core.models import ScanResult

ProgressHook = Callable[[str, dict[str, object]], None]

_TIER_STYLE: dict[str, str] = {
    "confirmed": "green",
    "probable": "yellow",
    "potential": "dim",
}
_SEV_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _tier(value: str) -> str:
    return f"[{_TIER_STYLE.get(value, 'white')}]{value}[/]"


def render_result(console: Console, result: ScanResult, *, quiet: bool = False) -> None:
    """Print the final scan summary to `console`."""
    if not quiet:
        console.print(f"[bold yellow]{result.banner}[/bold yellow]")
    console.print(
        f"hosts up [bold]{result.stats.hosts_up}[/bold]  "
        f"services [bold]{result.stats.services_found}[/bold]  "
        f"findings [bold]{result.stats.findings}[/bold]  "
        f"in-scope [bold]{result.stats.targets_in_scope}[/bold]  "
        f"out-of-scope [bold]{result.stats.targets_out_of_scope}[/bold]  "
        f"packets [bold]{result.stats.packets_sent}[/bold]"
    )

    if not result.hosts:
        console.print("[dim](no live hosts)[/dim]")
        return

    table = Table(box=SIMPLE_HEAVY, expand=False, pad_edge=False)
    for column in ("IP", "Name", "MAC", "Vendor", "OS", "Ports", "Conf."):
        table.add_column(column, overflow="fold")
    for host in result.hosts:
        ports = ", ".join(str(p) for p in host.open_ports) or "-"
        table.add_row(
            host.ip,
            host.best_name,
            host.mac or "",
            host.vendor or "",
            host.os_guess or "",
            ports,
            _tier(host.confidence.value),
        )
    console.print(table)

    _render_findings(console, result)


def _render_findings(console: Console, result: ScanResult) -> None:
    rows = [(h, f) for h in result.hosts for f in h.findings]
    if not rows:
        return
    table = Table(title="Findings", box=SIMPLE_HEAVY, title_justify="left")
    for column in ("Host", "Severity", "Title", "Conf."):
        table.add_column(column, overflow="fold")
    for host, finding in rows:
        sev = finding.severity.value
        table.add_row(
            host.ip,
            f"[{_SEV_STYLE.get(sev, 'white')}]{sev}[/]",
            finding.title,
            _tier(finding.confidence.value),
        )
    console.print(table)


@contextlib.contextmanager
def live_status(console: Console, *, enabled: bool) -> Iterator[ProgressHook]:
    """Yield an engine progress hook backed by a transient rich spinner.

    When `enabled` is False (silent/quiet/dry-run/non-tty) the yielded hook is a
    no-op and nothing is drawn, so output stays clean for piping.
    """
    if not enabled:
        def noop(event: str, fields: dict[str, object]) -> None:
            return None

        yield noop
        return

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    )
    task = progress.add_task("starting scan...", total=None)
    counters = {"up": 0}

    def hook(event: str, fields: dict[str, object]) -> None:
        if event == "scope":
            in_scope = fields.get("in_scope", 0)
            progress.update(task, description=f"scope resolved: {in_scope} in-scope")
        elif event == "host":
            counters["up"] += 1
            progress.update(
                task, description=f"discovering... {counters['up']} up (last {fields.get('ip')})"
            )
        elif event == "fingerprint":
            progress.update(task, description=f"fingerprinting {fields.get('ip')}")
        elif event == "done":
            progress.update(task, description="finalizing report")

    with progress:
        yield hook
