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
from rich.markup import escape
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
    return f"[{_TIER_STYLE.get(value, 'white')}]{escape(value)}[/]"


def _cell(value: object) -> str:
    """Markup-escape a host-derived cell before it reaches rich.

    `Table.add_row` renders a `str` cell as console markup, so a device that
    advertises a DHCP/mDNS hostname (or banner-derived vendor/OS string) of
    `[black on black]` or `[/dim]` would otherwise restyle or blank its own row
    in the analyst's report. Everything the scanned host controls goes through
    here; our own literal style tags are written around it.
    """
    return escape("" if value is None else str(value))


def render_result(
    console: Console, result: ScanResult, *, quiet: bool = False, verbose: int = 0
) -> None:
    """Print the final scan summary to `console`.

    Default output is deliberately lean: banner, one stats line, and the host
    table — that's the answer to "what's out there." The adaptive planner's
    audit trail (`_render_plan`) is a debug/verification artifact, not part of
    that core answer, so it stays behind `-v`. Findings are the tool's actual
    deliverable, not clutter, so `_render_findings` stays unconditional
    whenever there are any to show — it already self-gates on empty.
    """
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
            _cell(host.ip),
            _cell(host.best_name),
            _cell(host.mac or ""),
            _cell(host.vendor or ""),
            _cell(host.os_guess or ""),
            _cell(ports),
            _tier(host.confidence.value),
        )
    console.print(table)

    if verbose >= 1:
        _render_plan(console, result)
    _render_findings(console, result)


def _render_plan(console: Console, result: ScanResult) -> None:
    """Show the adaptive planner's account (Go engine + --adaptive only)."""
    plan = result.plan
    if plan is None:
        return
    console.print(
        f"[bold]adaptive plan[/bold]  probes [bold]{plan.probes_sent}[/bold]/"
        f"{plan.probes_planned} sent ([green]{plan.probes_saved} saved[/green])  "
        f"detection risk [bold]{plan.risk_spent}[/bold] of {plan.risk_of_full_scan} full-scan"
    )
    if not plan.verdicts:
        return
    table = Table(title="Device classification", box=SIMPLE_HEAVY, title_justify="left")
    for column in ("Host", "Class", "Conf.", "Stopped by"):
        table.add_column(column, overflow="fold")
    for verdict in plan.verdicts:
        table.add_row(
            _cell(verdict.ip),
            _cell(verdict.device_class),
            f"{verdict.confidence:.3f}",
            _cell(verdict.stopped_by),
        )
    console.print(table)


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
            _cell(host.ip),
            f"[{_SEV_STYLE.get(sev, 'white')}]{escape(sev)}[/]",
            _cell(finding.title),
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
                task,
                description=(
                    f"discovering... {counters['up']} up "
                    f"(last {escape(str(fields.get('ip', '')))})"
                ),
            )
        elif event == "fingerprint":
            progress.update(
                task, description=f"fingerprinting {escape(str(fields.get('ip', '')))}"
            )
        elif event == "done":
            progress.update(task, description="finalizing report")

    with progress:
        yield hook
