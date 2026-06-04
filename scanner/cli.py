"""CLI — `pps <targets> [flags]`. Typer + rich, nmap-style UX.

Two independent dials, never conflated:
  VERBOSITY  (how chatty):   -q / --silent / -v / --debug / --no-color
  INTENSITY  (how loud):     --mode / -T 0..5 / --rate / --max-detect-risk

The CLI resolves flags into a ScanConfig, builds the ScopeGuard (E5) and
StealthBudget (D3), wires concrete discoverers/fingerprinters/writers into the
ScanEngine (A1), runs it, applies the confidence policy (C7), and emits output.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from scanner import __version__, discovery, fingerprint, report, risk
from scanner.core.budget import StealthBudget
from scanner.core.engine import ScanEngine
from scanner.core.models import ScanConfig, ScanMode
from scanner.core.scope import AuditLog, ScopeGuard, ScopeViolationError

app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
    help="[bold]pps[/bold] — passive-first network discovery, enumeration & reporting. "
    "[dim]Scanning only; no exploitation.[/dim]",
)

# rich help panel group labels
_TARGETS = "Targets & Input"
_VERB = "Verbosity"
_INTENS = "Intensity"
_OUTPUT = "Output Files"
_TOGGLES = "Toggles"
_SAFETY = "Safety"
_MAINT = "Maintenance"


def _version_cb(value: bool) -> None:
    if value:
        Console().print(f"pps {__version__}")
        raise typer.Exit()


@app.command()
def scan(  # noqa: PLR0913 - a CLI surface is inherently wide
    targets: Annotated[
        list[str] | None,
        typer.Argument(
            help="IP / CIDR / range / hostname (e.g. 192.168.1.0/24 10.0.0.5-20 host.lan)",
            show_default=False,
            rich_help_panel=_TARGETS,
        ),
    ] = None,
    iface: Annotated[
        str | None,
        typer.Option("--iface", "-i", help="capture interface", rich_help_panel=_TARGETS),
    ] = None,
    pcap: Annotated[
        str | None,
        typer.Option("--pcap", help="read from pcap instead of live", rich_help_panel=_TARGETS),
    ] = None,
    # --- verbosity dial ---
    verbose: Annotated[
        int, typer.Option("--verbose", "-v", count=True, help="-v/-vv/-vvv", rich_help_panel=_VERB)
    ] = 0,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="results only", rich_help_panel=_VERB)
    ] = False,
    silent: Annotated[
        bool,
        typer.Option("--silent", help="no terminal output (files only)", rich_help_panel=_VERB),
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", help="debug tracing", rich_help_panel=_VERB)
    ] = False,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="disable ANSI color", rich_help_panel=_VERB)
    ] = False,
    # --- intensity dial ---
    mode: Annotated[
        ScanMode,
        typer.Option("--mode", "-m", help="scan intensity", rich_help_panel=_INTENS),
    ] = ScanMode.PASSIVE,
    timing: Annotated[
        int,
        typer.Option(
            "--timing", "-T", min=0, max=5, help="timing template 0-5", rich_help_panel=_INTENS
        ),
    ] = 3,
    rate: Annotated[
        int | None, typer.Option("--rate", help="max packets/sec", rich_help_panel=_INTENS)
    ] = None,
    timeout: Annotated[
        int, typer.Option("--timeout", help="probe timeout (ms)", rich_help_panel=_INTENS)
    ] = 3000,
    retries: Annotated[
        int, typer.Option("--retries", help="probe retries", rich_help_panel=_INTENS)
    ] = 1,
    threads: Annotated[
        int | None, typer.Option("--threads", help="max concurrency", rich_help_panel=_INTENS)
    ] = None,
    max_detect_risk: Annotated[
        int | None,
        typer.Option("--max-detect-risk", help="0=passive..9=full", rich_help_panel=_INTENS),
    ] = None,
    # --- output files ---
    out_txt: Annotated[
        str | None, typer.Option("--txt", help="write text report", rich_help_panel=_OUTPUT)
    ] = None,
    out_json: Annotated[
        str | None, typer.Option("--json", help="write JSON report", rich_help_panel=_OUTPUT)
    ] = None,
    out_xml: Annotated[
        str | None, typer.Option("--xml", help="write XML report", rich_help_panel=_OUTPUT)
    ] = None,
    out_html: Annotated[
        str | None, typer.Option("--html", help="write HTML report", rich_help_panel=_OUTPUT)
    ] = None,
    out_csv: Annotated[
        str | None, typer.Option("--csv", help="write CSV report", rich_help_panel=_OUTPUT)
    ] = None,
    out_sarif: Annotated[
        str | None, typer.Option("--sarif", help="write SARIF report", rich_help_panel=_OUTPUT)
    ] = None,
    out_all: Annotated[
        str | None,
        typer.Option("--all", "-A", help="write all formats to BASE.*", rich_help_panel=_OUTPUT),
    ] = None,
    # --- toggles ---
    do_fingerprint: Annotated[
        bool,
        typer.Option(
            "--fingerprint/--no-fingerprint", help="identity probes", rich_help_panel=_TOGGLES
        ),
    ] = True,
    do_names: Annotated[
        bool, typer.Option("--names/--no-names", help="name resolution", rich_help_panel=_TOGGLES)
    ] = True,
    do_classify: Annotated[
        bool, typer.Option("--classify", help="device classification", rich_help_panel=_TOGGLES)
    ] = False,
    do_enrich: Annotated[
        bool, typer.Option("--enrich", help="external intel enrichment", rich_help_panel=_TOGGLES)
    ] = False,
    # --- safety ---
    scope_file: Annotated[
        str, typer.Option("--scope", help="scope allowlist file", rich_help_panel=_SAFETY)
    ] = "config/scope.yaml",
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="plan only; send zero packets", rich_help_panel=_SAFETY),
    ] = False,
    audit_log: Annotated[
        str | None,
        typer.Option("--audit-log", help="append JSONL audit trail", rich_help_panel=_SAFETY),
    ] = None,
    # --- maintenance ---
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_cb,
            is_eager=True,
            help="show version",
            rich_help_panel=_MAINT,
        ),
    ] = False,
) -> None:
    """Discover, fingerprint and report on in-scope network assets."""
    console = Console(no_color=no_color, stderr=False)

    if not targets:
        console.print("[red]error:[/red] no targets given. See [bold]pps --help[/bold].")
        raise typer.Exit(code=2)

    if out_all:
        out_txt = out_txt or f"{out_all}.txt"
        out_json = out_json or f"{out_all}.json"
        out_xml = out_xml or f"{out_all}.xml"
        out_html = out_html or f"{out_all}.html"
        out_csv = out_csv or f"{out_all}.csv"
        out_sarif = out_sarif or f"{out_all}.sarif"

    cfg = ScanConfig(
        targets=targets,
        iface=iface,
        pcap=pcap,
        mode=mode,
        timing=timing,
        rate=rate,
        timeout_ms=timeout,
        retries=retries,
        threads=threads,
        max_detect_risk=max_detect_risk,
        fingerprint=do_fingerprint,
        names=do_names,
        classify=do_classify,
        enrich=do_enrich,
        scope_file=scope_file,
        dry_run=dry_run,
        audit_log=audit_log,
        out_txt=out_txt,
        out_json=out_json,
        out_xml=out_xml,
        out_html=out_html,
        out_csv=out_csv,
        out_sarif=out_sarif,
        verbosity=-1 if quiet else verbose,
        silent=silent,
        no_color=no_color,
    )

    try:
        audit = AuditLog(cfg.audit_log)
        guard = ScopeGuard.from_file(cfg.scope_file, audit=audit)
    except FileNotFoundError:
        console.print(f"[red]error:[/red] scope file not found: {cfg.scope_file}")
        raise typer.Exit(code=2) from None

    if not silent:
        console.print(f"[bold yellow][!] {guard.banner}[/bold yellow]")
        console.print(f"[dim]mode={mode.value} -T{timing} fingerprint={do_fingerprint}[/dim]")

    budget = StealthBudget.from_config(cfg)
    engine = ScanEngine(
        scope=guard,
        budget=budget,
        discoverers=discovery.get_discoverers(cfg),
        fingerprinters=fingerprint.get_fingerprinters(cfg) if do_fingerprint else [],
    )

    try:
        result = asyncio.run(engine.run(cfg))
    except ScopeViolationError as exc:
        console.print(f"[red]scope violation:[/red] {exc}")
        raise typer.Exit(code=3) from exc

    risk.tier_result(result)

    if not silent:
        report.render_result(console, result)

    writers = report.get_writers()
    targets_map = {
        "txt": cfg.out_txt,
        "json": cfg.out_json,
        "xml": cfg.out_xml,
        "html": cfg.out_html,
        "csv": cfg.out_csv,
        "sarif": cfg.out_sarif,
    }
    for fmt, path in targets_map.items():
        if path and fmt in writers:
            writers[fmt].write(result, Path(path))
            if not silent:
                console.print(f"[green]wrote[/green] {fmt} -> {path}")
        elif path:
            console.print(f"[yellow]skip[/yellow] {fmt}: writer not available yet")


if __name__ == "__main__":
    app()
