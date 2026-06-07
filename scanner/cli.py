"""BANSHEE CLI — `banshee <targets> [flags]`. Typer + rich, nmap-style UX.

Two independent dials, never conflated:
  VERBOSITY  (how chatty):   -q / --silent / -v / --debug / --no-color
  INTENSITY  (how loud):     --mode / -T 0..5 / --rate / --max-detect-risk

The CLI resolves flags into a ScanConfig, builds the ScopeGuard (E5) and
StealthBudget (D3), wires concrete discoverers/fingerprinters/writers into the
ScanEngine (A1), runs it, applies the confidence policy (C7), and emits output.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from scanner import __version__, discovery, fingerprint, report, risk
from scanner.core.budget import StealthBudget
from scanner.core.engine import ScanEngine
from scanner.core.models import ScanConfig, ScanMode
from scanner.core.scope import AuditLog, ScopeGuard, ScopeViolationError
from scanner.correlate import build_attack_graph, build_segment_map
from scanner.intel import enrich_result, prioritize_result
from scanner.llm import generate_report, run_react_loop
from scanner.plugins import run_plugins
from scanner.ui import print_banner

app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
    help=(
        "[bold red]BANSHEE[/bold red] — passive-first network discovery, "
        "fingerprinting & risk reporting. [dim]No exploitation. Ever.[/dim]"
    ),
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
        Console().print(f"banshee {__version__}")
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
        int | None,
        typer.Option("--timeout", help="probe timeout ms (default from -T)",
                     rich_help_panel=_INTENS),
    ] = None,
    retries: Annotated[
        int | None,
        typer.Option("--retries", help="probe retries (default from -T)",
                     rich_help_panel=_INTENS),
    ] = None,
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
        bool,
        typer.Option("--enrich", help="external intel enrichment (data leaves host)",
                     rich_help_panel=_TOGGLES),
    ] = False,
    do_ssvc: Annotated[
        bool,
        typer.Option("--ssvc", help="SSVC priority tags on findings (local)",
                     rich_help_panel=_TOGGLES),
    ] = False,
    do_agentic: Annotated[
        bool,
        typer.Option("--agentic", help="ReAct LLM analysis via local Ollama",
                     rich_help_panel=_TOGGLES),
    ] = False,
    do_plugins: Annotated[
        bool,
        typer.Option("--plugins", help="apply YAML plugin rules from config/plugins/",
                     rich_help_panel=_TOGGLES),
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
    # Verbosity dial → log level. --debug wins; --silent silences the library logs.
    if debug:
        log_level = logging.DEBUG
    elif silent:
        log_level = logging.CRITICAL
    elif verbose >= 2:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s %(name)s: %(message)s")

    console = Console(no_color=no_color, stderr=False)
    print_banner(console, quiet=quiet, silent=silent)

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

    if not silent and not quiet:
        console.print(f"[bold yellow][!] {guard.banner}[/bold yellow]")
        console.print(f"[dim]mode={mode.value} -T{timing} fingerprint={do_fingerprint}[/dim]")

    budget = StealthBudget.from_config(cfg)
    live_enabled = not silent and not quiet and not dry_run and console.is_terminal
    from scanner.report.live import live_dashboard
    with live_dashboard(console, cfg, enabled=live_enabled) as progress_hook:
        engine = ScanEngine(
            scope=guard,
            budget=budget,
            discoverers=discovery.get_discoverers(cfg),
            fingerprinters=fingerprint.get_fingerprinters(cfg) if do_fingerprint else [],
            progress=progress_hook,
        )
        try:
            result = asyncio.run(engine.run(cfg))
        except ScopeViolationError as exc:
            console.print(f"[red]scope violation:[/red] {exc}")
            raise typer.Exit(code=3) from exc

    risk.tier_result(result)

    # P3 — attack-path graph (always runs; attaches pivot findings)
    attack_graph = build_attack_graph(result)
    if not silent and attack_graph.edges:  # noqa: SIM102
        n_pivots = len(attack_graph.pivot_targets())
        console.print(
            f"[dim]C1 attack graph: {len(attack_graph.edges)} edges, {n_pivots} pivots[/dim]"
        )

    # P4 — segment map (C2): group hosts by subnet, flag bridge hosts
    seg_map = build_segment_map(result)
    if not silent and seg_map.segments:
        bridges = len(seg_map.bridges)
        console.print(
            f"[dim]C2 segment map: {len(seg_map.segments)} segments, {bridges} bridge hosts[/dim]"
        )

    # P3 — YAML plugin rules
    if do_plugins:
        n_plugin = run_plugins(result)
        if not silent:
            console.print(f"[dim]E1 plugins: {n_plugin} findings added[/dim]")

    # P3 — external intel enrichment (data leaves host)
    if do_enrich:
        console.print(
            "[bold yellow][!] --enrich: CVE IDs will be sent to FIRST.org and CISA. "
            "Data leaves host.[/bold yellow]"
        )
        asyncio.run(enrich_result(result))

    # P3 — SSVC prioritization (local, always safe)
    if do_ssvc:
        priorities = prioritize_result(result)
        if not silent:
            console.print(f"[dim]C5 SSVC: {len(priorities)} findings tagged[/dim]")

    # P3 — agentic ReAct analysis + LLM report
    if do_agentic:
        if not silent:
            console.print("[dim]D1 ReAct: running agentic analysis via Ollama...[/dim]")
        analysis = asyncio.run(run_react_loop(result))
        if not silent:
            console.print(analysis)
        llm_summary = asyncio.run(generate_report(result))
        if not silent:
            console.print("\n[bold]AI Executive Summary[/bold]\n" + llm_summary)

    if not silent:
        report.render_result(console, result, quiet=quiet)

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
