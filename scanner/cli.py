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
import ipaddress
import logging
import re
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console

from scanner import __version__, discovery, fingerprint, report, risk
from scanner.core.budget import StealthBudget
from scanner.core.engine import ScanEngine, TargetTooLargeError
from scanner.core.models import ScanConfig, ScanMode, ScanResult
from scanner.core.scope import AuditLog, ScopeGuard, ScopeViolationError
from scanner.correlate import build_attack_graph, build_segment_map, score_deception
from scanner.engine_go import resolve_engine, run_go_engine
from scanner.engine_install import EngineInstallError, install_engine
from scanner.intel import enrich_result, prioritize_result
from scanner.llm import generate_report, run_react_loop
from scanner.plugins import run_plugins
from scanner.report.diff import compute_diff, render_diff
from scanner.store import RogueDetector, ScanStore
from scanner.ui import print_banner

# Only digits and IP/CIDR/range punctuation — a token that looks like an address.
_NETWORKISH = re.compile(r"^[0-9./:\-]+$")
# A plausible DNS hostname: valid label chars, and at least one alphanumeric so a
# string of punctuation ("@@@", "...") is not mistaken for a name.
_HOSTNAME = re.compile(r"^(?=.*[A-Za-z0-9])[A-Za-z0-9._-]+$")


def _target_is_valid(token: str) -> bool:
    """True if a target token is usable: a valid IP (v4/v6), CIDR, last-octet or
    full range, or a plausible hostname. A token that looks like an address (only
    digits and network punctuation) but does not parse — ``999.999.999.999``,
    ``10.0.0.0/99``, ``10.0.0.5-999`` — and junk like ``@@@`` are rejected here,
    so a typo fails fast with a clear message instead of silently resolving to
    nothing. A well-formed but unresolvable hostname still passes; the resolver
    decides, and the run reports that no host responded."""
    token = token.strip()
    if not token:
        return False
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        pass
    if "/" in token:  # CIDR (v4 or v6)
        try:
            ipaddress.ip_network(token, strict=False)
            return True
        except ValueError:
            return False
    if _NETWORKISH.match(token):  # address-shaped: must be a valid range, else bad
        if "-" in token:
            left, right = token.rsplit("-", 1)
            try:
                ipaddress.ip_address(left)
                if "." in right or ":" in right:
                    ipaddress.ip_address(right)
                else:
                    ipaddress.ip_address(f"{left.rsplit('.', 1)[0]}.{right}")
                return True
            except ValueError:
                return False
        return False
    return bool(_HOSTNAME.match(token))


def parse_ports(spec: str) -> list[int]:
    """Parse an nmap-style port spec: "22,80,443" or "1-1024" or a mix of both.

    Raises ValueError on anything unparseable so the CLI can refuse the run
    rather than silently scanning a different port set than the operator asked for.
    """
    ports: list[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ValueError(f"reversed port range: {chunk}")
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(chunk))
    if not ports:
        raise ValueError("no ports given")
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"port out of range: {p}")
    return sorted(set(ports))

async def _run_pipeline(
    cfg: ScanConfig,
    guard: ScopeGuard,
    budget: StealthBudget,
    console: Console,
    live_enabled: bool,
    scope_path: str,
) -> ScanResult:
    """Run the scan and every post-scan analysis pass in one event loop.

    Ordering is load-bearing: `risk.tier_result` is the final authority on
    confidence and is what caps LLM-inferred findings at POTENTIAL, so it must
    run *after* every pass that can add or mutate a finding — plugins, intel,
    rogue detection and the agentic stage all do.
    """
    silent = cfg.silent
    with report.live_dashboard(console, cfg, enabled=live_enabled) as progress_hook:
        if cfg.engine == "go":
            # Go is the hands: fast, low-memory active discovery/probing. It loads
            # and enforces the same scope file itself. Passive/analysis/report
            # stages below stay Python regardless of engine.
            result = await run_go_engine(cfg, guard, scope_path)
        else:
            engine = ScanEngine(
                scope=guard,
                budget=budget,
                discoverers=discovery.get_discoverers(cfg),
                fingerprinters=fingerprint.get_fingerprinters(cfg) if cfg.fingerprint else [],
                progress=progress_hook,
            )
            result = await engine.run(cfg)

    # C1 — attack-path graph (always runs; attaches pivot findings)
    attack_graph = build_attack_graph(result)
    if not silent and attack_graph.edges:
        n_pivots = len(attack_graph.pivot_targets())
        console.print(
            f"[dim]C1 attack graph: {len(attack_graph.edges)} edges, {n_pivots} pivots[/dim]"
        )

    # C2 — segment map: group hosts by subnet, flag bridge hosts
    seg_map = build_segment_map(result)
    if not silent and seg_map.segments:
        console.print(
            f"[dim]C2 segment map: {len(seg_map.segments)} segments, "
            f"{len(seg_map.bridges)} bridge hosts[/dim]"
        )

    # E1 — YAML plugin rules
    if cfg.plugins:
        n_plugin = run_plugins(result)
        if not silent:
            console.print(f"[dim]E1 plugins: {n_plugin} findings added[/dim]")

    # C8 — deception/honeypot signals (local, zero packets). Runs before
    # tier_result so its POTENTIAL findings pass through the confidence policy.
    if cfg.deception:
        n_decoy = score_deception(result)
        if not silent:
            console.print(f"[dim]C8 deception: {n_decoy} host(s) flagged (POTENTIAL)[/dim]")

    # C4 — external intel enrichment (data leaves host)
    if cfg.enrich:
        await enrich_result(result)

    # C5 — SSVC prioritization (local, always safe)
    if cfg.ssvc:
        priorities = prioritize_result(result)
        if not silent:
            console.print(f"[dim]C5 SSVC: {len(priorities)} findings tagged[/dim]")

    # D1/D4 — agentic ReAct analysis + LLM report
    if cfg.agentic:
        if not silent:
            console.print("[dim]D1 ReAct: running agentic analysis via Ollama...[/dim]")
        analysis = await run_react_loop(result)
        llm_summary = await generate_report(result)
        if not silent:
            console.print(analysis)
            console.print("\n[bold]AI Executive Summary[/bold]\n" + llm_summary)

    # A6/E2 — persistence and rogue detection. The baseline must be read before
    # this run is written, or every MAC in the run would match itself.
    async with AsyncExitStack() as stack:
        store = await stack.enter_async_context(ScanStore(cfg.db)) if cfg.db else None
        if store is not None and not cfg.baseline:
            known_macs = await store.get_known_macs()
            rogues = RogueDetector().check(result, known_macs)
            if not silent and rogues:
                console.print(f"[bold red]E2 rogue: {len(rogues)} unknown MAC(s)[/bold red]")

        risk.tier_result(result)
        result.stats.findings = sum(len(h.findings) for h in result.hosts)

        if store is not None:
            run_id = await store.save_result(result)
            if not silent:
                console.print(f"[green]A6 stored[/green] run #{run_id} -> {cfg.db}")

    return result


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
_ENGINE = "Engine"

_ENGINE_CHOICES = ("python", "go", "auto")

# The default scope path is relative to the working directory. When BANSHEE is
# installed as a tool (uv tool / pipx / pip) and run from an arbitrary directory,
# that file will not exist — so we fall back to a copy shipped inside the package.
_DEFAULT_SCOPE_FILE = "config/scope.yaml"


def _resolve_scope_file(scope_file: str, console: Console, *, quiet: bool) -> str:
    """Return a usable scope path.

    If the given file exists, use it. If it does not and the user did not override
    ``--scope`` (still the default), fall back to the packaged default scope so an
    installed ``banshee`` works from any directory. An explicit missing path is
    left untouched, so it fails loudly with the value the user actually typed.
    """
    if Path(scope_file).exists():
        return scope_file
    if scope_file != _DEFAULT_SCOPE_FILE:
        return scope_file
    from importlib.resources import files

    packaged = files("scanner").joinpath("data", "default_scope.yaml")
    if not packaged.is_file():
        return scope_file
    if not quiet:
        console.print(
            "[yellow]open scope: every target is allowed (nmap-style). "
            "You are responsible for authorization on every target. "
            "Pass --scope to restrict to a lab range.[/yellow]"
        )
    return str(packaged)


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
    ports: Annotated[
        str | None,
        typer.Option(
            "--ports",
            "-p",
            help="ports to probe, e.g. 22,80,443 or 1-1024 (default: common set)",
            rich_help_panel=_TARGETS,
        ),
    ] = None,
    sniff_timeout: Annotated[
        float,
        typer.Option(
            "--sniff-timeout",
            min=0.0,
            help="seconds the passive sniffer listens before reporting",
            rich_help_panel=_TARGETS,
        ),
    ] = 10.0,
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
    ] = ScanMode.NORMAL,
    timing: Annotated[
        int,
        typer.Option(
            "--timing", "-T", min=0, max=5, help="timing template 0-5", rich_help_panel=_INTENS
        ),
    ] = 3,
    rate: Annotated[
        int | None,
        typer.Option("--rate", min=0, help="max packets/sec (0 = template default)",
                     rich_help_panel=_INTENS),
    ] = None,
    timeout: Annotated[
        int | None,
        typer.Option("--timeout", min=1, help="probe timeout ms (default from -T)",
                     rich_help_panel=_INTENS),
    ] = None,
    retries: Annotated[
        int | None,
        typer.Option("--retries", min=0, help="probe retries (default from -T)",
                     rich_help_panel=_INTENS),
    ] = None,
    threads: Annotated[
        int | None,
        typer.Option("--threads", min=1, help="max concurrency", rich_help_panel=_INTENS),
    ] = None,
    max_detect_risk: Annotated[
        int | None,
        typer.Option("--max-detect-risk", min=0, max=10, help="0=passive..10=full",
                     rich_help_panel=_INTENS),
    ] = None,
    # --- engine ---
    engine: Annotated[
        str,
        typer.Option(
            "--engine",
            help="active-scan engine: auto (default: Go if present, else fetched "
            "automatically on first use, else Python), python (force in-process), "
            "or go (force the fast core).",
            rich_help_panel=_ENGINE,
        ),
    ] = "auto",
    adaptive: Annotated[
        bool,
        typer.Option(
            "--adaptive",
            help="Go engine: pick probes by info-gain/risk, stop early (needs --engine go)",
            rich_help_panel=_ENGINE,
        ),
    ] = False,
    udp: Annotated[
        bool,
        typer.Option(
            "--udp",
            help="Go engine: UDP scan; silent ports report open|filtered (needs --engine go)",
            rich_help_panel=_ENGINE,
        ),
    ] = False,
    service_scan: Annotated[
        bool,
        typer.Option(
            "--service-scan",
            "-sV",
            help="Go engine: identify service product/version from banners (needs --engine go)",
            rich_help_panel=_ENGINE,
        ),
    ] = False,
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
        bool,
        typer.Option(
            "--classify/--no-classify",
            help="device classification (local, zero packets)",
            rich_help_panel=_TOGGLES,
        ),
    ] = True,
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
    do_deception: Annotated[
        bool,
        typer.Option("--deception", help="flag possible honeypot/decoy hosts (local, 0 packets)",
                     rich_help_panel=_TOGGLES),
    ] = False,
    # --- persistence ---
    db: Annotated[
        str | None,
        typer.Option(
            "--db",
            help="SQLite path — persist this run and compare MACs to the baseline",
            rich_help_panel=_OUTPUT,
        ),
    ] = None,
    baseline: Annotated[
        bool,
        typer.Option(
            "--baseline",
            help="seed the MAC baseline from this run without raising rogue findings",
            rich_help_panel=_OUTPUT,
        ),
    ] = False,
    # --- safety ---
    scope_file: Annotated[
        str, typer.Option("--scope", help="scope allowlist file", rich_help_panel=_SAFETY)
    ] = _DEFAULT_SCOPE_FILE,
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
        console.print("[red]error:[/red] no targets given. See [bold]banshee --help[/bold].")
        raise typer.Exit(code=2)

    if engine not in _ENGINE_CHOICES:
        choices = ", ".join(_ENGINE_CHOICES)
        console.print(f"[red]error:[/red] unknown --engine {engine!r}; choose from {choices}")
        raise typer.Exit(code=2)
    if mode == ScanMode.PASSIVE:
        # Passive capture is scapy-only; the Go engine has no passive path.
        engine = "python"
    else:
        # The Python engine handles plain scans, so only fetch Go on demand — when a
        # Go-only feature needs it. Otherwise 'auto' uses Go if already present, else
        # Python, with no surprise download on an ordinary scan.
        needs_go = adaptive or udp or service_scan
        engine = resolve_engine(engine, provision=needs_go, console=console)
    if adaptive and engine != "go":
        console.print(
            "[red]error:[/red] --adaptive needs the Go engine. Run "
            "`banshee install-engine` to download it, or build it and pass --engine go."
        )
        raise typer.Exit(code=2)
    if udp and engine != "go":
        console.print(
            "[red]error:[/red] --udp needs the Go engine. Run "
            "`banshee install-engine` to download it, or build it and pass --engine go."
        )
        raise typer.Exit(code=2)
    if udp and adaptive:
        console.print(
            "[red]error:[/red] --udp and --adaptive are mutually exclusive "
            "(the adaptive planner is TCP-only)"
        )
        raise typer.Exit(code=2)
    if service_scan and engine != "go":
        console.print(
            "[red]error:[/red] -sV/--service-scan needs the Go engine. Run "
            "`banshee install-engine` to download it, or build it and pass --engine go."
        )
        raise typer.Exit(code=2)
    if service_scan and udp:
        console.print(
            "[red]error:[/red] -sV/--service-scan probes TCP service banners and does not "
            "apply to a --udp sweep"
        )
        raise typer.Exit(code=2)

    if out_all:
        out_txt = out_txt or f"{out_all}.txt"
        out_json = out_json or f"{out_all}.json"
        out_xml = out_xml or f"{out_all}.xml"
        out_html = out_html or f"{out_all}.html"
        out_csv = out_csv or f"{out_all}.csv"
        out_sarif = out_sarif or f"{out_all}.sarif"

    parsed_ports: list[int] | None = None
    if ports:
        try:
            parsed_ports = parse_ports(ports)
        except ValueError as exc:
            console.print(f"[red]error:[/red] bad --ports value {ports!r}: {exc}")
            raise typer.Exit(code=2) from None

    malformed = [t for t in targets if not _target_is_valid(t)]
    if malformed:
        console.print(
            f"[yellow]warning:[/yellow] ignoring malformed target(s): {', '.join(malformed)}"
        )
    targets = [t for t in targets if _target_is_valid(t)]
    if not targets:
        console.print("[red]error:[/red] no valid targets (expected IP, CIDR, range, or hostname)")
        raise typer.Exit(code=2)

    if pcap and not Path(pcap).exists():
        console.print(f"[red]error:[/red] pcap file not found: {pcap}")
        raise typer.Exit(code=2)

    cfg = ScanConfig(
        targets=targets,
        iface=iface,
        pcap=pcap,
        ports=parsed_ports,
        sniff_timeout=sniff_timeout,
        mode=mode,
        timing=timing,
        rate=rate,
        timeout_ms=timeout,
        retries=retries,
        threads=threads,
        max_detect_risk=max_detect_risk,
        engine=engine,
        adaptive=adaptive,
        udp=udp,
        service_scan=service_scan,
        fingerprint=do_fingerprint,
        names=do_names,
        classify=do_classify,
        enrich=do_enrich,
        ssvc=do_ssvc,
        plugins=do_plugins,
        agentic=do_agentic,
        deception=do_deception,
        db=db,
        baseline=baseline,
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
        resolved_scope = _resolve_scope_file(cfg.scope_file, console, quiet=quiet or silent)
        guard = ScopeGuard.from_file(resolved_scope, audit=audit)
    except FileNotFoundError:
        console.print(f"[red]error:[/red] scope file not found: {cfg.scope_file}")
        raise typer.Exit(code=2) from None
    except Exception as exc:  # malformed YAML, bad schema, unreadable file, ...
        console.print(f"[red]error:[/red] could not load scope file {cfg.scope_file!r}: {exc}")
        raise typer.Exit(code=2) from exc

    if not silent and not quiet:
        console.print(f"[bold yellow][!] {guard.banner}[/bold yellow]")
        console.print(
            f"[dim]mode={mode.value} -T{timing} engine={engine} fingerprint={do_fingerprint}[/dim]"
        )

    if do_enrich and not silent:
        console.print(
            "[bold yellow][!] --enrich: CVE IDs will be sent to FIRST.org and CISA. "
            "Data leaves host.[/bold yellow]"
        )

    budget = StealthBudget.from_config(cfg)
    live_enabled = not silent and not quiet and not dry_run and console.is_terminal
    try:
        result = asyncio.run(
            _run_pipeline(cfg, guard, budget, console, live_enabled, resolved_scope)
        )
    except ScopeViolationError as exc:
        console.print(f"[red]scope violation:[/red] {exc}")
        raise typer.Exit(code=3) from exc
    except RuntimeError as exc:  # Go engine not built / failed to run
        console.print(f"[red]engine error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except TargetTooLargeError as exc:
        console.print(f"[red]target too large:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if not silent:
        report.render_result(console, result, quiet=quiet)
        if not dry_run and not result.hosts:
            console.print(
                "[dim]no hosts responded — they may be down, filtered, "
                "or a hostname did not resolve[/dim]"
            )

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
            try:
                writers[fmt].write(result, Path(path))
            except OSError as exc:
                console.print(f"[red]error:[/red] could not write {fmt} report to {path}: {exc}")
                raise typer.Exit(code=1) from exc
            if not silent:
                console.print(f"[green]wrote[/green] {fmt} -> {path}")
        elif path:
            console.print(f"[yellow]skip[/yellow] {fmt}: writer not available yet")


# The `diff` verb lives in its own single-command Typer app rather than as a
# second command on `app`. Adding a second command to `app` would flip Typer into
# multi-command mode, where the primary `banshee <targets>` form (and every test
# that drives it) would require an explicit `scan` subcommand. main() dispatches
# on the first token instead, so the scan surface is untouched.
diff_app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    help="Compare two BANSHEE JSON reports and show what changed.",
)


@diff_app.command()
def diff(
    old: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, help="earlier BANSHEE JSON report"),
    ],
    new: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, help="later BANSHEE JSON report"),
    ],
    out_json: Annotated[
        str | None, typer.Option("--json", help="write the diff as JSON too")
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="disable ANSI colour")] = False,
) -> None:
    """Diff two scan reports: new/gone hosts, opened/closed ports, version changes."""
    console = Console(no_color=no_color)
    try:
        old_result = ScanResult.model_validate_json(old.read_text(encoding="utf-8"))
        new_result = ScanResult.model_validate_json(new.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        console.print(f"[red]error:[/red] could not read a BANSHEE JSON report: {exc}")
        raise typer.Exit(code=2) from exc

    delta = compute_diff(old_result, new_result)
    if out_json:
        try:
            Path(out_json).write_text(delta.model_dump_json(indent=2), encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]error:[/red] could not write diff to {out_json}: {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[green]wrote[/green] diff -> {out_json}")
    render_diff(delta, console)


install_app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    help="Download the prebuilt Go engine so `--engine go` works without a toolchain.",
)


@install_app.command()
def install_engine_cmd(
    tag: Annotated[
        str | None,
        typer.Option("--tag", help="release tag to fetch (default: latest)"),
    ] = None,
    dest_dir: Annotated[
        str | None,
        typer.Option("--dir", help="directory to install into (default: next to `banshee`)"),
    ] = None,
) -> None:
    """Fetch the banshee-engine binary for this OS/arch from GitHub Releases."""
    console = Console()
    try:
        install_engine(console, tag=tag, dest_dir=dest_dir)
    except EngineInstallError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


def main() -> None:
    """Console entry point. Routes `banshee diff ...` and `banshee install-engine
    ...` to their own apps and every other invocation to the scan command, so all
    verbs share one `banshee`."""
    argv = sys.argv[1:]
    if argv and argv[0] == "diff":
        diff_app(args=argv[1:])
    elif argv and argv[0] == "install-engine":
        install_app(args=argv[1:])
    else:
        app()


if __name__ == "__main__":
    main()
