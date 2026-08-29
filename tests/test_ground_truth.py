"""End-to-end verification against known ground truth on loopback.

Every other test in this suite mocks the network, which means none of them can
catch the failure mode that matters most for a scanner: *reporting things that
are not there*. These tests bind real listeners on 127.0.0.1, run the real CLI,
and compare its output against the sockets we actually opened.

Two directions are checked, and the negative one is the important half:
  - every port we bound must be reported open   (no false negatives)
  - a port we deliberately left closed must NOT be reported open (no fabrication)

127.0.0.1 is the only target used. It is the operator's own machine, always in
the default scope, and — critically — the only host whose true state the test
can independently establish.
"""

from __future__ import annotations

import contextlib
import json
import socket

import pytest
from typer.testing import CliRunner

from scanner.cli import app, parse_ports
from scanner.core.models import ConfidenceTier, Finding, Severity
from scanner.plugins.engine import load_rules

runner = CliRunner()

PROJECT_PLUGIN_DIR = "config/plugins"


@pytest.fixture
def loopback_scope(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "banner: TEST AUTHORIZED LOOPBACK ONLY\n"
        "allowlist:\n  - 127.0.0.0/8\n"
        "denylist: []\nmax_hosts_per_scan: 16\nmax_ports_per_host: 1000\n",
        encoding="utf-8",
    )
    return str(p)


@contextlib.contextmanager
def listeners(count: int):
    """Bind `count` TCP listeners on ephemeral loopback ports; yield their ports."""
    socks = []
    try:
        for _ in range(count):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            s.listen(8)
            socks.append(s)
        yield [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            with contextlib.suppress(OSError):
                s.close()


def closed_port() -> int:
    """Reserve an ephemeral port, then release it, so nothing is listening on it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def scan_localhost(scope_file, tmp_path, ports: list[int]) -> dict:
    out = tmp_path / "gt.json"
    result = runner.invoke(
        app,
        [
            "127.0.0.1",
            "--mode", "normal",
            "--engine", "python",  # ground truth pins the reference (Python) path
            "-T", "4",
            "--sniff-timeout", "0.5",
            "--no-fingerprint",
            "--ports", ",".join(str(p) for p in ports),
            "--scope", scope_file,
            "--silent",
            "--json", str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text(encoding="utf-8"))


def open_ports_of(data: dict, ip: str = "127.0.0.1") -> set[int]:
    for host in data["hosts"]:
        if host["ip"] == ip:
            return {s["port"] for s in host["services"] if s["state"] == "open"}
    return set()


# ── ground truth ──────────────────────────────────────────────────────────────

def test_reports_exactly_the_ports_that_are_open(loopback_scope, tmp_path):
    """The scanner's output must equal reality — in both directions."""
    with listeners(3) as bound:
        shut = closed_port()
        assert shut not in bound
        data = scan_localhost(loopback_scope, tmp_path, [*bound, shut])

    found = open_ports_of(data)
    assert found == set(bound), (
        f"ground-truth mismatch: bound={sorted(bound)} closed={shut} reported={sorted(found)}"
    )
    # The negative half stated separately so a failure names the actual defect.
    assert shut not in found, f"fabricated an open port: {shut} was never bound"


def test_reports_nothing_when_nothing_is_listening(loopback_scope, tmp_path):
    """With no listeners on the probed ports, no service may be claimed open."""
    shut = [closed_port() for _ in range(3)]
    data = scan_localhost(loopback_scope, tmp_path, shut)
    assert open_ports_of(data) == set()


def test_open_ports_are_marked_confirmed_and_packets_were_sent(loopback_scope, tmp_path):
    """A reported port must carry CONFIRMED evidence and a real packet count.

    packets_sent > 0 is what separates an actual probe from an invented result.
    """
    with listeners(1) as bound:
        data = scan_localhost(loopback_scope, tmp_path, bound)

    host = next(h for h in data["hosts"] if h["ip"] == "127.0.0.1")
    assert host["state"] == "up"
    svc = next(s for s in host["services"] if s["port"] == bound[0])
    assert svc["confidence"] == ConfidenceTier.CONFIRMED.value
    assert svc["source"] == "A3"
    assert data["stats"]["packets_sent"] > 0


def test_passive_mode_sends_zero_packets_and_claims_no_ports(loopback_scope, tmp_path):
    """Passive mode must not probe, even with a live listener sitting there."""
    out = tmp_path / "passive.json"
    with listeners(1) as bound:
        result = runner.invoke(
            app,
            [
                "127.0.0.1", "--mode", "passive", "--no-fingerprint", "--sniff-timeout", "0.5",
                "--ports", str(bound[0]),
                "--scope", loopback_scope, "--silent", "--json", str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))

    assert data["stats"]["packets_sent"] == 0
    assert open_ports_of(data) == set()


# ── the two regressions that let broken features ship green ───────────────────

def test_shipped_plugin_rules_actually_load():
    """Guards F1: the rule files in the repo must parse under the real loader."""
    rules = load_rules(__import__("pathlib").Path(PROJECT_PLUGIN_DIR))
    assert len(rules) >= 4, f"shipped plugin rules failed to load: {len(rules)}"
    assert all("id" in r and "match" in r for r in rules)


@pytest.mark.asyncio
async def test_llm_findings_are_capped_after_every_analysis_pass(monkeypatch, loopback_scope):
    """Guards F3: a finding injected by a late pass is still forced to POTENTIAL.

    The policy pass used to run before plugins/intel/LLM, so anything they added
    escaped the cap entirely.
    """
    from rich.console import Console

    from scanner.cli import _run_pipeline
    from scanner.core.budget import StealthBudget
    from scanner.core.models import ScanConfig, ScanMode
    from scanner.core.scope import AuditLog, ScopeGuard

    def fake_plugins(result, plugin_dir=None):
        for host in result.hosts:
            host.findings.append(
                Finding(
                    id="LLM-ESCAPE",
                    title="injected by a late pass",
                    severity=Severity.HIGH,
                    confidence=ConfidenceTier.CONFIRMED,
                    is_llm_inferred=True,
                )
            )
        return 1

    monkeypatch.setattr("scanner.cli.run_plugins", fake_plugins)

    cfg = ScanConfig(
        targets=["127.0.0.1"], mode=ScanMode.NORMAL, ports=[closed_port()],
        fingerprint=False, plugins=True, silent=True, scope_file=loopback_scope,
        sniff_timeout=0.5,
    )
    guard = ScopeGuard.from_file(loopback_scope, audit=AuditLog(None))
    result = await _run_pipeline(
        cfg, guard, StealthBudget.from_config(cfg), Console(quiet=True),
        live_enabled=False, scope_path=loopback_scope,
    )

    injected = [f for h in result.hosts for f in h.findings if f.id == "LLM-ESCAPE"]
    assert injected, "test setup failed — the late pass did not run"
    assert all(f.confidence == ConfidenceTier.POTENTIAL for f in injected)


def test_banner_falls_back_to_ascii_on_a_legacy_codepage(tmp_path):
    """A cp1252 Windows console must not crash on the block-drawing banner."""
    import io

    from rich.console import Console

    from scanner.ui import print_banner

    buf = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict", newline="")
    console = Console(file=buf, width=100, no_color=True, legacy_windows=True)
    print_banner(console)  # raised UnicodeEncodeError before the fallback existed
    buf.flush()
    rendered = buf.buffer.getvalue().decode("cp1252")
    assert "BANSHEE" in rendered or "__ )" in rendered


def test_parse_ports_accepts_lists_ranges_and_rejects_junk():
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("20-22,80") == [20, 21, 22, 80]
    for bad in ("", "80-20", "0", "70000", "http"):
        with pytest.raises(ValueError):
            parse_ports(bad)


def test_banner_is_captured_from_a_server_that_speaks_first(loopback_scope, tmp_path):
    """A real greeting must land in Service.banner, and must not be invented.

    Guards F16: nothing in the pipeline populated Service.banner, which made the
    negative-space honeypot check ("SSH open with no banner") fire on every SSH
    host alive. Two listeners here: one greets on connect, one stays silent.
    """
    import threading

    greeting = b"SSH-2.0-OpenSSH_9.6 ground-truth\r\n"
    talker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    talker.bind(("127.0.0.1", 0))
    talker.listen(4)
    mute = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mute.bind(("127.0.0.1", 0))
    mute.listen(4)
    t_port, m_port = talker.getsockname()[1], mute.getsockname()[1]

    def greet():
        with contextlib.suppress(OSError):
            conn, _ = talker.accept()
            conn.sendall(greeting)
            conn.close()

    thread = threading.Thread(target=greet, daemon=True)
    thread.start()
    try:
        data = scan_localhost(loopback_scope, tmp_path, [t_port, m_port])
    finally:
        talker.close()
        mute.close()

    host = next(h for h in data["hosts"] if h["ip"] == "127.0.0.1")
    by_port = {s["port"]: s for s in host["services"]}
    assert by_port[t_port]["banner"] is not None
    assert "OpenSSH_9.6 ground-truth" in by_port[t_port]["banner"]
    # The silent listener must report no banner rather than a fabricated one.
    assert by_port[m_port]["banner"] is None


def test_no_banner_honeypot_check_ignores_services_never_connected_to():
    """Guards F16: the check may only fire for ports the TCP sweep actually opened."""
    from scanner.core.models import Host, HostState, PortState, Proto, Service
    from scanner.fingerprint.negspace import _check_banner_absence

    def ssh_host(source: str) -> Host:
        return Host(
            ip="10.0.0.9",
            state=HostState.UP,
            services=[
                Service(port=22, proto=Proto.TCP, state=PortState.OPEN, source=source)
            ],
        )

    passive = ssh_host("A2")  # seen on the wire; no socket was ever opened to it
    _check_banner_absence(passive)
    assert passive.findings == []

    probed = ssh_host("A3")  # connected to, and it said nothing
    _check_banner_absence(probed)
    assert [f.source for f in probed.findings] == ["B8"]
