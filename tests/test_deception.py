"""C8 deception/honeypot analysis — fires on decoy signals, stays silent on
ordinary hosts, and never claims more than POTENTIAL.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from scanner.cli import app
from scanner.core.models import (
    ConfidenceTier,
    Host,
    HostState,
    PortState,
    ScanConfig,
    ScanResult,
    Service,
    Severity,
)
from scanner.correlate import score_deception

runner = CliRunner()


def _svc(port, name="svc", *, banner=None, product=None):
    return Service(port=port, name=name, state=PortState.OPEN, banner=banner, product=product)


def _result(*hosts):
    return ScanResult(config=ScanConfig(targets=["10.0.0.0/24"]), hosts=list(hosts))


def _finding(host):
    return next((f for f in host.findings if f.source == "C8"), None)


def test_deception_flags_decoy_signals():
    many = Host(ip="10.0.0.1", state=HostState.UP, services=[_svc(p) for p in range(1, 12)])
    bait = Host(
        ip="10.0.0.2",
        state=HostState.UP,
        services=[_svc(21, "ftp"), _svc(23, "telnet"), _svc(3306, "mysql")],
    )
    hp = Host(
        ip="10.0.0.3",
        state=HostState.UP,
        services=[_svc(22, "ssh", banner="SSH-2.0-Cowrie honeypot"), _svc(2222, "ssh")],
    )
    result = _result(many, bait, hp)

    assert score_deception(result) == 3
    for host in result.hosts:
        f = _finding(host)
        assert f is not None, f"{host.ip} not flagged"
        # Honesty: never more than POTENTIAL, and evidence is always carried.
        assert f.confidence == ConfidenceTier.POTENTIAL
        assert f.severity == Severity.LOW
        assert f.evidence
    assert "cowrie" in _finding(hp).evidence.lower()


def test_deception_leaves_ordinary_hosts_alone():
    # A normal server (web + ssh) trips no signal — the false-positive guard.
    ordinary = Host(
        ip="10.0.0.9",
        state=HostState.UP,
        services=[_svc(22, "ssh", banner="SSH-2.0-OpenSSH_9.6"), _svc(443, "https")],
    )
    result = _result(ordinary)
    assert score_deception(result) == 0
    assert _finding(ordinary) is None


def test_deception_os_contradiction_alone_is_too_weak():
    # A single weak signal (Windows port + Unix banner) must not flag on its own.
    host = Host(
        ip="10.0.0.5",
        state=HostState.UP,
        services=[_svc(445, "microsoft-ds"), _svc(22, "ssh", banner="SSH-2.0-OpenSSH_8.9 Debian")],
    )
    assert score_deception(_result(host)) == 0


def test_deception_cli_flag_no_false_positive_on_loopback(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "banner: TEST\nallowlist:\n  - 127.0.0.0/8\ndenylist: []\n"
        "max_hosts_per_scan: 16\nmax_ports_per_host: 100\n",
        encoding="utf-8",
    )
    out = tmp_path / "d.json"
    r = runner.invoke(
        app,
        [
            "127.0.0.1", "--mode", "normal", "-T", "4", "--sniff-timeout", "0.5",
            "--no-fingerprint", "--deception", "--ports", "135,445",
            "--scope", str(scope), "--silent", "--json", str(out),
        ],
    )
    assert r.exit_code == 0, r.output
    data = json.loads(out.read_text(encoding="utf-8"))
    for host in data["hosts"]:
        assert not [f for f in host["findings"] if f["source"] == "C8"], "false honeypot flag"
