"""CLI surface — flag wiring, scope enforcement, output, exit codes.

All invocations use --dry-run so no packets are sent and the passive sniffer is
skipped (keeps the suite fast and fully offline).
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from scanner import __version__
from scanner.cli import app

runner = CliRunner()


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "banner: TEST AUTHORIZED\nallowlist:\n  - 10.0.0.0/8\n  - 127.0.0.0/8\n"
        "denylist: []\nmax_hosts_per_scan: 1024\nmax_ports_per_host: 1000\n",
        encoding="utf-8",
    )
    return str(p)


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_no_targets_errors():
    result = runner.invoke(app, [])
    assert result.exit_code == 2


def test_dry_run_in_scope(scope_file):
    result = runner.invoke(app, ["10.0.0.1", "--dry-run", "--scope", scope_file])
    assert result.exit_code == 0


def test_scope_violation_exits_3(scope_file):
    result = runner.invoke(app, ["8.8.8.8", "--dry-run", "--scope", scope_file])
    assert result.exit_code == 3
    assert "scope violation" in result.stdout.lower()


def test_missing_scope_file_exits_2():
    result = runner.invoke(app, ["10.0.0.1", "--dry-run", "--scope", "no/such/file.yaml"])
    assert result.exit_code == 2


def test_json_output_written(scope_file, tmp_path):
    out = tmp_path / "r.json"
    result = runner.invoke(
        app, ["10.0.0.1", "--dry-run", "--silent", "--scope", scope_file, "--json", str(out)]
    )
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["config"]["dry_run"] is True
    assert len(data["hosts"]) == 1


def test_all_formats_written(scope_file, tmp_path):
    base = tmp_path / "scan"
    result = runner.invoke(
        app,
        ["10.0.0.1", "--dry-run", "--silent", "--scope", scope_file, "--all", str(base)],
    )
    assert result.exit_code == 0
    for ext in ("txt", "json", "xml", "html", "csv", "sarif"):
        assert (tmp_path / f"scan.{ext}").exists(), ext


def test_silent_produces_no_stdout(scope_file, tmp_path):
    out = tmp_path / "r.json"
    result = runner.invoke(
        app, ["10.0.0.1", "--dry-run", "--silent", "--scope", scope_file, "--json", str(out)]
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == ""


def test_range_expands_multiple_hosts(scope_file, tmp_path):
    out = tmp_path / "r.json"
    result = runner.invoke(
        app, ["10.0.0.1-3", "--dry-run", "--silent", "--scope", scope_file, "--json", str(out)]
    )
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["hosts"]) == 3


def test_audit_log_written(scope_file, tmp_path):
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(
        app,
        ["10.0.0.1", "--dry-run", "--silent", "--scope", scope_file, "--audit-log", str(audit)],
    )
    assert result.exit_code == 0
    lines = audit.read_text(encoding="utf-8").strip().splitlines()
    events = {json.loads(ln)["event"] for ln in lines}
    assert "scan_start" in events
    assert "dry_run" in events
