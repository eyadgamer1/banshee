"""Error and edge-case handling — every bad input fails fast with a clear message
and the documented exit code, never a traceback.

Exit codes: 2 = bad usage, 1 = runtime/IO error, 3 = scope violation.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from scanner.cli import app

runner = CliRunner()


@pytest.fixture
def scope(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "banner: TEST\nallowlist:\n  - 127.0.0.0/8\ndenylist: []\n"
        "max_hosts_per_scan: 16\nmax_ports_per_host: 100\n",
        encoding="utf-8",
    )
    return str(p)


def _run(args):
    return runner.invoke(app, [*args, "--silent"])


@pytest.mark.parametrize("target", ["999.999.999.999", "10.0.0.0/99", "10.0.0.5-999", "@@@"])
def test_malformed_targets_rejected(target, scope):
    r = _run([target, "--scope", scope])
    assert r.exit_code == 2, r.output


@pytest.mark.parametrize(
    "opt",
    [
        ["--max-detect-risk", "99"], ["--max-detect-risk", "-1"],
        ["--rate", "-5"], ["--threads", "-3"], ["--timeout", "0"],
        ["-T", "9"], ["-m", "nonsense"], ["--engine", "bogus"], ["-p", "abc"],
    ],
)
def test_out_of_range_or_unknown_options_rejected(opt, scope):
    r = _run(["127.0.0.1", "--scope", scope, *opt])
    assert r.exit_code == 2, r.output


def test_malformed_scope_file_is_clean_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("banner: x\nallowlist: [unclosed", encoding="utf-8")
    r = _run(["127.0.0.1", "-p", "135", "--scope", str(bad)])
    assert r.exit_code == 2, r.output
    assert "Traceback" not in r.output


def test_unwritable_output_path_is_clean_error(scope, tmp_path):
    # A directory is not a writable report path: clean exit 1, never a traceback.
    r = _run(["127.0.0.1", "-p", "135", "--scope", scope, "--json", str(tmp_path)])
    assert r.exit_code == 1, r.output
    assert "Traceback" not in r.output


def test_partial_targets_warn_but_scan_the_valid_ones(scope):
    # One good target + one malformed: the run proceeds and warns, not exit 2.
    r = runner.invoke(
        app,
        ["127.0.0.1", "999.999.999.999", "-p", "135", "-m", "normal",
         "-T", "4", "--sniff-timeout", "0.5", "--no-fingerprint", "--scope", scope],
    )
    assert r.exit_code == 0, r.output
    assert "malformed" in r.output
