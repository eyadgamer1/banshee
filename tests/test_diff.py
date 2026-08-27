"""`banshee diff` — compare two reports, honestly.

Drives the real diff CLI over crafted JSON reports and asserts every kind of
change is detected (new/gone host, opened/closed port, version change) and that
an ambiguous open|filtered port never manufactures a spurious open/close.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from scanner.cli import diff_app, main
from scanner.core.models import Host, HostState, PortState, ScanConfig, ScanResult, Service

runner = CliRunner()


def _report(path, hosts):
    result = ScanResult(config=ScanConfig(targets=["10.0.0.0/24"]), hosts=hosts)
    path.write_text(result.model_dump_json(), encoding="utf-8")
    return str(path)


def _host(ip, services):
    return Host(ip=ip, state=HostState.UP, services=services)


def _svc(port, name, *, state=PortState.OPEN, product=None, version=None):
    return Service(port=port, name=name, state=state, product=product, version=version)


def test_diff_detects_every_change_kind(tmp_path):
    old = _report(
        tmp_path / "old.json",
        [
            _host("10.0.0.1", [
                _svc(22, "ssh", product="OpenSSH", version="8.9p1"),
                _svc(23, "telnet"),
            ]),
            _host("10.0.0.2", [_svc(80, "http")]),  # will vanish
        ],
    )
    new = _report(
        tmp_path / "new.json",
        [
            _host("10.0.0.1", [
                _svc(22, "ssh", product="OpenSSH", version="9.9p1"),  # version change
                _svc(8080, "http-alt"),  # opened; 23 closed
            ]),
            _host("10.0.0.3", [_svc(443, "https")]),  # new host
        ],
    )
    out = tmp_path / "d.json"
    r = runner.invoke(diff_app, [old, new, "--json", str(out), "--no-color"])
    assert r.exit_code == 0, r.output
    d = json.loads(out.read_text(encoding="utf-8"))

    assert [h["ip"] for h in d["new_hosts"]] == ["10.0.0.3"]
    assert [h["ip"] for h in d["gone_hosts"]] == ["10.0.0.2"]
    (hd,) = d["host_diffs"]
    assert hd["ip"] == "10.0.0.1"
    assert [s["port"] for s in hd["opened"]] == [8080]
    assert [s["port"] for s in hd["closed"]] == [23]
    (ch,) = hd["changed"]
    assert (ch["port"], ch["old"], ch["new"]) == (22, "OpenSSH 8.9p1", "OpenSSH 9.9p1")


def test_diff_no_changes_reports_identical(tmp_path):
    hosts = [_host("10.0.0.1", [_svc(22, "ssh")])]
    a = _report(tmp_path / "a.json", hosts)
    b = _report(tmp_path / "b.json", hosts)
    r = runner.invoke(diff_app, [a, b, "--no-color"])
    assert r.exit_code == 0
    assert "no changes" in r.output


def test_diff_open_filtered_is_not_a_change(tmp_path):
    # A silent UDP-style open|filtered port must not read as an opened service.
    old = _report(tmp_path / "o.json", [_host("10.0.0.1", [_svc(22, "ssh")])])
    new = _report(
        tmp_path / "n.json",
        [_host("10.0.0.1", [_svc(22, "ssh"), _svc(161, "snmp", state=PortState.OPEN_FILTERED)])],
    )
    out = tmp_path / "d.json"
    r = runner.invoke(diff_app, [old, new, "--json", str(out)])
    assert r.exit_code == 0
    assert json.loads(out.read_text(encoding="utf-8"))["host_diffs"] == []


def test_diff_bad_report_exits_2(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid banshee json", encoding="utf-8")
    good = _report(tmp_path / "g.json", [])
    r = runner.invoke(diff_app, [str(bad), good])
    assert r.exit_code == 2


def test_main_routes_diff_subcommand(tmp_path, monkeypatch, capsys):
    a = _report(tmp_path / "a.json", [_host("10.0.0.1", [_svc(22, "ssh")])])
    b = _report(tmp_path / "b.json", [_host("10.0.0.1", [_svc(22, "ssh"), _svc(80, "http")])])
    monkeypatch.setattr("sys.argv", ["banshee", "diff", a, b, "--no-color"])
    try:
        main()
    except SystemExit as exc:
        assert exc.code in (0, None)
    assert "opened" in capsys.readouterr().out
