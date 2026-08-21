"""E1 YAML plugin engine — rule loading, matching, and application."""

from __future__ import annotations

from scanner.core.models import (
    Host,
    HostState,
    PortState,
    Proto,
    ScanConfig,
    ScanResult,
    Service,
)
from scanner.plugins.engine import _matches, apply_rules, load_rules, run_plugins


def host(ip="10.0.0.5", ports=None, device_type=None, hostname=None, os_guess=None):
    return Host(
        ip=ip,
        state=HostState.UP,
        device_type=device_type,
        hostname=hostname,
        os_guess=os_guess,
        services=[Service(port=p, proto=Proto.TCP, state=PortState.OPEN) for p in (ports or [])],
    )


def result(hosts):
    return ScanResult(config=ScanConfig(), hosts=hosts)


def test_match_open_ports_any():
    assert _matches(host(ports=[23]), {"open_ports": [23, 2323]}) is True
    assert _matches(host(ports=[80]), {"open_ports": [23]}) is False


def test_match_device_type_regex():
    assert _matches(host(device_type="router"), {"device_type": "rout"}) is True
    assert _matches(host(device_type="server"), {"device_type": "rout"}) is False


def test_match_hostname_regex():
    assert _matches(host(hostname="db-prod-1"), {"hostname_regex": "^db-"}) is True


def test_match_os_regex():
    assert _matches(host(os_guess="Windows"), {"os_regex": "windows"}) is True


def test_match_all_conditions_anded():
    h = host(ports=[23], device_type="router")
    assert _matches(h, {"open_ports": [23], "device_type": "router"}) is True
    assert _matches(h, {"open_ports": [23], "device_type": "printer"}) is False


def test_empty_match_block_matches_everything():
    assert _matches(host(), {}) is True


def test_apply_rules_adds_finding():
    rules = [{
        "id": "TELNET",
        "title": "Telnet open",
        "severity": "high",
        "confidence": "confirmed",
        "match": {"open_ports": [23]},
    }]
    r = result([host(ports=[23])])
    added = apply_rules(r, rules)
    assert added == 1
    f = r.hosts[0].findings[0]
    assert f.severity.value == "high"
    assert f.source == "plugin:TELNET"


def test_apply_rules_dedups():
    rules = [{"id": "X", "title": "x", "match": {"open_ports": [23]}}]
    r = result([host(ports=[23])])
    apply_rules(r, rules)
    second = apply_rules(r, rules)  # same rule again
    assert second == 0
    assert len(r.hosts[0].findings) == 1


def test_load_rules_from_dir(tmp_path):
    (tmp_path / "r1.yaml").write_text(
        'id: R1\ntitle: "rule one"\nmatch:\n  open_ports:\n    - 22\n', encoding="utf-8"
    )
    (tmp_path / "notarule.yaml").write_text("just: data\n", encoding="utf-8")
    rules = load_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0]["id"] == "R1"


def test_load_rules_missing_dir():
    from pathlib import Path

    assert load_rules(Path("does/not/exist")) == []


def test_run_plugins_end_to_end(tmp_path):
    (tmp_path / "telnet.yaml").write_text(
        'id: TEL\ntitle: "Telnet"\nseverity: high\nmatch:\n  open_ports:\n    - 23\n',
        encoding="utf-8",
    )
    r = result([host(ports=[23])])
    count = run_plugins(r, plugin_dir=tmp_path)
    assert count == 1
