"""E5 ScopeGuard — the authoritative safety boundary."""

from __future__ import annotations

import pytest

from scanner.core.scope import AuditLog, ScopeGuard, ScopeViolationError


def guard(allow=("10.0.0.0/8",), deny=()):
    return ScopeGuard(allowlist=list(allow), denylist=list(deny), audit=AuditLog(None))


def test_in_scope_allowlist():
    g = guard()
    assert g.is_in_scope("10.1.2.3") is True
    assert g.is_in_scope("8.8.8.8") is False


def test_denylist_overrides_allowlist():
    g = guard(allow=("10.0.0.0/8",), deny=("10.0.0.0/16",))
    assert g.is_in_scope("10.0.0.5") is False  # denied subnet
    assert g.is_in_scope("10.1.0.5") is True  # allowed, not denied


def test_check_raises_for_out_of_scope():
    g = guard()
    with pytest.raises(ScopeViolationError) as ei:
        g.check("8.8.8.8")
    assert ei.value.target == "8.8.8.8"
    assert "allowlist" in ei.value.reason


def test_check_raises_for_denylisted():
    g = guard(allow=("10.0.0.0/8",), deny=("10.9.9.0/24",))
    with pytest.raises(ScopeViolationError):
        g.check("10.9.9.9")


def test_check_raises_for_unresolvable_token():
    g = guard()
    with pytest.raises(ScopeViolationError):
        g.check("not-an-ip")


def test_check_passes_for_in_scope():
    g = guard()
    g.check("10.0.0.1")  # must not raise


def test_filter_targets_partitions_without_raising():
    g = guard()
    in_s, out_s = g.filter_targets(["10.0.0.1", "8.8.8.8", "10.0.0.2", "1.1.1.1"])
    assert in_s == ["10.0.0.1", "10.0.0.2"]
    assert out_s == ["8.8.8.8", "1.1.1.1"]


def test_scope_decisions_are_audited():
    audit = AuditLog(None)
    g = ScopeGuard(allowlist=["10.0.0.0/8"], audit=audit)
    g.check("10.0.0.1")
    with pytest.raises(ScopeViolationError):
        g.check("8.8.8.8")
    events = [e["event"] for e in audit.entries]
    assert "scope_accept" in events
    assert "scope_reject" in events


def test_from_file_roundtrip(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "banner: HELLO\nallowlist:\n  - 192.168.0.0/16\ndenylist: []\n"
        "max_hosts_per_scan: 7\nmax_ports_per_host: 9\n",
        encoding="utf-8",
    )
    g = ScopeGuard.from_file(p)
    assert g.banner == "HELLO"
    assert g.max_hosts_per_scan == 7
    assert g.max_ports_per_host == 9
    assert g.is_in_scope("192.168.1.1") is True


def test_ipv6_in_scope():
    g = ScopeGuard(allowlist=["::1/128", "fd00::/8"], audit=AuditLog(None))
    assert g.is_in_scope("::1") is True
    assert g.is_in_scope("fd00::1234") is True
    assert g.is_in_scope("2001:4860:4860::8888") is False


def test_audit_log_writes_jsonl(tmp_path):
    path = tmp_path / "a.jsonl"
    audit = AuditLog(str(path))
    audit.log("hello", k="v")
    audit.log("world", n=2)
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    import json

    assert json.loads(lines[0])["event"] == "hello"
    assert json.loads(lines[1])["n"] == 2
