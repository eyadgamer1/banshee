"""E5 scope-guard tests — the safety boundary. These must never regress."""

from __future__ import annotations

import pytest

from scanner.core.scope import AuditLog, ScopeGuard, ScopeViolationError


@pytest.fixture
def guard() -> ScopeGuard:
    return ScopeGuard(
        allowlist=["127.0.0.0/8", "192.168.0.0/16"],
        denylist=["192.168.99.0/24"],
        audit=AuditLog(None),
    )


def test_in_scope_allowed(guard: ScopeGuard) -> None:
    assert guard.is_in_scope("127.0.0.1")
    assert guard.is_in_scope("192.168.1.50")


def test_out_of_scope_rejected(guard: ScopeGuard) -> None:
    assert not guard.is_in_scope("8.8.8.8")
    assert not guard.is_in_scope("10.0.0.1")


def test_denylist_beats_allowlist(guard: ScopeGuard) -> None:
    assert not guard.is_in_scope("192.168.99.5")


def test_check_raises_out_of_scope(guard: ScopeGuard) -> None:
    with pytest.raises(ScopeViolationError):
        guard.check("8.8.8.8")


def test_check_raises_denylist(guard: ScopeGuard) -> None:
    with pytest.raises(ScopeViolationError):
        guard.check("192.168.99.5")


def test_check_passes_in_scope(guard: ScopeGuard) -> None:
    guard.check("127.0.0.1")  # must not raise


def test_check_rejects_non_ip(guard: ScopeGuard) -> None:
    with pytest.raises(ScopeViolationError):
        guard.check("not-an-ip")


def test_filter_partitions(guard: ScopeGuard) -> None:
    allowed, denied = guard.filter_targets(["127.0.0.1", "8.8.8.8", "192.168.1.1", "1.1.1.1"])
    assert allowed == ["127.0.0.1", "192.168.1.1"]
    assert denied == ["8.8.8.8", "1.1.1.1"]


def test_audit_records_decisions() -> None:
    audit = AuditLog(None)
    g = ScopeGuard(allowlist=["10.0.0.0/8"], audit=audit)
    g.check("10.0.0.1")
    with pytest.raises(ScopeViolationError):
        g.check("8.8.8.8")
    events = [e["event"] for e in audit.entries]
    assert "scope_accept" in events
    assert "scope_reject" in events


def test_from_file_loads_default_scope() -> None:
    g = ScopeGuard.from_file("config/scope.yaml")
    assert g.banner == "AUTHORIZED TARGETS ONLY"
    assert g.is_in_scope("192.168.1.1")
    assert not g.is_in_scope("8.8.8.8")
