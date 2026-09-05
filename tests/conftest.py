"""Shared pytest fixtures and fakes for the pps test suite.

Every test runs fully offline: no real packets, no DNS, no external APIs. Active
probe paths are exercised either through the pure wire-codec helpers or by
monkeypatching the synchronous probe functions, never by touching the network.
"""

from __future__ import annotations

import pytest

from scanner.core.budget import StealthBudget
from scanner.core.engine import RunContext
from scanner.core.models import (
    ConfidenceTier,
    Host,
    HostState,
    PortState,
    Proto,
    ScanConfig,
    ScanMode,
    Service,
)
from scanner.core.scope import AuditLog, ScopeGuard

# Allowlist that covers loopback + RFC1918 so test targets are always in scope.
TEST_ALLOWLIST = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def make_scope(allowlist: list[str] | None = None, denylist: list[str] | None = None) -> ScopeGuard:
    return ScopeGuard(
        allowlist=allowlist if allowlist is not None else TEST_ALLOWLIST,
        denylist=denylist or [],
        banner="TEST SCOPE",
        audit=AuditLog(None),
    )


def make_budget(mode: ScanMode = ScanMode.NORMAL, timing: int = 4, **kw: object) -> StealthBudget:
    cfg = ScanConfig(mode=mode, timing=timing, **kw)  # type: ignore[arg-type]
    return StealthBudget.from_config(cfg)


def make_ctx(
    budget: StealthBudget | None = None,
    scope: ScopeGuard | None = None,
) -> RunContext:
    scope = scope or make_scope()
    budget = budget or make_budget()
    return RunContext(scope, budget, scope.audit)


@pytest.fixture
def scope() -> ScopeGuard:
    return make_scope()


@pytest.fixture
def passive_ctx() -> RunContext:
    # zero-active budget: no packets allowed (max-detect-risk 0)
    return make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=0, max_detect_risk=0))


@pytest.fixture
def active_ctx() -> RunContext:
    return make_ctx(budget=make_budget(mode=ScanMode.NORMAL, timing=4))


def make_host(
    ip: str = "10.0.0.5",
    *,
    state: HostState = HostState.UP,
    ports: list[int] | None = None,
    os_guess: str | None = None,
    device_type: str | None = None,
    mac: str | None = None,
    vendor: str | None = None,
) -> Host:
    services = [
        Service(port=p, proto=Proto.TCP, state=PortState.OPEN, confidence=ConfidenceTier.CONFIRMED)
        for p in (ports or [])
    ]
    return Host(
        ip=ip,
        state=state,
        services=services,
        os_guess=os_guess,
        device_type=device_type,
        mac=mac,
        vendor=vendor,
    )
