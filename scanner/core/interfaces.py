"""Pluggable component interfaces — dependency-injection contracts.

The engine never imports discovery/fingerprint/report directly. It operates on
these Protocols, and the CLI wires concrete implementations in. This lets each
module be built and tested independently against a frozen contract.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence

    from scanner.core.budget import StealthBudget
    from scanner.core.models import Host, ScanResult
    from scanner.core.scope import ScopeGuard


@runtime_checkable
class AuditLogger(Protocol):
    """Append-only audit trail (D5 evidence-replay groundwork)."""

    def log(self, event: str, **fields: object) -> None: ...


class ScanContext(Protocol):
    """Read-only services handed to every component during a run."""

    @property
    def scope(self) -> ScopeGuard: ...

    @property
    def budget(self) -> StealthBudget: ...

    @property
    def audit(self) -> AuditLogger: ...


class Discoverer(Protocol):
    """Finds live hosts among in-scope targets (A2–A5).

    MUST respect ctx.scope (never touch an out-of-scope IP) and ctx.budget
    (honor passive mode = zero active packets).
    """

    name: str
    feature_id: str

    async def discover(self, targets: Sequence[str], ctx: ScanContext) -> list[Host]: ...


class Fingerprinter(Protocol):
    """Enriches a single host in place with identity/service data (B1–B13)."""

    name: str
    feature_id: str

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host: ...


class ReportWriter(Protocol):
    """Serializes a ScanResult to one output format (E3)."""

    format_name: str

    def write(self, result: ScanResult, path: Path) -> None: ...
