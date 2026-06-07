"""Risk module — confidence tiers and prioritization (C4–C7).

Integration contract consumed by the CLI: `tier_result(result)` applies the
confidence-tier policy across all hosts/findings after the scan completes. Risk is
the *final authority* on `host.confidence`: producers set an initial value, this
pass recomputes it from the evidence actually gathered.

C7-lite policy (deterministic, no network, no LLM):

  1. Safety cap  — any LLM-inferred finding is forced to POTENTIAL, never escalated.
  2. Host tier   — recompute host.confidence from corroborating evidence:
       CONFIRMED  a confirmed service, or >= 2 independent identity signals
       PROBABLE   exactly 1 identity signal
       POTENTIAL  alive but unidentified, or not up

Host identity confidence and per-finding evidence confidence are intentionally
separate axes: a CONFIRMED open-port finding is not downgraded merely because the
host's identity is still unknown.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scanner.core.models import ConfidenceTier, HostState

if TYPE_CHECKING:
    from scanner.core.models import Host, ScanResult

_STRONG_CORROBORATION = 2  # independent identity signals needed for CONFIRMED


def _has_confirmed_service(host: Host) -> bool:
    return any(svc.confidence == ConfidenceTier.CONFIRMED for svc in host.services)


def _identity_signals(host: Host) -> int:
    """Count independent identity signals: MAC, vendor, any name, any service."""
    return sum(
        (
            host.mac is not None,
            host.vendor is not None,
            bool(host.names) or host.hostname is not None,
            bool(host.services),
        )
    )


def host_tier(host: Host) -> ConfidenceTier:
    """Evidence-derived identity confidence for a single host."""
    if host.state != HostState.UP:
        return ConfidenceTier.POTENTIAL
    if _has_confirmed_service(host):
        return ConfidenceTier.CONFIRMED
    signals = _identity_signals(host)
    if signals >= _STRONG_CORROBORATION:
        return ConfidenceTier.CONFIRMED
    if signals == 1:
        return ConfidenceTier.PROBABLE
    return ConfidenceTier.POTENTIAL


def tier_result(result: ScanResult) -> None:
    """Apply the C7-lite confidence-tier policy across the result, in place."""
    for host in result.hosts:
        host.confidence = host_tier(host)
        for finding in host.findings:
            # LLM-inferred intel can never be asserted above POTENTIAL.
            if finding.is_llm_inferred:
                finding.confidence = ConfidenceTier.POTENTIAL
