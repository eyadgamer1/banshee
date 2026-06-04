"""Risk module — confidence tiers and prioritization (C4–C7).

Integration contract consumed by the CLI: `tier_result(result)` applies the
confidence-tier policy across all hosts/findings after the scan completes.

Wave 0 enforces the one safety invariant now: any LLM-inferred finding is capped
at POTENTIAL. agent-risk (P1-4) expands this into the full C7-lite policy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scanner.core.models import ConfidenceTier

if TYPE_CHECKING:
    from scanner.core.models import ScanResult


def tier_result(result: ScanResult) -> None:
    """Apply confidence-tier policy in place. C7-lite baseline."""
    for host in result.hosts:
        for finding in host.findings:
            if finding.is_llm_inferred and finding.confidence != ConfidenceTier.POTENTIAL:
                finding.confidence = ConfidenceTier.POTENTIAL
