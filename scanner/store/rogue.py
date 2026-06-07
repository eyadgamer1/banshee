"""E2 — rogue device detector.

Compares MACs observed in the current scan against the persistent baseline in
`mac_baseline` (written by A6 ScanStore). Any MAC not previously recorded is
flagged as a rogue (or new/unknown) device and a Finding is attached to the host.

This is a post-scan pass: call `RogueDetector.check(result, known_macs)` after
`ScanStore.save_result()` to annotate the result in place.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scanner.core.models import ConfidenceTier, Finding, Severity

if TYPE_CHECKING:
    from scanner.core.models import Host, ScanResult


class RogueDetector:
    """E2 — flags hosts whose MACs have never been seen before."""

    def check(self, result: ScanResult, known_macs: set[str]) -> list[Host]:
        """Attach rogue findings to hosts with unknown MACs; return affected hosts."""
        rogues: list[Host] = []
        for host in result.hosts:
            if host.mac and host.mac.lower() not in known_macs:
                finding = Finding(
                    id=f"E2-{host.mac.replace(':', '')}",
                    title=f"New/unrecognised MAC: {host.mac}",
                    severity=Severity.MEDIUM,
                    confidence=ConfidenceTier.CONFIRMED,
                    description=(
                        f"Host {host.ip} ({host.vendor or 'unknown vendor'}) has a MAC address "
                        f"({host.mac}) not present in the scan baseline. This may indicate a "
                        f"new device, a spoofed MAC, or a rogue device on the network."
                    ),
                    source="E2",
                )
                host.findings.append(finding)
                rogues.append(host)
        return rogues
