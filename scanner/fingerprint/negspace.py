"""B8 — Negative-space fingerprinting.

Infers host properties from what is *absent* rather than what is present.
Classic examples:
  - No port 445 on a device with Windows OUI → policy-blocked or IDS
  - Port 22 open but no banner returned → honeypot or restricted SSH
  - ICMP echo reply with TTL=128 but no Windows ports → TTL spoofing
  - Lots of filtered ports between open ones → stateful firewall present

This module runs as a post-processor after all other fingerprinters have
populated Host.services. It adds INFO/LOW findings to flag anomalies.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.interfaces import ScanContext  # noqa: TC004
    from scanner.core.models import Host

log = logging.getLogger(__name__)

# Port ranges that a "normal" device of each type would expose
_EXPECTED_OPEN: dict[str, set[int]] = {
    "windows-workstation": {135, 139, 445},
    "linux-server":        {22},
    "router":              {80, 443},
    "printer":             {9100, 631},
}

# OS guess keywords → device archetype
_OS_ARCHETYPE: list[tuple[str, str]] = [
    ("windows", "windows-workstation"),
    ("linux",   "linux-server"),
    ("cisco",   "router"),
]


class NegativeSpaceFingerprinter:
    name = "negative-space"
    feature_id = "B8"

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:  # noqa: ARG002
        _check_banner_absence(host)
        _check_ttl_vs_ports(host)
        _check_firewall_gaps(host)
        _check_expected_ports(host)
        return host

    # Required by Fingerprinter protocol
    @property
    def passive(self) -> bool:
        return True  # purely analytical — zero packets


def _check_banner_absence(host: Host) -> None:
    """SSH open but silent on connect - possible honeypot or access control.

    Only meaningful for services the TCP sweep (A3) actually connected to, since
    that is the one code path that attempts a banner read. Without this guard the
    check fired on every SSH host alive, because a service discovered passively or
    listed from a pcap has `banner is None` for the trivial reason that nobody ever
    opened a socket to it.
    """
    from scanner.core.models import ConfidenceTier, Finding, Severity
    for svc in host.services:
        if svc.port == 22 and svc.source != "A3":
            continue
        if svc.port == 22 and svc.banner is None and svc.state.value == "open":
            host.findings.append(Finding(
                id=f"B8-nobanner-{host.ip.replace('.', '_')}",
                title="SSH open with no banner — possible honeypot or restricted access",
                severity=Severity.LOW,
                confidence=ConfidenceTier.POTENTIAL,
                description=(
                    "Port 22 is open but returned no banner. Honeypots and bastion "
                    "hosts often suppress banners."
                ),
                source="B8",
            ))
            break


def _check_ttl_vs_ports(host: Host) -> None:
    """TTL=128 (Windows) but zero Windows service ports detected."""
    if not host.os_guess:
        return
    from scanner.core.models import ConfidenceTier, Finding, Severity
    os_lower = host.os_guess.lower()
    if "windows" in os_lower:
        windows_ports = {135, 139, 445, 3389, 5985}
        if not any(p in host.open_ports for p in windows_ports):
            host.findings.append(Finding(
                id=f"B8-ttlspoof-{host.ip.replace('.', '_')}",
                title="OS fingerprint mismatch: Windows TTL but no Windows ports",
                severity=Severity.LOW,
                confidence=ConfidenceTier.POTENTIAL,
                description=(
                    "TCP/IP stack suggests Windows (TTL~128) but no typical Windows "
                    "service ports are open. May indicate TTL spoofing, a firewall, or a VM."
                ),
                source="B8",
            ))


def _check_firewall_gaps(host: Host) -> None:
    """Detect filtered ports clustered between open ones — stateful firewall signal."""
    if not host.services:
        return
    from scanner.core.models import ConfidenceTier, Finding, PortState, Severity
    filtered = [s.port for s in host.services if s.state == PortState.FILTERED]
    if len(filtered) >= 5:
        host.findings.append(Finding(
            id=f"B8-fw-{host.ip.replace('.', '_')}",
            title=f"Stateful firewall likely ({len(filtered)} filtered ports)",
            severity=Severity.INFO,
            confidence=ConfidenceTier.PROBABLE,
            description=(
                f"{len(filtered)} ports return FILTERED (no RST, no ICMP unreachable). "
                "Consistent with a stateful firewall dropping unwanted traffic."
            ),
            source="B8",
        ))


_SERVICE_ONLY_PORTS = {53, 80, 443, 8080, 8443, 8000, 8888}


def _check_expected_ports(host: Host) -> None:
    """Flag if a device archetype is missing its expected service ports."""
    from scanner.core.models import ConfidenceTier, Finding, Severity
    archetype: str | None = None
    os_lower = (host.os_guess or "").lower()
    for keyword, arch in _OS_ARCHETYPE:
        if keyword in os_lower:
            archetype = arch
            break
    if archetype is None and host.device_type:
        archetype = f"{host.device_type}"

    expected = _EXPECTED_OPEN.get(archetype or "", set())
    missing = expected - set(host.open_ports)
    if not (missing and len(missing) == len(expected)):
        return

    # Suppress expected-ports finding on any internet-facing host that exposes ONLY
    # web/DNS-facing ports (80/443/8080/53 etc.). For such hosts, admin ports being
    # absent (Windows 135/445, Linux 22) is standard firewall policy — not an anomaly.
    # Applies regardless of OS archetype so CDN edge nodes, cloud LBs, and DNS resolvers
    # don't generate noise regardless of whether they fingerprint as linux-server or
    # windows-workstation (Google/Facebook CDN TTL=128 triggers the Windows archetype).
    if host.open_ports and set(host.open_ports).issubset(_SERVICE_ONLY_PORTS):
        return

    missing_str = ", ".join(str(p) for p in sorted(missing))
    host.findings.append(Finding(
        id=f"B8-missing-{host.ip.replace('.', '_')}",
        title=f"Expected ports absent for {archetype}: {missing_str}",
        severity=Severity.INFO,
        confidence=ConfidenceTier.POTENTIAL,
        description=(
            f"Device identified as {archetype} but none of the expected ports "
            f"({missing_str}) are open. May indicate firewall policy or wrong classification."
        ),
        source="B8",
    ))
