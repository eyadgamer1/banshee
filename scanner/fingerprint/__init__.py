"""Fingerprint module — enriches hosts with identity/service data (B1–B13).

Integration contract: `get_fingerprinters(cfg)` returns ordered Fingerprinter
instances. Passive enrichers always run; active ones respect budget/flags.

P1: B1 oui, B2 dhcp, B6 name-resolve.
P2: B3 tcp/ip stack, B4 TLS JA4, B5 device classifier.
P4: B7 clock-skew, B8 negative-space.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scanner.fingerprint.classifier import DeviceClassifier
from scanner.fingerprint.clockskew import ClockSkewFingerprinter
from scanner.fingerprint.dhcp import DhcpFingerprinter
from scanner.fingerprint.names import NameResolver
from scanner.fingerprint.negspace import NegativeSpaceFingerprinter
from scanner.fingerprint.oui import OuiFingerprinter
from scanner.fingerprint.tcpip import TcpIpFingerprinter
from scanner.fingerprint.tls import TlsJa4Fingerprinter

if TYPE_CHECKING:
    from scanner.core.interfaces import Fingerprinter
    from scanner.core.models import ScanConfig

__all__ = [
    "ClockSkewFingerprinter",
    "DeviceClassifier",
    "DhcpFingerprinter",
    "NameResolver",
    "NegativeSpaceFingerprinter",
    "OuiFingerprinter",
    "TcpIpFingerprinter",
    "TlsJa4Fingerprinter",
    "get_fingerprinters",
]


def get_fingerprinters(cfg: ScanConfig) -> list[Fingerprinter]:
    """Return ordered fingerprinters for this run."""
    fingerprinters: list[Fingerprinter] = [OuiFingerprinter(), DhcpFingerprinter()]
    if cfg.names:
        fingerprinters.append(NameResolver())
    # B3 and B4 need raw sockets — skip in passive mode
    from scanner.core.models import ScanMode

    if cfg.mode != ScanMode.PASSIVE:
        fingerprinters.append(TcpIpFingerprinter())
        fingerprinters.append(TlsJa4Fingerprinter(iface=cfg.iface))
    # B5 classifier is always safe (local, no network)
    if cfg.classify:
        fingerprinters.append(DeviceClassifier())
    # B7 clock-skew — active, skipped in passive mode
    if cfg.mode != ScanMode.PASSIVE:
        fingerprinters.append(ClockSkewFingerprinter())
    # B8 negative-space — purely analytical, always safe
    fingerprinters.append(NegativeSpaceFingerprinter())
    return fingerprinters
