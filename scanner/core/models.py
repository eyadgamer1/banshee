"""Core data models — the contract every module builds against.

Pydantic v2 models shared across discovery, fingerprint, correlate, risk,
intel, report, and store. No I/O, no network, no third-party probing here —
pure data shapes only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ConfidenceTier(StrEnum):
    """Evidence strength for any asserted fact (host, service, finding).

    CONFIRMED  — direct observation (open TCP connect, returned banner, ARP reply).
    PROBABLE   — strong inference from correlated signals (OUI + DHCP + open ports).
    POTENTIAL  — weak / single-signal / LLM-only inference. Never auto-escalated.
    """

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POTENTIAL = "potential"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanMode(StrEnum):
    """Intensity dial (separate from verbosity).

    PASSIVE     — zero active packets; observe only.
    STEALTH     — minimal, rate-limited active probes.
    NORMAL      — standard active discovery + fingerprint.
    AGGRESSIVE  — full probe set, max concurrency.
    """

    PASSIVE = "passive"
    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


class HostState(StrEnum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class Proto(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class Service(BaseModel):
    """A single observed service/port on a host."""

    port: int
    proto: Proto = Proto.TCP
    state: PortState = PortState.OPEN
    name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    confidence: ConfidenceTier = ConfidenceTier.CONFIRMED
    source: str = ""  # feature ID that produced this (e.g. "A3", "B2")


class Finding(BaseModel):
    """A noteworthy observation about a host — not an exploit, just intel."""

    id: str
    title: str
    severity: Severity = Severity.INFO
    confidence: ConfidenceTier = ConfidenceTier.POTENTIAL
    description: str = ""
    evidence: str | None = None
    source: str = ""  # feature ID
    is_llm_inferred: bool = False  # if True, capped at POTENTIAL by policy


class Host(BaseModel):
    """A discovered network asset, enriched by fingerprint/correlate/risk."""

    ip: str
    state: HostState = HostState.UNKNOWN
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    device_type: str | None = None
    # name-resolve (B6) sources kept separate for evidence/replay
    names: dict[str, str] = Field(default_factory=dict)  # {"rdns": ..., "mdns": ...}
    services: list[Service] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    confidence: ConfidenceTier = ConfidenceTier.POTENTIAL
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)

    @property
    def best_name(self) -> str:
        """Friendliest display name available."""
        return (
            self.hostname
            or self.names.get("mdns")
            or self.names.get("rdns")
            or self.names.get("netbios")
            or self.ip
        )

    @property
    def open_ports(self) -> list[int]:
        return sorted(s.port for s in self.services if s.state == PortState.OPEN)


class ScanConfig(BaseModel):
    """Resolved run configuration — produced by the CLI, consumed by the engine."""

    targets: list[str] = Field(default_factory=list)
    iface: str | None = None
    pcap: str | None = None

    # intensity dial
    mode: ScanMode = ScanMode.PASSIVE
    timing: int = 3  # -T0..T5
    rate: int | None = None  # packets/sec cap
    timeout_ms: int = 3000
    retries: int = 1
    threads: int | None = None
    max_detect_risk: int | None = None  # 0 = passive only

    # feature toggles
    fingerprint: bool = True
    classify: bool = False
    names: bool = True
    enrich: bool = False
    vuln: bool = False
    graph: bool = False
    agentic: bool = False

    # safety
    scope_file: str = "config/scope.yaml"
    dry_run: bool = False
    audit_log: str | None = None

    # output
    out_txt: str | None = None
    out_json: str | None = None
    out_xml: str | None = None
    out_html: str | None = None
    out_csv: str | None = None
    out_sarif: str | None = None

    # display
    verbosity: int = 0  # -v count; negative = quiet
    silent: bool = False
    no_color: bool = False


class ScanStats(BaseModel):
    targets_requested: int = 0
    targets_in_scope: int = 0
    targets_out_of_scope: int = 0
    hosts_up: int = 0
    services_found: int = 0
    findings: int = 0
    packets_sent: int = 0


class ScanResult(BaseModel):
    """Top-level scan output — serialized by every report writer (E3)."""

    config: ScanConfig
    banner: str = ""
    hosts: list[Host] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None

    @property
    def up_hosts(self) -> list[Host]:
        return [h for h in self.hosts if h.state == HostState.UP]
