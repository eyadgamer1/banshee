"""Core data models — the contract every module builds against.

Pydantic v2 models shared across discovery, fingerprint, correlate, risk,
intel, report, and store. No I/O, no network, no third-party probing here —
pure data shapes only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


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

    STEALTH     — minimal, rate-limited active probes.
    NORMAL      — standard active discovery + fingerprint.
    AGGRESSIVE  — full probe set, max concurrency.
    """

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
    # UDP's honest "cannot tell": a silent port may be open (the service ignored
    # our probe) or filtered. Never collapsed to OPEN, and excluded from open_ports.
    OPEN_FILTERED = "open|filtered"


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
    ssvc_priority: str | None = None  # C5 SSVC action tier (IMMEDIATE/OUT_OF_CYCLE/SCHEDULED/DEFER)


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

    @field_validator("services", "findings", mode="before")
    @classmethod
    def _null_to_empty_list(cls, v: object) -> object:
        """Accept null for an empty collection from any JSON producer.

        Go (the ``--engine go`` core) marshals a nil slice as JSON ``null``; the
        default_factory only fires when the key is absent, not when it is present
        and null. Coercing here lets the Go bridge deserialize with no special-casing.
        """
        return [] if v is None else v

    @field_validator("names", mode="before")
    @classmethod
    def _null_to_empty_dict(cls, v: object) -> object:
        return {} if v is None else v

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
    iface: str | None = None  # capture NIC for raw-socket fingerprinters (e.g. TLS JA4)

    # intensity dial
    mode: ScanMode = ScanMode.NORMAL
    timing: int = 3  # -T0..T5
    rate: int | None = None  # packets/sec cap
    # None => inherit from the -T timing template; an explicit value overrides it
    # (0 is a legal override, e.g. --retries 0 at -T5).
    timeout_ms: int | None = None
    retries: int | None = None
    threads: int | None = None
    max_detect_risk: int | None = None  # 0 = no active probes (noise ceiling)

    # active-scan engine: "python" (default, in-process asyncio) or "go" (the fast,
    # low-memory static core; see scanner/engine_go.py). Passive/analysis/report
    # stages are always Python regardless.
    engine: str = "python"
    # adaptive information-gain probe planner — Go engine only, for now. Selects
    # probes by bits-per-unit-risk and stops early once a device class is confident.
    adaptive: bool = False
    # UDP scan (Go engine only): probe ports over UDP. A silent port is reported
    # open|filtered — never plain open. Mutually exclusive with adaptive (which is TCP).
    udp: bool = False
    # service/version identification (Go engine only, -sV): probe silent open TCP
    # ports for a version banner. Product/version are set only on a signature match,
    # never inferred from the port. TCP-only, so not combined with udp.
    service_scan: bool = False

    # port selection — None inherits the discoverer's default probe set
    ports: list[int] | None = None

    # Feature toggles. Every one of these is written by the CLI and serialised
    # into the report, so a consumer can tell "clean" from "that pass never ran".
    fingerprint: bool = True
    classify: bool = True
    names: bool = True
    enrich: bool = False
    ssvc: bool = False
    plugins: bool = False
    agentic: bool = False
    # C8 deception/honeypot signal analysis — local, zero packets. Emits at most
    # one POTENTIAL finding per host from already-collected data.
    deception: bool = False

    # persistence
    db: str | None = None
    baseline: bool = False

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


class PlanStep(BaseModel):
    """One adaptive probe: what was chosen, what it bought, and the posterior after."""

    ip: str
    port: int
    expected_bits: float
    risk: float
    outcome: str
    posterior_top: str
    posterior_prob: float


class PlanVerdict(BaseModel):
    """Per-host adaptive conclusion: device class, confidence, and why it stopped."""

    model_config = ConfigDict(populate_by_name=True)

    ip: str
    device_class: str = Field(alias="class")  # 'class' is reserved; Go emits "class"
    confidence: float
    probes: int
    stopped_by: str


class ScanPlan(BaseModel):
    """Audit trail for an adaptive scan (Go engine): what was probed and what it saved.

    Populated only when the Go engine ran with --adaptive; None on the Python path.
    Lets the operator defend the scan — probes skipped and detection risk avoided.
    """

    probes_planned: int = 0
    probes_sent: int = 0
    probes_saved: int = 0
    risk_spent: float = 0.0
    risk_of_full_scan: float = 0.0
    steps: list[PlanStep] = Field(default_factory=list)
    verdicts: list[PlanVerdict] = Field(default_factory=list)

    @field_validator("steps", "verdicts", mode="before")
    @classmethod
    def _null_to_empty_list(cls, v: object) -> object:
        return [] if v is None else v


class ScanResult(BaseModel):
    """Top-level scan output — serialized by every report writer (E3)."""

    config: ScanConfig
    banner: str = ""
    hosts: list[Host] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    plan: ScanPlan | None = None  # adaptive audit trail; set only by the Go engine

    @field_validator("hosts", mode="before")
    @classmethod
    def _null_to_empty_list(cls, v: object) -> object:
        """Tolerate a null hosts array from a JSON producer (see Host validators)."""
        return [] if v is None else v

    @property
    def up_hosts(self) -> list[Host]:
        return [h for h in self.hosts if h.state == HostState.UP]
