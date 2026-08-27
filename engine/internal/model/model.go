// Package model mirrors the Python ScanResult schema byte-for-byte on the wire.
//
// This is deliberate and load-bearing: the Python test suite — in particular
// tests/test_ground_truth.py, which binds real listeners and asserts the reported
// ports equal the bound ports exactly — becomes the conformance oracle for this
// engine. Any drift in these tags is a drift in behaviour, and the ground-truth
// suite will catch it.
package model

import "time"

type ConfidenceTier string

const (
	Confirmed ConfidenceTier = "confirmed"
	Probable  ConfidenceTier = "probable"
	Potential ConfidenceTier = "potential"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

type HostState string

const (
	StateUp      HostState = "up"
	StateDown    HostState = "down"
	StateUnknown HostState = "unknown"
)

type PortState string

const (
	PortOpen     PortState = "open"
	PortClosed   PortState = "closed"
	PortFiltered PortState = "filtered"
	// PortOpenFiltered is UDP's honest "cannot tell": a silent port may be open
	// (service ignored our probe) or filtered. We never collapse it to "open".
	PortOpenFiltered PortState = "open|filtered"
)

type Service struct {
	Port       int            `json:"port"`
	Proto      string         `json:"proto"`
	State      PortState      `json:"state"`
	Name       *string        `json:"name"`
	Product    *string        `json:"product"`
	Version    *string        `json:"version"`
	Banner     *string        `json:"banner"`
	Confidence ConfidenceTier `json:"confidence"`
	Source     string         `json:"source"`
}

type Finding struct {
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Severity      Severity       `json:"severity"`
	Confidence    ConfidenceTier `json:"confidence"`
	Description   string         `json:"description"`
	Evidence      *string        `json:"evidence"`
	Source        string         `json:"source"`
	IsLLMInferred bool           `json:"is_llm_inferred"`
	SSVCPriority  *string        `json:"ssvc_priority"`
}

type Host struct {
	IP         string            `json:"ip"`
	State      HostState         `json:"state"`
	Hostname   *string           `json:"hostname"`
	MAC        *string           `json:"mac"`
	Vendor     *string           `json:"vendor"`
	OSGuess    *string           `json:"os_guess"`
	DeviceType *string           `json:"device_type"`
	Names      map[string]string `json:"names"`
	Services   []Service         `json:"services"`
	Findings   []Finding         `json:"findings"`
	Confidence ConfidenceTier    `json:"confidence"`
	FirstSeen  time.Time         `json:"first_seen"`
	LastSeen   time.Time         `json:"last_seen"`
}

type Stats struct {
	TargetsRequested  int `json:"targets_requested"`
	TargetsInScope    int `json:"targets_in_scope"`
	TargetsOutOfScope int `json:"targets_out_of_scope"`
	HostsUp           int `json:"hosts_up"`
	ServicesFound     int `json:"services_found"`
	Findings          int `json:"findings"`
	PacketsSent       int `json:"packets_sent"`
}

// Config carries only the fields a consumer needs to tell "clean" from "that pass
// never ran". The Python side owns the full ScanConfig; this is the engine's slice.
type Config struct {
	Targets     []string `json:"targets"`
	Ports       []int    `json:"ports"`
	Mode        string   `json:"mode"`
	Timing      int      `json:"timing"`
	Adaptive    bool     `json:"adaptive"`
	Fingerprint bool     `json:"fingerprint"`
	DryRun      bool     `json:"dry_run"`
	ScopeFile   string   `json:"scope_file"`
}

type Result struct {
	Config     Config     `json:"config"`
	Banner     string     `json:"banner"`
	Hosts      []Host     `json:"hosts"`
	Stats      Stats      `json:"stats"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	// Engine-only: the adaptive planner's account of what it chose and why.
	Plan *PlanReport `json:"plan,omitempty"`
}

// PlanReport is the audit trail for adaptive probing: which probes were selected,
// in what order, and what each one bought in bits. Without this the planner is an
// opaque optimisation; with it, the operator can defend the scan.
type PlanReport struct {
	ProbesPlanned  int           `json:"probes_planned"`
	ProbesSent     int           `json:"probes_sent"`
	ProbesSaved    int           `json:"probes_saved"`
	RiskSpent      float64       `json:"risk_spent"`
	RiskOfFullScan float64       `json:"risk_of_full_scan"`
	Steps          []PlanStep    `json:"steps"`
	Verdicts       []HostVerdict `json:"verdicts"`
}

type PlanStep struct {
	IP       string  `json:"ip"`
	Port     int     `json:"port"`
	Bits     float64 `json:"expected_bits"`
	Risk     float64 `json:"risk"`
	Outcome  string  `json:"outcome"`
	PostTop  string  `json:"posterior_top"`
	PostProb float64 `json:"posterior_prob"`
}

type HostVerdict struct {
	IP         string  `json:"ip"`
	Class      string  `json:"class"`
	Confidence float64 `json:"confidence"`
	Probes     int     `json:"probes"`
	StoppedBy  string  `json:"stopped_by"`
}

func Ptr[T any](v T) *T { return &v }
