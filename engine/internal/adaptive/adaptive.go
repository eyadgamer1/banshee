// Package adaptive selects probes by expected information gain per unit of
// detection risk.
//
// Every other scanner picks ports from a static, global frequency list: nmap's
// --top-ports is the same 1,000 ports for a domestic printer and a border
// firewall, ordered by how often that port was open across the whole internet in
// 2008. It cannot use what it already learned about *this* host, and it has no
// notion that probing 445 costs more than probing 443 on a monitored network.
//
// This planner does both. It carries a posterior over device classes per host,
// and before each probe it computes, for every candidate port:
//
//	EIG(p) = H(prior) - [ P(open)*H(post | open) + P(closed)*H(post | closed) ]
//
// which is the number of bits of class uncertainty the probe is expected to
// resolve, and then selects
//
//	argmax  EIG(p) / cost(p)
//
// where cost is that port's detection risk. It stops as soon as the posterior
// crosses a confidence threshold, so a host that is obviously a printer costs
// three packets instead of a thousand. The saved probes are the point: fewer
// packets means less noise on the wire, fewer IDS signatures tripped, and a scan
// that finishes on a /16 within an engagement window.
//
// Every choice is recorded in a model.PlanReport so the operator can defend the
// scan afterwards — which probe was sent, what it was expected to buy in bits,
// what it cost in risk, and what the posterior did in response.
package adaptive

import (
	"math"
	"sort"
)

// Class is a device archetype the planner reasons about. Kept deliberately
// coarse: the goal is to steer probe selection, not to be the final classifier.
type Class string

const (
	Router      Class = "router"
	Switch      Class = "switch"
	AccessPoint Class = "access-point"
	Printer     Class = "printer"
	Camera      Class = "camera"
	IoT         Class = "iot"
	Server      Class = "server"
	Workstation Class = "workstation"
	NAS         Class = "nas"
	VoIP        Class = "voip"
	ICS         Class = "ics"
	Unknown     Class = "unknown"
)

// Classes is the fixed, ordered class list. Order is fixed so that planning is
// deterministic — Go map iteration is not, and a scanner whose probe order
// changes between runs cannot be diffed against its own previous run.
var Classes = []Class{
	Router, Switch, AccessPoint, Printer, Camera, IoT,
	Server, Workstation, NAS, VoIP, ICS, Unknown,
}

// priors are the starting beliefs for a host with no evidence. Roughly the mix
// of an enterprise LAN: mostly workstations, some servers, a thin tail of
// appliances. They are a starting point, not a claim — two probes move them far
// more than the priors themselves do.
var priors = map[Class]float64{
	Router: 0.06, Switch: 0.04, AccessPoint: 0.04, Printer: 0.05,
	Camera: 0.05, IoT: 0.08, Server: 0.20, Workstation: 0.30,
	NAS: 0.04, VoIP: 0.04, ICS: 0.02, Unknown: 0.08,
}

// likelihood[port][class] = P(port open | host is of class).
//
// These are conditional probabilities, not port lists: 0.9 means nine of ten
// such devices answer there. A class absent from a port's row falls back to
// baseline, which keeps any single observation from driving a class to exactly
// zero and freezing it out of the posterior forever.
const baseline = 0.03

var likelihood = map[int]map[Class]float64{
	21:    {NAS: 0.35, Printer: 0.20, ICS: 0.25, Camera: 0.15, Router: 0.10},
	22:    {Server: 0.75, Router: 0.45, NAS: 0.60, IoT: 0.20, Switch: 0.35, AccessPoint: 0.30, Workstation: 0.08},
	23:    {Router: 0.30, Switch: 0.35, ICS: 0.45, Camera: 0.25, IoT: 0.20, Printer: 0.10},
	53:    {Router: 0.55, Server: 0.25, AccessPoint: 0.20},
	80:    {Router: 0.85, Printer: 0.80, Camera: 0.90, IoT: 0.70, Server: 0.65, NAS: 0.85, AccessPoint: 0.80, Switch: 0.60, VoIP: 0.70, ICS: 0.40, Workstation: 0.10},
	102:   {ICS: 0.55},
	135:   {Workstation: 0.85, Server: 0.70},
	139:   {Workstation: 0.70, Server: 0.55, NAS: 0.65, Printer: 0.25},
	161:   {Router: 0.60, Switch: 0.70, Printer: 0.55, AccessPoint: 0.55, ICS: 0.35, VoIP: 0.30},
	443:   {Server: 0.70, Router: 0.65, Camera: 0.55, NAS: 0.70, AccessPoint: 0.60, IoT: 0.35, VoIP: 0.40, Workstation: 0.08},
	445:   {Workstation: 0.88, Server: 0.72, NAS: 0.70},
	502:   {ICS: 0.50},
	515:   {Printer: 0.60},
	548:   {NAS: 0.45},
	554:   {Camera: 0.85, IoT: 0.10},
	631:   {Printer: 0.70, Workstation: 0.25, Server: 0.15},
	1900:  {IoT: 0.55, Camera: 0.35, NAS: 0.40, Router: 0.35, Printer: 0.20},
	2049:  {NAS: 0.40, Server: 0.30},
	3389:  {Workstation: 0.35, Server: 0.40},
	5060:  {VoIP: 0.90, Router: 0.10},
	5357:  {Workstation: 0.45, Printer: 0.30},
	8080:  {Camera: 0.45, IoT: 0.40, Server: 0.35, Router: 0.30, ICS: 0.30, Printer: 0.15},
	8443:  {Server: 0.30, NAS: 0.35, Camera: 0.25, AccessPoint: 0.30},
	9100:  {Printer: 0.90},
	20000: {ICS: 0.30},
	47808: {ICS: 0.35},
}

// riskOf is the detection cost of probing a port, 1 (quiet) to 10 (loud), and it
// is what makes this planner different from a pure information-gain one. A TCP
// connect to 443 is indistinguishable from ordinary web traffic. A connect to
// 445 or 3389 lands in Windows security logs, trips lateral-movement rules in
// every commercial EDR, and is exactly what a blue team greps for. Ports not
// listed default to riskDefault.
const riskDefault = 3.0

var riskOf = map[int]float64{
	80: 1.0, 443: 1.0, 8080: 1.5, 8443: 1.5,
	53: 2.0, 22: 2.5, 631: 2.0, 515: 2.0, 9100: 2.0,
	1900: 2.0, 161: 2.5, 554: 2.5, 5060: 2.5, 548: 3.0, 2049: 3.0,
	21: 4.0, 139: 5.0, 5357: 4.0,
	23: 6.0, 3389: 7.0, 445: 8.0,
	102: 9.0, 502: 9.0, 20000: 9.0, 47808: 9.0, // ICS: a probe can disrupt the process, not only alert on it
}

// Outcome is what a probe actually observed. Filtered is not evidence about the
// service — a firewall dropped the packet — so it must not update the posterior.
type Outcome string

const (
	Open     Outcome = "open"
	Closed   Outcome = "closed"
	Filtered Outcome = "filtered"
)

// Options tune when the planner stops. Both stops matter: Confidence ends the
// run early on an easy host, MaxRisk caps the total noise on a hard one.
type Options struct {
	// Confidence is the posterior probability at which the class is called and
	// probing stops. 0.85 by default.
	Confidence float64
	// MaxProbes caps probes per host regardless of confidence. 0 means the
	// length of the candidate port list.
	MaxProbes int
	// MaxRisk caps total detection risk spent per host. 0 means unlimited.
	MaxRisk float64
	// MinBits stops probing when the best remaining probe would buy less than
	// this many bits — the point past which packets are being spent for nothing.
	MinBits float64
	// Ports restricts the candidate set. Empty means every port in the model.
	Ports []int
}

func (o Options) withDefaults() Options {
	if o.Confidence <= 0 || o.Confidence >= 1 {
		o.Confidence = 0.85
	}
	if o.MinBits <= 0 {
		o.MinBits = 0.01
	}
	return o
}

// Planner holds one host's belief state. Not safe for concurrent use; give each
// host its own — they are cheap, and hosts are scanned in parallel.
type Planner struct {
	opts       Options
	posterior  map[Class]float64
	candidates []int
	probed     map[int]bool
	spentRisk  float64
	probes     int
}

func New(o Options) *Planner {
	o = o.withDefaults()
	p := &Planner{
		opts:      o,
		posterior: make(map[Class]float64, len(Classes)),
		probed:    make(map[int]bool),
	}
	for _, c := range Classes {
		p.posterior[c] = priors[c]
	}
	if len(o.Ports) > 0 {
		p.candidates = append(p.candidates, o.Ports...)
	} else {
		for port := range likelihood {
			p.candidates = append(p.candidates, port)
		}
	}
	sort.Ints(p.candidates)
	if p.opts.MaxProbes <= 0 {
		p.opts.MaxProbes = len(p.candidates)
	}
	return p
}

func pOpen(port int, class Class) float64 {
	row, ok := likelihood[port]
	if !ok {
		return baseline
	}
	v, ok := row[class]
	if !ok {
		return baseline
	}
	return v
}

func portRisk(port int) float64 {
	if r, ok := riskOf[port]; ok {
		return r
	}
	return riskDefault
}

func entropy(dist map[Class]float64) float64 {
	var h float64
	for _, p := range dist {
		if p > 0 {
			h -= p * math.Log2(p)
		}
	}
	return h
}

// update returns the posterior after observing `port` in state `open`. It never
// mutates the receiver, so the same function serves both the hypothetical
// lookahead in Bits and the real update in Observe — which means the bits the
// planner reports are computed by the identical code path that later applies
// them. A separate "predicted" path would be free to drift from the real one.
func (p *Planner) update(port int, open bool) map[Class]float64 {
	out := make(map[Class]float64, len(p.posterior))
	var total float64
	for _, c := range Classes {
		l := pOpen(port, c)
		if !open {
			l = 1 - l
		}
		v := p.posterior[c] * l
		out[c] = v
		total += v
	}
	if total <= 0 {
		// Degenerate evidence. Keep the prior rather than emitting NaNs.
		for _, c := range Classes {
			out[c] = p.posterior[c]
		}
		return out
	}
	for c := range out {
		out[c] /= total
	}
	return out
}

// predictOpen is the prior predictive P(port open) under the current posterior.
func (p *Planner) predictOpen(port int) float64 {
	var q float64
	for _, c := range Classes {
		q += p.posterior[c] * pOpen(port, c)
	}
	return q
}

// Bits is the expected information gain of probing a port, in bits.
func (p *Planner) Bits(port int) float64 {
	q := p.predictOpen(port)
	h := entropy(p.posterior)
	expected := q*entropy(p.update(port, true)) + (1-q)*entropy(p.update(port, false))
	gain := h - expected
	if gain < 0 {
		// Only reachable through floating-point noise; EIG is non-negative.
		return 0
	}
	return gain
}

// Choice is the planner's recommendation for the next probe.
type Choice struct {
	Port  int
	Bits  float64
	Risk  float64
	Value float64 // Bits per unit risk — the quantity actually maximised.
}

// Next returns the most informative affordable probe, or ok=false when the
// planner is done and the reason it stopped.
func (p *Planner) Next() (Choice, string, bool) {
	if p.Confidence() >= p.opts.Confidence {
		return Choice{}, "confidence", false
	}
	if p.probes >= p.opts.MaxProbes {
		return Choice{}, "probe-cap", false
	}

	best := Choice{Value: -1}
	affordable := false
	for _, port := range p.candidates {
		if p.probed[port] {
			continue
		}
		r := portRisk(port)
		if p.opts.MaxRisk > 0 && p.spentRisk+r > p.opts.MaxRisk {
			continue
		}
		affordable = true
		bits := p.Bits(port)
		value := bits / r
		// Ties break toward the lower port number, which `candidates` being
		// sorted gives for free — again so two runs plan identically.
		if value > best.Value {
			best = Choice{Port: port, Bits: bits, Risk: r, Value: value}
		}
	}

	if !affordable {
		if p.opts.MaxRisk > 0 {
			return Choice{}, "risk-budget", false
		}
		return Choice{}, "exhausted", false
	}
	if best.Bits < p.opts.MinBits {
		return Choice{}, "no-information", false
	}
	return best, "", true
}

// Observe folds a probe result into the posterior. A Filtered result is recorded
// as spent risk and a used probe, but it moves no belief: a dropped packet says
// something about the firewall, not about the host behind it.
func (p *Planner) Observe(port int, outcome Outcome) {
	if p.probed[port] {
		return
	}
	p.probed[port] = true
	p.probes++
	p.spentRisk += portRisk(port)
	switch outcome {
	case Open:
		p.posterior = p.update(port, true)
	case Closed:
		p.posterior = p.update(port, false)
	case Filtered:
	}
}

// Verdict is the current best class and its posterior probability.
func (p *Planner) Verdict() (Class, float64) {
	best, bestP := Unknown, -1.0
	for _, c := range Classes {
		if v := p.posterior[c]; v > bestP {
			best, bestP = c, v
		}
	}
	return best, bestP
}

func (p *Planner) Confidence() float64 { _, c := p.Verdict(); return c }
func (p *Planner) Probes() int         { return p.probes }
func (p *Planner) SpentRisk() float64  { return p.spentRisk }

// Posterior returns a copy of the current belief, for reporting.
func (p *Planner) Posterior() map[Class]float64 {
	out := make(map[Class]float64, len(p.posterior))
	for c, v := range p.posterior {
		out[c] = v
	}
	return out
}

// FullRisk is the detection cost of probing every candidate port, i.e. what a
// conventional fixed-list scan of the same port set would have spent. It is the
// denominator for the saving the planner claims, and reporting it is what keeps
// that claim honest.
func (p *Planner) FullRisk() float64 {
	var total float64
	for _, port := range p.candidates {
		total += portRisk(port)
	}
	return total
}

func (p *Planner) Candidates() []int { return append([]int(nil), p.candidates...) }
