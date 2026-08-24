// Package scan is the active engine: concurrent TCP-connect probing, optional
// server-first banner reads, and per-host adaptive probe selection.
//
// It sends nothing a passive budget forbids, touches nothing the scope guard
// forbids, and — like the Python A3 discoverer it mirrors — proves liveness from
// the connect result itself: an accepted connect is a CONFIRMED open service, a
// refused connect proves the host is up with the port closed, and a timeout is
// no signal at all. Fabrication is impossible by construction because a Service
// only exists here as the direct record of a socket that actually opened.
package scan

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eyadgamer1/banshee/engine/internal/adaptive"
	"github.com/eyadgamer1/banshee/engine/internal/budget"
	"github.com/eyadgamer1/banshee/engine/internal/model"
	"github.com/eyadgamer1/banshee/engine/internal/scope"
)

// Banner read budget, matching the Python side: short on purpose, since a server
// that speaks first does so immediately and one that stays silent should cost
// almost nothing to rule out. The read sends no bytes — it only reads a greeting
// off a connection that is already open — so it adds no packet and does not
// change the scan's detection profile.
const (
	bannerBytes     = 256
	bannerReadDelay = 2 * time.Second
)

// wellKnown gives display names for the ports we probe. Display only; it never
// drives a decision.
var wellKnown = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 53: "domain", 80: "http",
	102: "iso-tsap", 135: "msrpc", 139: "netbios-ssn", 161: "snmp",
	443: "https", 445: "microsoft-ds", 502: "modbus", 515: "printer",
	548: "afp", 554: "rtsp", 631: "ipp", 1900: "ssdp", 2049: "nfs",
	3389: "ms-wbt-server", 5060: "sip", 8080: "http-alt", 8443: "https-alt",
	9100: "jetdirect",
}

// Options configure a run. Adaptive turns on the information-gain planner; with
// it off the engine probes the full candidate set like a conventional scanner,
// which is what the ground-truth conformance tests exercise.
type Options struct {
	Ports        []int
	Adaptive     bool
	Banners      bool
	PerHostProbe adaptive.Options // planner tuning when Adaptive is on
}

// Engine binds the safety boundary (scope), the noise boundary (budget) and the
// run options. One Engine scans many hosts concurrently; the budget it holds is
// the shared, global pacing authority across all of them.
type Engine struct {
	guard  *scope.Guard
	budget *budget.Budget
	opts   Options
}

func NewEngine(g *scope.Guard, b *budget.Budget, o Options) *Engine {
	return &Engine{guard: g, budget: b, opts: o}
}

// probeResult is one connect outcome, the atom everything else is built from.
type probeResult struct {
	port    int
	state   model.PortState
	banner  string
	upProof bool // connect or refused — either proves the host answered
}

// Run scans every in-scope target concurrently and returns a fully populated
// model.Result whose JSON is byte-compatible with the Python schema, so the
// existing Python ground-truth suite can validate this engine unchanged.
func (e *Engine) Run(ctx context.Context, targets []string) (*model.Result, error) {
	started := time.Now().UTC()
	inScope, outOfScope := e.guard.Filter(targets)

	res := &model.Result{
		Config: model.Config{
			Targets:  targets,
			Ports:    e.opts.Ports,
			Mode:     "active",
			Adaptive: e.opts.Adaptive,
			DryRun:   !e.budget.AllowActive,
		},
		Banner: e.guard.Banner,
		// Init non-nil so an empty scan serializes "hosts":[] not "hosts":null.
		// pydantic on the Python side rejects null for a list field; the passive
		// early-return below relies on this literal since it never reaches the
		// active assignment.
		Hosts:     []model.Host{},
		StartedAt: started,
		Stats: model.Stats{
			TargetsRequested:  len(targets),
			TargetsInScope:    len(inScope),
			TargetsOutOfScope: len(outOfScope),
		},
	}

	if !e.budget.AllowActive {
		// Passive budget: no active probe may be sent. Report honestly rather
		// than fabricating — zero packets, zero services, no hosts claimed up.
		fin := time.Now().UTC()
		res.FinishedAt = &fin
		return res, nil
	}

	var (
		mu       sync.Mutex
		hosts    []model.Host
		plan     = &model.PlanReport{}
		wg       sync.WaitGroup
		hostSlot = make(chan struct{}, hostParallelism(e.budget.Concurrency))
	)

	for _, ip := range inScope {
		wg.Add(1)
		hostSlot <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-hostSlot }()
			host, steps, verdict := e.scanHost(ctx, ip)
			if host == nil {
				return
			}
			mu.Lock()
			hosts = append(hosts, *host)
			if e.opts.Adaptive {
				plan.Steps = append(plan.Steps, steps...)
				plan.Verdicts = append(plan.Verdicts, verdict)
			}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	sort.Slice(hosts, func(i, j int) bool { return lessIP(hosts[i].IP, hosts[j].IP) })
	if hosts == nil {
		hosts = []model.Host{} // empty active scan: keep "hosts":[] on the wire
	}
	res.Hosts = hosts
	e.fillStats(res, plan)

	fin := time.Now().UTC()
	res.FinishedAt = &fin
	return res, nil
}

// hostParallelism caps how many hosts run at once. It is derived from the
// per-probe concurrency so the two multiply out to a sane socket count rather
// than exploding on a large target list; the budget's own delay/rate cap remains
// the true throttle on packets emitted.
func hostParallelism(conc int) int {
	if conc <= 0 {
		return 1
	}
	if conc > 64 {
		return 64
	}
	return conc
}

// scanHost probes one IP, adaptively or exhaustively, and returns the host (nil
// if it never answered), the planner's step log, and its verdict.
func (e *Engine) scanHost(ctx context.Context, ip string) (*model.Host, []model.PlanStep, model.HostVerdict) {
	now := time.Now().UTC()
	host := &model.Host{
		IP:    ip,
		State: model.StateDown,
		Names: map[string]string{},
		// Services/Findings init non-nil: a host that answers with no open ports
		// (refused connect) must still serialize "services":[]/"findings":[], not
		// null, or pydantic rejects the list fields on the Python side.
		Services:   []model.Service{},
		Findings:   []model.Finding{},
		Confidence: model.Probable,
		FirstSeen:  now,
		LastSeen:   now,
	}

	var steps []model.PlanStep
	var planner *adaptive.Planner
	if e.opts.Adaptive {
		planner = adaptive.New(e.opts.PerHostProbe)
	}

	answered := false
	record := func(pr probeResult) {
		if pr.upProof {
			answered = true
			host.State = model.StateUp
		}
		if pr.state == model.PortOpen {
			host.Services = append(host.Services, e.service(pr))
		}
	}

	if e.opts.Adaptive {
		for {
			choice, _, ok := planner.Next()
			if !ok {
				break
			}
			pr := e.probe(ctx, ip, choice.Port)
			record(pr)
			planner.Observe(choice.Port, outcome(pr.state))
			top, prob := planner.Verdict()
			steps = append(steps, model.PlanStep{
				IP: ip, Port: choice.Port,
				Bits: round(choice.Bits), Risk: choice.Risk,
				Outcome: string(pr.state), PostTop: string(top), PostProb: round(prob),
			})
		}
	} else {
		for _, port := range e.candidatePorts() {
			record(e.probe(ctx, ip, port))
		}
	}

	if !answered {
		return nil, nil, model.HostVerdict{}
	}

	sort.Slice(host.Services, func(i, j int) bool { return host.Services[i].Port < host.Services[j].Port })

	verdict := model.HostVerdict{IP: ip}
	if e.opts.Adaptive {
		top, prob := planner.Verdict()
		dt := string(top)
		host.DeviceType = &dt
		verdict = model.HostVerdict{
			IP: ip, Class: dt, Confidence: round(prob),
			Probes: planner.Probes(), StoppedBy: stopReason(planner),
		}
	}
	return host, steps, verdict
}

func (e *Engine) candidatePorts() []int {
	if len(e.opts.Ports) > 0 {
		return e.opts.Ports
	}
	// Same default high-signal set the Python A3 sweep uses.
	return []int{80, 443, 22, 445, 3389, 139, 135, 8080, 23, 53}
}

// probe performs one budgeted, scope-checked TCP connect. Scope is re-checked
// here as defense in depth even though Run already filtered — a bug that added a
// target after filtering must still not put a packet on the wire.
func (e *Engine) probe(ctx context.Context, ip string, port int) probeResult {
	pr := probeResult{port: port, state: model.PortFiltered}
	if !e.guard.InScope(ip) || !e.budget.CanSend() {
		return pr
	}
	if err := e.budget.Acquire(ctx); err != nil {
		return pr
	}
	defer e.budget.Release()
	if err := e.budget.Throttle(ctx); err != nil {
		return pr
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: e.budget.ConnectTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		// A refusal proves the host is up with the port closed; a timeout or
		// unreachable is no signal, so it stays filtered.
		if isRefused(err) {
			pr.state = model.PortClosed
			pr.upProof = true
		}
		return pr
	}
	defer conn.Close()

	pr.state = model.PortOpen
	pr.upProof = true
	if e.opts.Banners {
		pr.banner = readBanner(conn)
	}
	return pr
}

// readBanner reads a server-speaks-first greeting from an already-open
// connection. It writes nothing, so it costs no extra packet.
func readBanner(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(bannerReadDelay))
	r := bufio.NewReader(conn)
	buf := make([]byte, bannerBytes)
	n, err := r.Read(buf)
	if n == 0 || (err != nil && !errors.Is(err, net.ErrClosed) && n == 0) {
		return ""
	}
	return strings.TrimSpace(string(buf[:n]))
}

func (e *Engine) service(pr probeResult) model.Service {
	svc := model.Service{
		Port: pr.port, Proto: "tcp", State: model.PortOpen,
		Confidence: model.Confirmed, Source: "A3",
	}
	if name, ok := wellKnown[pr.port]; ok {
		svc.Name = model.Ptr(name)
	}
	if pr.banner != "" {
		svc.Banner = model.Ptr(pr.banner)
	}
	return svc
}

func (e *Engine) fillStats(res *model.Result, plan *model.PlanReport) {
	res.Stats.HostsUp = len(res.Hosts)
	for _, h := range res.Hosts {
		res.Stats.ServicesFound += len(h.Services)
		res.Stats.Findings += len(h.Findings)
	}
	res.Stats.PacketsSent = e.budget.PacketsSent()

	if !e.opts.Adaptive {
		return
	}
	// Stable sort by IP only: it groups a host's steps together for readability
	// while preserving the order the planner actually chose them, which is the
	// story the audit trail exists to tell. Sorting by port would erase it.
	sort.SliceStable(plan.Steps, func(i, j int) bool {
		return lessIP(plan.Steps[i].IP, plan.Steps[j].IP)
	})
	sort.Slice(plan.Verdicts, func(i, j int) bool { return lessIP(plan.Verdicts[i].IP, plan.Verdicts[j].IP) })
	plan.ProbesSent = len(plan.Steps)
	full := adaptive.New(e.opts.PerHostProbe).FullRisk()
	perHostFull := full * float64(len(res.Hosts))
	plan.ProbesPlanned = len(adaptive.New(e.opts.PerHostProbe).Candidates()) * len(res.Hosts)
	plan.ProbesSaved = plan.ProbesPlanned - plan.ProbesSent
	plan.RiskOfFullScan = round(perHostFull)
	var spent float64
	for _, s := range plan.Steps {
		spent += s.Risk
	}
	plan.RiskSpent = round(spent)
	res.Plan = plan
}

func outcome(s model.PortState) adaptive.Outcome {
	switch s {
	case model.PortOpen:
		return adaptive.Open
	case model.PortClosed:
		return adaptive.Closed
	default:
		return adaptive.Filtered
	}
}

func stopReason(p *adaptive.Planner) string {
	_, reason, ok := p.Next()
	if ok {
		return "budget" // stopped by the outer loop, not the planner
	}
	return reason
}

func isRefused(err error) bool {
	return errors.Is(err, syscallRefused) || strings.Contains(strings.ToLower(err.Error()), "refused")
}

func round(f float64) float64 {
	return float64(int64(f*1000+0.5)) / 1000
}

// lessIP orders IPv4/IPv6 addresses by their bytes so host output is stable and
// diffable, not lexical ("10" before "9").
func lessIP(a, b string) bool {
	ipa, ipb := net.ParseIP(a), net.ParseIP(b)
	switch {
	case ipa == nil && ipb == nil:
		return a < b
	case ipa == nil:
		return true
	case ipb == nil:
		return false
	}
	ba, bb := ipa.To16(), ipb.To16()
	for i := range ba {
		if ba[i] != bb[i] {
			return ba[i] < bb[i]
		}
	}
	return false
}
