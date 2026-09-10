package scan

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eyadgamer1/banshee/engine/internal/adaptive"
	"github.com/eyadgamer1/banshee/engine/internal/budget"
	"github.com/eyadgamer1/banshee/engine/internal/scope"
)

// scopeWith builds a loopback scope guard with an explicit max_ports_per_host,
// so the cap that used to be parsed-and-ignored can be exercised end to end.
func scopeWith(t *testing.T, maxPorts int) *scope.Guard {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.yaml")
	body := "banner: TEST\nallowlist:\n  - 127.0.0.1/8\n  - 192.0.2.0/24\ndenylist: []\n" +
		"max_hosts_per_scan: 16\nmax_ports_per_host: " + itoa(maxPorts) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := scope.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func ptrInt(v int) *int { return &v }

// TestScopePortCapLimitsPortsProbed is the regression test for max_ports_per_host
// being parsed, stored, and then consulted by no probe path at all: a scope file
// that set it was silently ignored, so the limit an operator wrote down did not
// keep a single packet off the wire.
func TestScopePortCapLimitsPortsProbed(t *testing.T) {
	ports := []int{}
	for range 6 {
		ports = append(ports, freePort(t)) // closed, so each costs one quick connect
	}

	eng := NewEngine(scopeWith(t, 2), normalBudget(), Options{Ports: ports})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Stats.PacketsSent; got != 2 {
		t.Fatalf("max_ports_per_host=2 with 6 ports requested sent %d packets, want 2", got)
	}
}

func TestScopePortCapAppliesToTheDefaultPortSet(t *testing.T) {
	eng := NewEngine(scopeWith(t, 3), normalBudget(), Options{})
	if got := len(eng.candidatePorts()); got != 3 {
		t.Fatalf("default port set under max_ports_per_host=3 has %d ports, want 3", got)
	}
}

// TestMaxDetectRiskPrunesLoudProbes is the regression test for the flag that
// behaved identically at 3 and at 9 outside adaptive mode. Packets are counted
// rather than open ports asserted, so the result does not depend on whether the
// loud port happens to have a listener on the test machine.
func TestMaxDetectRiskPrunesLoudProbes(t *testing.T) {
	quiet := freePort(t) // ephemeral, unlisted in the risk table => riskDefault 3
	const loud = 445     // microsoft-ds, priced at 8: the loudest thing in the default set

	if adaptive.PortRisk(loud) <= 3 || adaptive.PortRisk(quiet) > 3 {
		t.Fatalf("risk table assumption broken: %d=%v, %d=%v",
			loud, adaptive.PortRisk(loud), quiet, adaptive.PortRisk(quiet))
	}

	run := func(risk int) int {
		b := budget.New(budget.Options{Mode: budget.Normal, Timing: 4, MaxDetectRisk: ptrInt(risk)})
		eng := NewEngine(scopeWith(t, 100), b, Options{Ports: []int{quiet, loud}})
		res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		return res.Stats.PacketsSent
	}

	if got := run(3); got != 1 {
		t.Errorf("--max-detect-risk 3 sent %d packets, want 1 (the risk-8 probe must be refused)", got)
	}
	if got := run(9); got != 2 {
		t.Errorf("--max-detect-risk 9 sent %d packets, want 2", got)
	}
	if run(3) == run(9) {
		t.Error("--max-detect-risk 3 and 9 still behave identically on a non-adaptive scan")
	}
}

func TestModePresetDoesNotPruneTheOperatorsPortList(t *testing.T) {
	// No explicit --max-detect-risk: a mode preset tunes timing and concurrency
	// and must not silently drop ports the operator asked for.
	b := budget.New(budget.Options{Mode: budget.Stealth, Timing: 4})
	eng := NewEngine(scopeWith(t, 100), b, Options{Ports: []int{80, 445, 3389, 502}})
	if got := len(eng.candidatePorts()); got != 4 {
		t.Fatalf("stealth mode pruned the port list to %d, want all 4 kept", got)
	}
}

// listenSilent binds a listener that accepts and then holds the connection open
// without ever speaking. A probe against it therefore blocks for the full
// bannerReadDelay, which gives this test a long, deterministic, purely local
// per-probe cost — no dependence on how the machine's network happens to treat
// unroutable addresses.
func listenSilent(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { <-done; c.Close() }() // hold it open, say nothing
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// TestPortsOfOneHostAreProbedInParallel is the regression test for the engine
// parallelising across hosts only: every port of a single host used to be probed
// strictly in series, so one host cost a full per-probe stall per port. With
// 65535 ports at the T3 connect timeout that is over two days for a single
// target, which an operator experiences as an indefinite hang.
func TestPortsOfOneHostAreProbedInParallel(t *testing.T) {
	const ports = 4

	list := make([]int, 0, ports)
	for range ports {
		list = append(list, listenSilent(t))
	}

	b := budget.New(budget.Options{Mode: budget.Normal, Timing: 4, Threads: ptrInt(ports)})
	eng := NewEngine(scopeWith(t, 100), b, Options{Ports: list, Banners: true})

	start := time.Now()
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	if got := len(res.Hosts[0].Services); got != ports {
		t.Fatalf("reported %d services, want %d — parallelism must not lose results", got, ports)
	}

	// Each probe stalls for bannerReadDelay. Serial would be ports*that; probing
	// them concurrently costs roughly one. Half the serial cost is a generous
	// bound that still fails decisively on the old one-at-a-time loop.
	serial := ports * bannerReadDelay
	if elapsed > serial/2 {
		t.Fatalf("%d ports on one host took %v (serial would be ~%v); ports are still probed one at a time",
			ports, elapsed, serial)
	}
}

// TestParallelPortProbingIsDeterministic pins the ordering guarantee the
// parallel sweep has to preserve: results are recorded in candidate order, not
// goroutine-completion order, so two runs of the same scan are diffable.
func TestParallelPortProbingIsDeterministic(t *testing.T) {
	var open []int
	for range 6 {
		open = append(open, listen(t))
	}
	var first []int
	for run := range 3 {
		eng := NewEngine(scopeWith(t, 100), normalBudget(), Options{Ports: open})
		res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Hosts) != 1 {
			t.Fatalf("run %d: want 1 host, got %d", run, len(res.Hosts))
		}
		var got []int
		for _, s := range res.Hosts[0].Services {
			got = append(got, s.Port)
		}
		if len(got) != len(open) {
			t.Fatalf("run %d: reported %d services, want %d", run, len(got), len(open))
		}
		for i := 1; i < len(got); i++ {
			if got[i-1] >= got[i] {
				t.Fatalf("run %d: services not in ascending port order: %v", run, got)
			}
		}
		if run == 0 {
			first = got
			continue
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("run %d differs from run 0: %v vs %v", run, got, first)
			}
		}
	}
}

func TestParallelismSplitsConcurrencyAcrossHostsAndPorts(t *testing.T) {
	cases := []struct {
		conc, hosts  int
		wantH, wantP int
	}{
		{500, 1, 1, 500},  // one target must be able to spend the whole budget
		{500, 200, 64, 7}, // many targets: hosts capped at 64, remainder per host
		{50, 10, 10, 5},   //
		{1, 10, 1, 1},     // a serial budget stays serial
		{0, 10, 1, 1},     //
		{8, 0, 8, 1},      // no targets: nothing to split
	}
	for _, c := range cases {
		h := hostParallelism(c.conc, c.hosts)
		p := portParallelism(c.conc, h)
		if h != c.wantH || p != c.wantP {
			t.Errorf("conc=%d hosts=%d: got hosts=%d ports=%d, want hosts=%d ports=%d",
				c.conc, c.hosts, h, p, c.wantH, c.wantP)
		}
		if c.conc > 0 && h*p > c.conc {
			t.Errorf("conc=%d hosts=%d: %d*%d exceeds the configured concurrency", c.conc, c.hosts, h, p)
		}
	}
}

// listenModelled binds a port the adaptive planner actually models. An
// ephemeral port is useless here: it carries no likelihood row, so every class
// gets the same baseline, the expected information gain is exactly zero, and the
// planner correctly refuses to spend a packet on it. Both ports below have a
// single dominant class, so one open result moves the posterior decisively.
func listenModelled(t *testing.T) int {
	t.Helper()
	for _, port := range []int{9100 /* printer 0.90 */, 5060 /* voip 0.90 */} {
		l, err := net.Listen("tcp", "127.0.0.1:"+itoa(port))
		if err != nil {
			continue // already in use on this machine; try the next
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		return port
	}
	t.Skip("no modelled port free to bind on this machine")
	return 0
}

// adaptiveEngine builds an adaptive engine over a single modelled port with an
// explicit stop threshold. 0.45 sits above the strongest prior (workstation,
// 0.30) so at least one probe is always required to reach it, and below what one
// open result on either port produces (~0.61 / ~0.52) so it is reachable.
func adaptiveEngine(t *testing.T, port int, confidence float64) *Engine {
	t.Helper()
	return NewEngine(scopeWith(t, 100), normalBudget(), Options{
		Adaptive:     true,
		Ports:        []int{port},
		PerHostProbe: adaptive.Options{Confidence: confidence, Ports: []int{port}},
	})
}

// TestWeakPosteriorWithholdsDeviceType is the regression test for the adaptive
// planner writing host.DeviceType regardless of the posterior's strength: a
// class sitting near 0.30 because the planner ran out of information was still
// emitted as an unqualified device_type.
func TestWeakPosteriorWithholdsDeviceType(t *testing.T) {
	port := listenModelled(t)
	// Unreachably strict: one probe cannot get any class to 0.999, so the
	// planner exhausts its candidates without ever earning a verdict.
	res, err := adaptiveEngine(t, port, 0.999).Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("want 1 host, got %d", len(res.Hosts))
	}
	host := res.Hosts[0]
	if host.DeviceType != nil {
		t.Errorf("device_type = %q asserted from a posterior that never reached the threshold", *host.DeviceType)
	}
	if host.DeviceTypeConfidence != nil {
		t.Errorf("device_type_confidence = %v set with no device_type; the two travel together", *host.DeviceTypeConfidence)
	}
	// The audit trail still records what the planner believed — withholding the
	// label must not erase the evidence for why it was withheld.
	if res.Plan == nil || len(res.Plan.Verdicts) != 1 {
		t.Fatal("plan verdict missing; the audit trail should still record the raw posterior")
	}
	if v := res.Plan.Verdicts[0]; v.Class == "" || v.StoppedBy == "" || v.Confidence <= 0 {
		t.Errorf("plan verdict is incomplete: %+v", v)
	}
}

// TestEarnedPosteriorPublishesDeviceTypeWithConfidence is the positive case: a
// verdict that clears the threshold is published, and it carries the number that
// justifies it rather than a bare label.
func TestEarnedPosteriorPublishesDeviceTypeWithConfidence(t *testing.T) {
	port := listenModelled(t)
	res, err := adaptiveEngine(t, port, 0.45).Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("want 1 host, got %d", len(res.Hosts))
	}
	host := res.Hosts[0]
	if host.DeviceType == nil {
		t.Fatal("device_type withheld even though the posterior cleared the threshold")
	}
	if host.DeviceTypeConfidence == nil {
		t.Fatal("device_type published without device_type_confidence")
	}
	if c := *host.DeviceTypeConfidence; c < 0.45 || c > 1 {
		t.Fatalf("device_type_confidence = %v, want the posterior in [threshold, 1]", c)
	}
}
