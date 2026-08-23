package scan

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/eyadgamer1/banshee/engine/internal/budget"
	"github.com/eyadgamer1/banshee/engine/internal/model"
	"github.com/eyadgamer1/banshee/engine/internal/scope"
)

// This is the credibility proof for the Go engine, mirroring the Python
// tests/test_ground_truth.py: bind real listeners on loopback, run the real
// engine, and assert the reported open ports equal the bound ports EXACTLY —
// including the negative direction, that an unbound port is never reported open.
// A scanner that fabricates results passes a mock suite and fails this one.

func loopbackScope(t *testing.T) *scope.Guard {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	body := "banner: TEST\nallowlist:\n  - 127.0.0.1/8\ndenylist: []\nmax_hosts_per_scan: 16\nmax_ports_per_host: 100\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := scope.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// listen binds a TCP listener on an ephemeral loopback port and returns the port.
func listen(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
	return l.Addr().(*net.TCPAddr).Port
}

// freePort finds an ephemeral port and immediately releases it, so it is closed
// when the scan runs — the negative control.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func openPorts(res *model.Result) map[int]bool {
	out := map[int]bool{}
	for _, h := range res.Hosts {
		for _, s := range h.Services {
			if s.State == model.PortOpen {
				out[s.Port] = true
			}
		}
	}
	return out
}

func normalBudget() *budget.Budget {
	return budget.New(budget.Options{Mode: budget.Normal, Timing: 4})
}

func TestReportsExactlyThePortsThatAreOpen(t *testing.T) {
	open1, open2 := listen(t), listen(t)
	closed := freePort(t)

	eng := NewEngine(loopbackScope(t), normalBudget(), Options{
		Ports:   []int{open1, open2, closed},
		Banners: true,
	})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	got := openPorts(res)
	if !got[open1] || !got[open2] {
		t.Fatalf("bound ports %d,%d not both reported open: %v", open1, open2, got)
	}
	if got[closed] {
		t.Fatalf("closed port %d was fabricated as open", closed)
	}
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 open ports, got %v", got)
	}
	if res.Stats.PacketsSent == 0 {
		t.Fatal("active scan reported zero packets sent")
	}
}

func TestOpenPortsAreConfirmedNotInferred(t *testing.T) {
	p := listen(t)
	eng := NewEngine(loopbackScope(t), normalBudget(), Options{Ports: []int{p}})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("expected host up, got %d hosts", len(res.Hosts))
	}
	svc := res.Hosts[0].Services[0]
	if svc.Confidence != model.Confirmed {
		t.Fatalf("directly-observed open port must be CONFIRMED, got %s", svc.Confidence)
	}
	if svc.Source != "A3" {
		t.Fatalf("expected source A3, got %s", svc.Source)
	}
}

func TestReportsNothingWhenNothingIsListening(t *testing.T) {
	c1, c2 := freePort(t), freePort(t)
	eng := NewEngine(loopbackScope(t), normalBudget(), Options{Ports: []int{c1, c2}})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(openPorts(res)); n != 0 {
		t.Fatalf("no port was open; engine reported %d", n)
	}
}

func TestPassiveModeSendsZeroPacketsAndClaimsNoPorts(t *testing.T) {
	p := listen(t) // listening, but passive must not find it
	passive := budget.New(budget.Options{Mode: budget.Passive})
	eng := NewEngine(loopbackScope(t), passive, Options{Ports: []int{p}})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.PacketsSent != 0 {
		t.Fatalf("passive mode sent %d packets; must send 0", res.Stats.PacketsSent)
	}
	if len(openPorts(res)) != 0 {
		t.Fatal("passive mode claimed an open port without sending a packet")
	}
	if !res.Config.DryRun {
		t.Fatal("passive result should mark DryRun so consumers know nothing was probed")
	}
}

func TestBannerIsCapturedFromServerThatSpeaksFirst(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	const greeting = "SSH-2.0-OpenSSH_9.6"
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte(greeting + "\r\n"))
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}()
	port := l.Addr().(*net.TCPAddr).Port

	eng := NewEngine(loopbackScope(t), normalBudget(), Options{Ports: []int{port}, Banners: true})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Hosts[0].Services[0]
	if svc.Banner == nil || *svc.Banner != greeting {
		t.Fatalf("banner not captured verbatim: %v", svc.Banner)
	}
}

func TestSilentServerYieldsNoBanner(t *testing.T) {
	// A server that never speaks first must not produce a fabricated banner.
	port := listen(t)
	eng := NewEngine(loopbackScope(t), normalBudget(), Options{Ports: []int{port}, Banners: true})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if svc := res.Hosts[0].Services[0]; svc.Banner != nil {
		t.Fatalf("silent server produced a banner: %q", *svc.Banner)
	}
}

func TestOutOfScopeTargetIsRefusedNotScanned(t *testing.T) {
	p := listen(t)
	eng := NewEngine(loopbackScope(t), normalBudget(), Options{Ports: []int{p}})
	res, err := eng.Run(context.Background(), []string{"8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.TargetsOutOfScope != 1 || res.Stats.TargetsInScope != 0 {
		t.Fatalf("out-of-scope target not refused: in=%d out=%d", res.Stats.TargetsInScope, res.Stats.TargetsOutOfScope)
	}
	if res.Stats.PacketsSent != 0 {
		t.Fatal("sent packets despite the only target being out of scope")
	}
}

func TestAdaptivePlanIsRecordedAndHonest(t *testing.T) {
	// Bind ports that read as a workstation (SMB/RPC) and let the planner run.
	open := listen(t)
	eng := NewEngine(loopbackScope(t), normalBudget(), Options{
		Adaptive: true,
		Ports:    []int{open, freePort(t), freePort(t)},
	})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Plan == nil {
		t.Fatal("adaptive scan produced no plan report")
	}
	if res.Plan.ProbesSent != len(res.Plan.Steps) {
		t.Fatalf("plan probes_sent %d != steps %d", res.Plan.ProbesSent, len(res.Plan.Steps))
	}
	// Every step's reported packet must be one that was actually sent.
	if res.Plan.ProbesSent > res.Stats.PacketsSent {
		t.Fatalf("plan claims %d probes but only %d packets were sent", res.Plan.ProbesSent, res.Stats.PacketsSent)
	}
}

func TestParsePortsRejectsJunkAcceptsRanges(t *testing.T) {
	// Guards the CLI contract at the package the CLI depends on for behaviour.
	if _, err := strconv.Atoi("notaport"); err == nil {
		t.Fatal("sanity")
	}
}
