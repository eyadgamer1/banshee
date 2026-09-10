package budget

import (
	"context"
	"sync"
	"testing"
	"time"
)

// These tests exist because the budget is a safety guarantee, not an
// optimisation. A scanner that quietly emits 64x its configured rate is a
// defect an operator cannot see from the output, so the pacing has to be
// pinned by a test rather than by a comment.

func ptr(v int) *int { return &v }

// TestThrottlePacesGloballyNotPerGoroutine is the regression test for the
// unlock-before-sleep bug: N goroutines used to each read the same lastSend,
// compute the same wait, sleep in parallel and then fire together, so the gap
// bound the batch instead of each send. With the lock held across the wait,
// N sends must take at least (N-1) gaps of wall time no matter how many
// goroutines are pushing.
func TestThrottlePacesGloballyNotPerGoroutine(t *testing.T) {
	const (
		sends = 8
		gap   = 20 * time.Millisecond
	)
	b := New(Options{Mode: Normal, Timing: 3})
	b.Delay = gap

	start := time.Now()
	var wg sync.WaitGroup
	for range sends {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := b.Throttle(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	// The first send is free; every subsequent one must wait a full gap.
	want := time.Duration(sends-1) * gap
	// Allow a little slack for timer granularity, but not a whole gap: the
	// broken version finished in ~1 gap total, which this comfortably rejects.
	if elapsed < want-(gap/2) {
		t.Fatalf("%d sends at a %v gap took %v, want >= ~%v — the delay is binding "+
			"per batch, not globally", sends, gap, elapsed, want)
	}
	if got := b.PacketsSent(); got != sends {
		t.Fatalf("counted %d packets, want %d", got, sends)
	}
}

// TestThrottleHonoursRateCapUnderConcurrency covers the --rate path, which is
// what an operator reaches for when they need a hard packets-per-second number.
func TestThrottleHonoursRateCapUnderConcurrency(t *testing.T) {
	const sends = 6
	b := New(Options{Mode: Normal, Timing: 3, RatePPS: 100}) // 10ms per packet

	start := time.Now()
	var wg sync.WaitGroup
	for range sends {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = b.Throttle(context.Background())
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	want := time.Duration(sends-1) * (10 * time.Millisecond)
	if elapsed < want-(5*time.Millisecond) {
		t.Fatalf("%d sends at 100pps took %v, want >= ~%v", sends, elapsed, want)
	}
}

// TestThrottleZeroDelayDoesNotBlock guards the other direction: T3+ has no
// inter-probe delay and no rate cap, and the fix must not turn that into a
// serialised crawl.
func TestThrottleZeroDelayDoesNotBlock(t *testing.T) {
	b := New(Options{Mode: Normal, Timing: 4})
	if b.Delay != 0 {
		t.Fatalf("T4 template should have no delay, got %v", b.Delay)
	}
	start := time.Now()
	for range 100 {
		if err := b.Throttle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("100 unpaced sends took %v, want near-instant", elapsed)
	}
}

func TestThrottleRespectsContextCancellation(t *testing.T) {
	b := New(Options{Mode: Normal, Timing: 3})
	b.Delay = time.Hour
	if err := b.Throttle(context.Background()); err != nil { // first send is free
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.Throttle(ctx); err == nil {
		t.Fatal("Throttle waiting an hour should have returned ctx.Err()")
	}
	// A cancelled wait must not count a packet that was never sent.
	if got := b.PacketsSent(); got != 1 {
		t.Fatalf("cancelled Throttle counted a packet: sent=%d, want 1", got)
	}
}

func TestPassiveBudgetSendsNothing(t *testing.T) {
	for name, b := range map[string]*Budget{
		"passive mode":       New(Options{Mode: Passive, Timing: 3}),
		"max-detect-risk 0":  New(Options{Mode: Normal, Timing: 3, MaxDetectRisk: ptr(0)}),
		"aggressive at risk": New(Options{Mode: Aggressive, Timing: 5, MaxDetectRisk: ptr(0)}),
	} {
		if b.AllowActive {
			t.Errorf("%s: AllowActive is true", name)
		}
		if b.CanSend() {
			t.Errorf("%s: CanSend is true", name)
		}
		if b.AllowProbeRisk(1.0) {
			t.Errorf("%s: AllowProbeRisk permitted the quietest possible probe", name)
		}
	}
}

func TestMaxPacketsStopsSending(t *testing.T) {
	b := New(Options{Mode: Normal, Timing: 4})
	b.MaxPackets = 3
	for i := range 3 {
		if !b.CanSend() {
			t.Fatalf("CanSend false at packet %d, under the cap of 3", i)
		}
		if err := b.Throttle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if b.CanSend() {
		t.Fatal("CanSend still true after the max-packets cap was reached")
	}
}

// TestMaxDetectRiskIsGradedNotBinary is the regression test for the flag that
// used to behave identically at 3 and at 9 outside adaptive mode.
func TestMaxDetectRiskIsGradedNotBinary(t *testing.T) {
	quiet := New(Options{Mode: Normal, Timing: 3, MaxDetectRisk: ptr(3)})
	loud := New(Options{Mode: Normal, Timing: 3, MaxDetectRisk: ptr(9)})

	// port 443 costs 1, port 445 costs 8 on the adaptive risk scale.
	if !quiet.AllowProbeRisk(1.0) {
		t.Error("--max-detect-risk 3 refused a risk-1 probe (443)")
	}
	if quiet.AllowProbeRisk(8.0) {
		t.Error("--max-detect-risk 3 permitted a risk-8 probe (445) — the flag is still binary")
	}
	if !loud.AllowProbeRisk(8.0) {
		t.Error("--max-detect-risk 9 refused a risk-8 probe (445)")
	}
	if quiet.AllowProbeRisk(8.0) == loud.AllowProbeRisk(8.0) {
		t.Error("risk 3 and risk 9 still behave identically")
	}
	// Exactly at the ceiling is allowed; the scale is inclusive.
	if !quiet.AllowProbeRisk(3.0) {
		t.Error("a probe exactly at the ceiling was refused")
	}
}

// TestModePresetImposesNoProbeCeiling pins the deliberate limit of the graded
// behaviour: a mode preset tunes timing and concurrency, it must not silently
// prune the operator's port list the way an explicit flag does.
func TestModePresetImposesNoProbeCeiling(t *testing.T) {
	for _, m := range []Mode{Stealth, Normal, Aggressive} {
		b := New(Options{Mode: m, Timing: 3})
		if b.MaxProbeRisk != 0 {
			t.Errorf("mode %s set a per-probe ceiling of %v without an explicit flag", m, b.MaxProbeRisk)
		}
		if !b.AllowProbeRisk(10.0) {
			t.Errorf("mode %s refused the loudest probe with no --max-detect-risk given", m)
		}
	}
}

func TestAcquireReleaseBoundsConcurrency(t *testing.T) {
	b := New(Options{Mode: Normal, Timing: 3, Threads: ptr(2)})
	ctx := context.Background()
	for range 2 {
		if err := b.Acquire(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Both slots held: a third Acquire must block until one is released.
	tight, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := b.Acquire(tight); err == nil {
		t.Fatal("Acquire handed out a third slot for a 2-slot budget")
	}
	b.Release()
	if err := b.Acquire(ctx); err != nil {
		t.Fatalf("Acquire failed after Release freed a slot: %v", err)
	}
}
