// Package budget resolves the intensity dial into enforced limits, ported from
// the Python StealthBudget (D3).
//
// Intensity (how loud) stays strictly separate from verbosity (how chatty).
// PASSIVE mode, or MaxDetectRisk 0, means zero active packets — full stop. The
// budget is the single source of truth every probe path consults before sending.
package budget

import (
	"context"
	"sync"
	"time"
)

type Mode string

const (
	Passive    Mode = "passive"
	Stealth    Mode = "stealth"
	Normal     Mode = "normal"
	Aggressive Mode = "aggressive"
)

type timing struct {
	concurrency int
	delay       time.Duration
	connect     time.Duration
	retries     int
}

// nmap-style timing templates, T0 (paranoid) through T5 (insane).
var templates = map[int]timing{
	0: {1, 5000 * time.Millisecond, 8000 * time.Millisecond, 3},
	1: {2, 1500 * time.Millisecond, 6000 * time.Millisecond, 2},
	2: {8, 400 * time.Millisecond, 5000 * time.Millisecond, 2},
	3: {50, 0, 3000 * time.Millisecond, 1},
	4: {200, 0, 1500 * time.Millisecond, 1},
	5: {500, 0, 750 * time.Millisecond, 0},
}

type modeProfile struct {
	factor float64
	active bool
	risk   int
}

var modes = map[Mode]modeProfile{
	Passive:    {0.0, false, 0},
	Stealth:    {0.25, true, 2},
	Normal:     {1.0, true, 5},
	Aggressive: {2.0, true, 9},
}

// Options are the raw CLI intentions. A nil pointer means "inherit the template";
// a set pointer overrides it, including a deliberate zero.
type Options struct {
	Mode          Mode
	Timing        int
	Threads       *int
	TimeoutMS     *int
	Retries       *int
	RatePPS       int
	MaxPackets    int
	MaxDetectRisk *int
}

// Budget is safe for concurrent use: every goroutine in the scan pool shares one.
type Budget struct {
	AllowActive    bool
	Concurrency    int
	Delay          time.Duration
	ConnectTimeout time.Duration
	Retries        int
	RatePPS        int
	MaxPackets     int
	DetectRisk     int

	mu       sync.Mutex
	sent     int
	lastSend time.Time
	slots    chan struct{}
}

func New(o Options) *Budget {
	tpl, ok := templates[o.Timing]
	if !ok {
		tpl = templates[3]
	}
	if o.Mode == "" {
		o.Mode = Normal
	}
	profile, ok := modes[o.Mode]
	if !ok {
		profile = modes[Normal]
	}

	risk := profile.risk
	if o.MaxDetectRisk != nil {
		risk = *o.MaxDetectRisk
	}
	allowActive := profile.active && risk > 0

	concurrency := 0
	if allowActive {
		concurrency = max(1, int(float64(tpl.concurrency)*profile.factor))
		if o.Threads != nil {
			concurrency = max(1, *o.Threads)
		}
	}

	connect := tpl.connect
	if o.TimeoutMS != nil {
		connect = time.Duration(max(0, *o.TimeoutMS)) * time.Millisecond
	}
	retries := tpl.retries
	if o.Retries != nil {
		retries = max(0, *o.Retries)
	}

	b := &Budget{
		AllowActive:    allowActive,
		Concurrency:    concurrency,
		Delay:          tpl.delay,
		ConnectTimeout: connect,
		Retries:        retries,
		RatePPS:        o.RatePPS,
		MaxPackets:     o.MaxPackets,
		DetectRisk:     risk,
	}
	b.slots = make(chan struct{}, max(1, concurrency))
	return b
}

// CanSend reports whether another active probe is permitted. Callers MUST check
// this before Throttle; passive mode never reaches the send path at all.
func (b *Budget) CanSend() bool {
	if !b.AllowActive {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.MaxPackets <= 0 || b.sent < b.MaxPackets
}

// Throttle blocks for the inter-probe delay and the per-second rate cap, then
// counts one packet against the budget. The lock is held across the wait on
// purpose: the delay is a global pacing guarantee, not a per-goroutine one, so
// serialising here is what makes the observable packet rate match the template.
func (b *Budget) Throttle(ctx context.Context) error {
	b.mu.Lock()
	gap := b.Delay
	if b.RatePPS > 0 {
		if perPacket := time.Second / time.Duration(b.RatePPS); perPacket > gap {
			gap = perPacket
		}
	}
	var wait time.Duration
	if !b.lastSend.IsZero() && gap > 0 {
		wait = gap - time.Since(b.lastSend)
	}
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		b.mu.Lock()
	}
	b.lastSend = time.Now()
	b.sent++
	b.mu.Unlock()
	return nil
}

// Acquire takes a concurrency slot, blocking until one frees or ctx ends.
func (b *Budget) Acquire(ctx context.Context) error {
	select {
	case b.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *Budget) Release() { <-b.slots }

func (b *Budget) PacketsSent() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sent
}
