package adaptive

import (
	"math"
	"testing"
)

// The planner's whole claim is that it spends fewer, cheaper probes than a fixed
// list while still reaching the right class. These tests hold it to that claim on
// the math itself, not on a live network.

func TestPriorsSumToOne(t *testing.T) {
	var total float64
	for _, c := range Classes {
		total += priors[c]
	}
	if math.Abs(total-1.0) > 1e-9 {
		t.Fatalf("priors must be a distribution; sum = %v", total)
	}
}

func TestPosteriorStaysADistribution(t *testing.T) {
	p := New(Options{})
	p.Observe(9100, Open) // printer signal
	p.Observe(445, Closed)
	var total float64
	for _, v := range p.Posterior() {
		if v < 0 || v > 1 {
			t.Fatalf("posterior out of [0,1]: %v", v)
		}
		total += v
	}
	if math.Abs(total-1.0) > 1e-9 {
		t.Fatalf("posterior must sum to 1; got %v", total)
	}
}

func TestInformationGainIsNonNegative(t *testing.T) {
	p := New(Options{})
	for _, port := range p.Candidates() {
		if b := p.Bits(port); b < 0 {
			t.Fatalf("EIG must be >= 0; port %d gave %v", port, b)
		}
	}
}

func TestObservingPrinterPortsConvergesToPrinter(t *testing.T) {
	p := New(Options{Confidence: 0.85})
	// 9100 (JetDirect) and 631 (IPP) are near-exclusive printer signals.
	p.Observe(9100, Open)
	p.Observe(631, Open)
	p.Observe(445, Closed)
	class, conf := p.Verdict()
	if class != Printer {
		t.Fatalf("expected printer, got %s (%.2f)", class, conf)
	}
	if conf < 0.85 {
		t.Fatalf("expected confident printer verdict, got %.2f", conf)
	}
}

func TestWindowsPortsConvergeToWorkstation(t *testing.T) {
	p := New(Options{})
	p.Observe(445, Open)
	p.Observe(135, Open)
	p.Observe(139, Open)
	if class, _ := p.Verdict(); class != Workstation {
		t.Fatalf("expected workstation from SMB/RPC ports, got %s", class)
	}
}

func TestPlannerPrefersCheapInformativeProbeFirst(t *testing.T) {
	p := New(Options{})
	choice, _, ok := p.Next()
	if !ok {
		t.Fatal("planner should offer a first probe")
	}
	// The first probe must beat 445 on value: 445 is highly informative but its
	// detection risk (8) should stop it being the opening move.
	if choice.Port == 445 {
		t.Fatalf("planner opened with the loudest port 445 — risk weighting is not applied")
	}
	if choice.Value <= 0 {
		t.Fatalf("first probe has non-positive value: %+v", choice)
	}
}

func TestAdaptiveStopsBeforeExhaustingAllPorts(t *testing.T) {
	p := New(Options{Confidence: 0.8})
	full := len(p.Candidates())
	// Feed an unambiguous camera: RTSP open, SMB closed.
	steps := 0
	for {
		choice, _, ok := p.Next()
		if !ok {
			break
		}
		// Simulate: camera-ish answers.
		switch choice.Port {
		case 554, 80:
			p.Observe(choice.Port, Open)
		default:
			p.Observe(choice.Port, Closed)
		}
		steps++
		if steps > full {
			t.Fatal("planner probed more than the full candidate set")
		}
	}
	if p.Probes() >= full {
		t.Fatalf("adaptive planner used all %d probes; it must stop early on a clear host", full)
	}
}

func TestRiskBudgetIsRespected(t *testing.T) {
	p := New(Options{MaxRisk: 5.0, Confidence: 0.999})
	for {
		choice, _, ok := p.Next()
		if !ok {
			break
		}
		p.Observe(choice.Port, Closed)
	}
	if p.SpentRisk() > 5.0+1e-9 {
		t.Fatalf("risk budget exceeded: spent %.2f of 5.0", p.SpentRisk())
	}
}

func TestFilteredResultDoesNotMoveBelief(t *testing.T) {
	p := New(Options{})
	before := p.Posterior()
	p.Observe(445, Filtered)
	after := p.Posterior()
	for _, c := range Classes {
		if math.Abs(before[c]-after[c]) > 1e-12 {
			t.Fatalf("filtered probe changed belief for %s: %v -> %v", c, before[c], after[c])
		}
	}
	if p.SpentRisk() == 0 {
		t.Fatal("filtered probe should still cost detection risk")
	}
}

func TestPlanningIsDeterministic(t *testing.T) {
	order := func() []int {
		p := New(Options{Confidence: 0.999})
		var seq []int
		for {
			choice, _, ok := p.Next()
			if !ok {
				break
			}
			seq = append(seq, choice.Port)
			p.Observe(choice.Port, Closed)
		}
		return seq
	}
	a, b := order(), order()
	if len(a) != len(b) {
		t.Fatalf("probe order length differs across runs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("probe order differs at %d: %d vs %d", i, a[i], b[i])
		}
	}
}
