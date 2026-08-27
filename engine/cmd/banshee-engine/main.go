// Command banshee-engine is the Go active-scan core for BANSHEE.
//
// It is a single static binary on purpose. A pentester cannot `pip install` on a
// client jump box or an ARM drop-box, but they can `scp` one file. This engine
// emits the exact JSON schema the Python tool produces, so it slots in as a fast,
// dependency-free front end while the Python side keeps the reporting, LLM and
// enrichment stages — and the Python ground-truth suite validates this binary
// unchanged.
//
// Safety is not optional and has no override flag: the scope guard refuses rather
// than warns, and a passive budget (--mode passive, or --max-detect-risk 0) puts
// zero packets on the wire.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/eyadgamer1/banshee/engine/internal/adaptive"
	"github.com/eyadgamer1/banshee/engine/internal/budget"
	"github.com/eyadgamer1/banshee/engine/internal/scan"
	"github.com/eyadgamer1/banshee/engine/internal/scope"
)

// Exit codes match the Python CLI so wrappers can treat both the same.
const (
	exitOK        = 0
	exitError     = 1
	exitBadUsage  = 2
	exitNoTargets = 3
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("banshee-engine", flag.ContinueOnError)
	var (
		scopeFile  = fs.String("scope", "config/scope.yaml", "scope allowlist file (authoritative; no override)")
		portsCSV   = fs.String("ports", "", "ports: 22,80,443 or 1-1024 (default: high-signal set)")
		mode       = fs.String("mode", "normal", "passive|stealth|normal|aggressive")
		timing     = fs.Int("T", 3, "timing template 0..5 (T0 paranoid .. T5 insane)")
		rate       = fs.Int("rate", 0, "max packets/sec (0 = template default)")
		threads    = fs.Int("threads", 0, "concurrency override (0 = derive from mode+timing)")
		timeoutMS  = fs.Int("timeout", -1, "connect timeout ms (-1 = template default)")
		maxRisk    = fs.Int("max-detect-risk", -1, "0..10; 0 forces passive (-1 = mode default)")
		adaptiveOn = fs.Bool("adaptive", false, "select probes by information gain per unit risk")
		udpOn      = fs.Bool("udp", false, "also sweep ports over UDP (open|filtered when silent)")
		serviceOn  = fs.Bool("sV", false, "probe silent open ports for a version banner (sends a probe)")
		banners    = fs.Bool("banners", true, "read server-first banners (sends no extra packet)")
		confidence = fs.Float64("confidence", 0.85, "adaptive: stop when class posterior reaches this")
		hostRisk   = fs.Float64("host-risk-budget", 0, "adaptive: cap detection risk per host (0 = none)")
		pretty     = fs.Bool("pretty", false, "indent JSON output")
		out        = fs.String("o", "-", "output file (- = stdout)")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: banshee-engine [flags] <target> [target...]\n\n")
		fmt.Fprintf(os.Stderr, "Targets are IPs or CIDRs. Every target must be inside --scope; out-of-scope\n")
		fmt.Fprintf(os.Stderr, "targets are refused, never scanned.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitBadUsage
	}

	targets := fs.Args()
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "error: no targets given")
		fs.Usage()
		return exitBadUsage
	}

	ports, err := parsePorts(*portsCSV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitBadUsage
	}

	guard, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	expanded, err := scope.Expand(targets, guard.MaxHostsPerScan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitBadUsage
	}

	b := budget.New(budget.Options{
		Mode:          budget.Mode(*mode),
		Timing:        *timing,
		RatePPS:       *rate,
		Threads:       optInt(fs, "threads", *threads),
		TimeoutMS:     optInt(fs, "timeout", *timeoutMS),
		MaxDetectRisk: optInt(fs, "max-detect-risk", *maxRisk),
	})

	eng := scan.NewEngine(guard, b, scan.Options{
		Ports:       ports,
		Adaptive:    *adaptiveOn,
		UDP:         *udpOn,
		ServiceScan: *serviceOn,
		Banners:     *banners,
		PerHostProbe: adaptive.Options{
			Confidence: *confidence,
			MaxRisk:    *hostRisk,
			Ports:      ports,
		},
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	result, err := eng.Run(ctx, expanded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	enc, err := marshal(result, *pretty)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	if err := emit(*out, enc); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	if result.Stats.TargetsInScope == 0 {
		fmt.Fprintln(os.Stderr, "warning: no targets were in scope; nothing scanned")
		return exitNoTargets
	}
	return exitOK
}

// optInt returns a pointer to v only if the flag was set on the command line, so
// an untouched flag inherits the budget template instead of overriding it with a
// zero the user never typed.
func optInt(fs *flag.FlagSet, name string, v int) *int {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	if !set {
		return nil
	}
	return &v
}

func marshal(v any, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}

func emit(path string, data []byte) error {
	data = append(data, '\n')
	if path == "-" || path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// parsePorts accepts nmap-style "22,80,443" and "1-1024", deduplicated and
// sorted. Empty input means "use the engine's default high-signal set".
func parsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	seen := map[int]bool{}
	var ports []int
	add := func(p int) error {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port out of range: %d", p)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
		return nil
	}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		lo, hi, ok := strings.Cut(tok, "-")
		if ok {
			a, err := strconv.Atoi(strings.TrimSpace(lo))
			if err != nil {
				return nil, fmt.Errorf("bad port range %q", tok)
			}
			z, err := strconv.Atoi(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("bad port range %q", tok)
			}
			if a > z {
				a, z = z, a
			}
			for p := a; p <= z; p++ {
				if err := add(p); err != nil {
					return nil, err
				}
			}
			continue
		}
		p, err := strconv.Atoi(tok)
		if err != nil {
			return nil, fmt.Errorf("bad port %q", tok)
		}
		if err := add(p); err != nil {
			return nil, err
		}
	}
	return ports, nil
}
