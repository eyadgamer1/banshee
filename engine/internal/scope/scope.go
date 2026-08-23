// Package scope is the authoritative safety boundary, ported from the Python
// ScopeGuard (E5). It refuses rather than warns, and there is no override flag.
package scope

import (
	"fmt"
	"net/netip"
	"os"

	"gopkg.in/yaml.v3"
)

type ViolationError struct {
	Target string
	Reason string
}

func (e *ViolationError) Error() string {
	return fmt.Sprintf("scope violation: %s — %s", e.Target, e.Reason)
}

// TooLargeError mirrors the Python TargetTooLargeError: a single token that would
// expand past the host cap is refused, never silently truncated to an arbitrary
// slice of a range the operator plainly did not mean to request.
type TooLargeError struct {
	Token string
	Size  uint64
	Limit int
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("%s expands to %d addresses, over the max_hosts_per_scan limit of %d. "+
		"Narrow the target or raise the cap in scope.yaml", e.Token, e.Size, e.Limit)
}

type file struct {
	Banner          string   `yaml:"banner"`
	Allowlist       []string `yaml:"allowlist"`
	Denylist        []string `yaml:"denylist"`
	MaxHostsPerScan int      `yaml:"max_hosts_per_scan"`
	MaxPortsPerHost int      `yaml:"max_ports_per_host"`
}

type Guard struct {
	Banner          string
	MaxHostsPerScan int
	MaxPortsPerHost int
	allow           []netip.Prefix
	deny            []netip.Prefix
}

func Load(path string) (*Guard, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f file
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	g := &Guard{
		Banner:          f.Banner,
		MaxHostsPerScan: f.MaxHostsPerScan,
		MaxPortsPerHost: f.MaxPortsPerHost,
	}
	if g.Banner == "" {
		g.Banner = "AUTHORIZED TARGETS ONLY"
	}
	if g.MaxHostsPerScan <= 0 {
		g.MaxHostsPerScan = 1024
	}
	if g.MaxPortsPerHost <= 0 {
		g.MaxPortsPerHost = 1000
	}
	if g.allow, err = parsePrefixes(f.Allowlist); err != nil {
		return nil, err
	}
	if g.deny, err = parsePrefixes(f.Denylist); err != nil {
		return nil, err
	}
	if len(g.allow) == 0 {
		return nil, fmt.Errorf("%s has an empty allowlist — refusing to run with no scope", path)
	}
	return g, nil
}

func parsePrefixes(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		p, err := netip.ParsePrefix(e)
		if err != nil {
			// A bare address is a valid entry; treat it as a single-host prefix.
			addr, aerr := netip.ParseAddr(e)
			if aerr != nil {
				return nil, fmt.Errorf("bad scope entry %q: %w", e, err)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func (g *Guard) InScope(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, d := range g.deny {
		if d.Contains(addr) {
			return false
		}
	}
	for _, a := range g.allow {
		if a.Contains(addr) {
			return true
		}
	}
	return false
}

// Filter splits targets into in-scope and out-of-scope, preserving order.
func (g *Guard) Filter(targets []string) (in, out []string) {
	for _, t := range targets {
		if g.InScope(t) {
			in = append(in, t)
		} else {
			out = append(out, t)
		}
	}
	return in, out
}
