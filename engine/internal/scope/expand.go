package scope

import (
	"net/netip"
	"strings"
)

// Expand turns targets (IPs or CIDRs) into a host list, refusing any single
// token that would expand past the cap rather than silently truncating it — a
// direct port of the Python TargetTooLargeError guard. The size check is
// arithmetic: a /8 is rejected without ever materialising 16 million addresses.
func Expand(targets []string, maxHosts int) ([]string, error) {
	var out []string
	for _, tok := range targets {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if !strings.Contains(tok, "/") {
			out = append(out, tok)
			continue
		}
		prefix, err := netip.ParsePrefix(tok)
		if err != nil {
			// Not a CIDR we understand; pass through and let scope reject it.
			out = append(out, tok)
			continue
		}
		size := prefixHostCount(prefix)
		if maxHosts > 0 && size > uint64(maxHosts) {
			return nil, &TooLargeError{Token: tok, Size: size, Limit: maxHosts}
		}
		for _, ip := range hostsOf(prefix) {
			out = append(out, ip)
		}
	}
	return out, nil
}

// prefixHostCount is 2^(bits-prefixlen) computed arithmetically. Capped well
// below the point of overflow because any value over maxHosts is already a
// refusal — the exact count past the cap does not matter.
func prefixHostCount(p netip.Prefix) uint64 {
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits <= 0 {
		return 1
	}
	if hostBits >= 63 {
		return ^uint64(0)
	}
	return uint64(1) << uint(hostBits)
}

// hostsOf enumerates a prefix. For /31 and /32 (and IPv6 equivalents) it returns
// the address itself rather than an empty set, matching the Python behaviour.
func hostsOf(p netip.Prefix) []string {
	p = p.Masked()
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits <= 1 {
		return []string{p.Addr().String()}
	}
	var out []string
	for addr := p.Addr(); p.Contains(addr); addr = addr.Next() {
		out = append(out, addr.String())
	}
	// Drop network and broadcast for IPv4 blocks larger than /31, as Python does.
	if p.Addr().Is4() && len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out
}
