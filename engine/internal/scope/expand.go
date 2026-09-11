package scope

import (
	"math/big"
	"net/netip"
	"strings"
)

// Expand turns targets (IPs, CIDRs or ranges) into a host list, refusing any
// single token that would expand past the cap rather than silently truncating
// it — a direct port of the Python TargetTooLargeError guard. The size check is
// arithmetic: a /8 is rejected without ever materialising 16 million addresses.
func Expand(targets []string, maxHosts int) ([]string, error) {
	var out []string
	for _, tok := range targets {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if !strings.Contains(tok, "/") {
			hosts, ok, err := expandRange(tok, maxHosts)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, hosts...)
			} else {
				out = append(out, tok)
			}
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
	return dedupe(out), nil
}

// dedupe drops repeated addresses while preserving first-seen order, matching
// what the Python engine does after resolution. Without it, `banshee 10.0.0.1
// 10.0.0.1` counted two targets on the Go path and one on the Python path, and
// the duplicate was probed twice — so the two engines disagreed on the host
// count for identical input, and the host cap counted the same address twice.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, tok := range in {
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	return out
}

// expandRange expands a last-octet range (1.2.3.10-20) or a full range
// (1.2.3.10-1.2.3.20), both endpoints inclusive. It is a port of the range
// branch of Python's expand_target (scanner/core/engine.py) and must stay
// behaviourally identical to it, because either engine may be the one that
// expands a given token.
//
// The bool reports whether tok was recognised as a range. A token that does not
// parse as one — bad address, mismatched families, or an end before its start —
// returns false so the caller passes it through untouched and the scope layer
// owns the rejection, exactly as the Python path does. Without this, a `-`
// token reached scope unexpanded and was reported as a scope violation, which
// blamed the allowlist for a parsing gap.
//
// No network/broadcast trim applies here: a range names both endpoints
// explicitly, so both are genuinely requested hosts.
func expandRange(tok string, maxHosts int) ([]string, bool, error) {
	i := strings.LastIndex(tok, "-")
	if i < 0 {
		return nil, false, nil
	}
	left, right := strings.TrimSpace(tok[:i]), strings.TrimSpace(tok[i+1:])
	start, err := netip.ParseAddr(left)
	if err != nil {
		return nil, false, nil
	}
	var end netip.Addr
	if strings.ContainsAny(right, ".:") { // full second address
		end, err = netip.ParseAddr(right)
	} else { // last-octet shorthand: borrow the prefix from the left address
		dot := strings.LastIndex(left, ".")
		if dot < 0 {
			return nil, false, nil
		}
		end, err = netip.ParseAddr(left[:dot+1] + right)
	}
	if err != nil || start.Is4() != end.Is4() || end.Less(start) {
		return nil, false, nil
	}
	// Arithmetic size check before building the list, so an oversized range is
	// refused without materialising it.
	size := new(big.Int).Sub(addrToBig(end), addrToBig(start))
	size.Add(size, big.NewInt(1))
	if maxHosts > 0 && size.Cmp(big.NewInt(int64(maxHosts))) > 0 {
		capped := ^uint64(0)
		if size.IsUint64() {
			capped = size.Uint64()
		}
		return nil, false, &TooLargeError{Token: tok, Size: capped, Limit: maxHosts}
	}
	var out []string
	for addr := start; ; addr = addr.Next() {
		out = append(out, addr.String())
		if addr == end || !addr.Next().IsValid() {
			break
		}
	}
	return out, true, nil
}

// addrToBig maps an address to its integer value via the 16-byte form, so one
// comparison path covers both IPv4 and IPv6 without overflow.
func addrToBig(a netip.Addr) *big.Int {
	b := a.As16()
	return new(big.Int).SetBytes(b[:])
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

// hostsOf enumerates a prefix.
//
// A /32 (or /128) is the single address itself. A /31 is BOTH of its addresses:
// RFC 3021 defines a two-address IPv4 block for point-to-point links where
// neither address is a network or broadcast address, so trimming one silently
// drops a real, scannable host — the far end of exactly the kind of link an
// operator writes a /31 to reach. The network/broadcast trim therefore applies
// only to IPv4 blocks of /30 and larger, where those addresses genuinely exist.
func hostsOf(p netip.Prefix) []string {
	p = p.Masked()
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits <= 0 {
		return []string{p.Addr().String()} // /32, /128
	}
	var out []string
	for addr := p.Addr(); p.Contains(addr); addr = addr.Next() {
		out = append(out, addr.String())
		if !addr.Next().IsValid() {
			break // last address in the space: Next() would not terminate the loop
		}
	}
	// Drop network and broadcast for IPv4 blocks larger than a /31 only.
	if p.Addr().Is4() && hostBits > 1 && len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out
}
