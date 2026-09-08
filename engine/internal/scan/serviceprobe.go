package scan

import (
	"net"
	"regexp"
	"time"
)

// Service/version identification, done honestly.
//
// Two layers, both match-only: product and version are set solely from bytes a
// service actually sent, never inferred from the port number. A banner that
// matches no signature yields no version — that is the rule that stops -sV from
// fabricating a service identity, the same discipline the rest of the engine
// applies to open ports and to UDP silence.
//
//   - Free layer (always on when banner reads are on): parse the server-first
//     greeting the TCP probe already captured. Sends nothing.
//   - Active layer (-sV only): for an open port that stayed silent, send one
//     protocol probe to elicit a version banner, then match it. This writes to
//     the wire, so it is gated behind the flag.

// serviceSignature maps a response pattern to a product and version. When
// product is non-empty it is a fixed name and the version comes from capture
// group 1; otherwise product is capture group 1 and version is group 2.
//
// specific marks a signature that names the exact product it looks for (SSH,
// Apache, vsFTPd, ...): a match is strong evidence, because the pattern only
// fires for that one protocol/product family. The generic fallback pattern
// matches ANY "Word/1.2.3"-shaped token in the banner — it makes -sV useful
// against unlisted products, but a match proves far less: the token could be
// an unrelated version string embedded in a banner, or (since it is derived
// from bytes the target chose to send) trivially spoofed. Callers use this
// bit to grade the resulting product/version claim, not just record it.
type serviceSignature struct {
	re       *regexp.Regexp
	product  string
	specific bool
}

// Ordered most-specific first; the first match wins.
var serviceSignatures = []serviceSignature{
	// SSH: "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" -> OpenSSH 6.6.1p1
	{regexp.MustCompile(`SSH-\d[\d.]*-([A-Za-z][\w.+-]*?)[_/ ]([\d][\w.]*)`), "", true},
	// HTTP Server header: "Server: Apache/2.4.7 (Ubuntu)" -> Apache 2.4.7
	{regexp.MustCompile(`(?i)server:\s*([A-Za-z][\w.+-]*)/([\d][\w.]*)`), "", true},
	// FTP greeting: "220 (vsFTPd 3.0.2)" -> vsFTPd 3.0.2
	{regexp.MustCompile(`(?i)\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla|FTP)\b[ /]v?([\d][\w.]*)`), "", true},
	// SMTP/IMAP/POP with an embedded product/version.
	{regexp.MustCompile(`(?i)\b(Postfix|Exim|Sendmail|Dovecot)\b[ /]v?([\d][\w.]*)`), "", true},
	// Generic "Product/1.2.3" as a last resort — still a real captured token,
	// but not tied to a known product family, so it is graded PROBABLE.
	{regexp.MustCompile(`\b([A-Za-z][\w.+-]{1,30})/([\d]+\.[\d][\w.]*)`), "", false},
}

// matchService extracts (product, version) from a banner, or ("","") when no
// signature matches. The caller leaves the fields unset on an empty result.
// specific reports whether the match came from a named-product signature
// (strong evidence) or the generic fallback pattern (weaker — grade PROBABLE).
func matchService(banner string) (product, version string, specific bool) {
	if banner == "" {
		return "", "", false
	}
	for _, sig := range serviceSignatures {
		m := sig.re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		if sig.product != "" {
			return sig.product, m[1], sig.specific
		}
		return m[1], m[2], sig.specific
	}
	return "", "", false
}

// weakBanner reports whether a captured banner did NOT yield a confident,
// named-product match — either nothing was captured, or what was captured
// only matched the generic fallback signature (which, as `matchService` docs
// note, can fire on an unrelated or spoofed token). -sV uses this to decide
// whether sending the extra disambiguating probe is worth it.
func weakBanner(banner string) bool {
	_, _, specific := matchService(banner)
	return !specific
}

// preferBanner picks which banner text to keep after an optional
// disambiguating probe. The active result wins when it gives a confident,
// named-product match, or when the passive banner had nothing at all;
// otherwise the original passive banner is kept — a weak-but-real capture is
// not thrown away for an equally weak or empty active result.
func preferBanner(passive, active string) string {
	if active == "" {
		return passive
	}
	_, _, activeSpecific := matchService(active)
	if activeSpecific || passive == "" {
		return active
	}
	return passive
}

// httpLikePorts are the plaintext HTTP ports worth a generic GET probe. TLS
// ports are excluded: eliciting an HTTPS banner needs a full handshake, which is
// out of scope for this bounded, honest probe.
var httpLikePorts = map[int]bool{80: true, 591: true, 8000: true, 8008: true, 8080: true, 8888: true}

// activeBanner sends one protocol probe on an already-open connection to draw a
// version banner from a service that did not speak first, and returns what it
// read (empty on no reply). It reuses the connection's budget slot — the socket
// is already open — so it adds bytes, not a new connection. Called only under
// -sV.
func activeBanner(conn net.Conn, port int) string {
	if !httpLikePorts[port] {
		return ""
	}
	req := "GET / HTTP/1.0\r\nHost: " + hostOf(conn) + "\r\nUser-Agent: banshee\r\nAccept: */*\r\n\r\n"
	_ = conn.SetWriteDeadline(time.Now().Add(bannerReadDelay))
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}
	return readBanner(conn)
}

// hostOf returns the remote host of a connection for the HTTP Host header, or a
// harmless default when it cannot be determined.
func hostOf(conn net.Conn) string {
	if ra := conn.RemoteAddr(); ra != nil {
		if host, _, err := net.SplitHostPort(ra.String()); err == nil {
			return host
		}
	}
	return "localhost"
}
