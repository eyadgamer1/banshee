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
type serviceSignature struct {
	re      *regexp.Regexp
	product string
}

// Ordered most-specific first; the first match wins.
var serviceSignatures = []serviceSignature{
	// SSH: "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" -> OpenSSH 6.6.1p1
	{regexp.MustCompile(`SSH-\d[\d.]*-([A-Za-z][\w.+-]*?)[_/ ]([\d][\w.]*)`), ""},
	// HTTP Server header: "Server: Apache/2.4.7 (Ubuntu)" -> Apache 2.4.7
	{regexp.MustCompile(`(?i)server:\s*([A-Za-z][\w.+-]*)/([\d][\w.]*)`), ""},
	// FTP greeting: "220 (vsFTPd 3.0.2)" -> vsFTPd 3.0.2
	{regexp.MustCompile(`(?i)\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla|FTP)\b[ /]v?([\d][\w.]*)`), ""},
	// SMTP/IMAP/POP with an embedded product/version.
	{regexp.MustCompile(`(?i)\b(Postfix|Exim|Sendmail|Dovecot)\b[ /]v?([\d][\w.]*)`), ""},
	// Generic "Product/1.2.3" as a last resort — still a real captured token.
	{regexp.MustCompile(`\b([A-Za-z][\w.+-]{1,30})/([\d]+\.[\d][\w.]*)`), ""},
}

// matchService extracts (product, version) from a banner, or ("","") when no
// signature matches. The caller leaves the fields unset on an empty result.
func matchService(banner string) (product, version string) {
	if banner == "" {
		return "", ""
	}
	for _, sig := range serviceSignatures {
		m := sig.re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		if sig.product != "" {
			return sig.product, m[1]
		}
		return m[1], m[2]
	}
	return "", ""
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
