package scan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eyadgamer1/banshee/engine/internal/model"
)

// UDP scanning is honest about what it cannot know. A connectionless probe has
// exactly three truthful outcomes:
//
//   - a reply from the port            -> OPEN      (CONFIRMED; the host is up)
//   - ICMP port-unreachable / refused  -> CLOSED    (CONFIRMED; the host is up)
//   - silence                          -> OPEN|FILTERED (POTENTIAL; proves nothing)
//
// The third case is the whole discipline: a silent UDP port may be open (the
// service ignored our datagram) or filtered, and we NEVER collapse that to a
// plain "open". Protocol-correct payloads for well-known ports make an open
// service answer, so silence is meaningful rather than merely uninformative.

const udpReadBytes = 512

// udpDefaultPorts is the high-signal UDP set used when no -ports is given: the
// services that actually answer a well-formed datagram.
var udpDefaultPorts = []int{53, 67, 123, 137, 138, 161, 500, 514, 520, 1900, 5353}

var udpWellKnown = map[int]string{
	53: "domain", 67: "dhcps", 68: "dhcpc", 69: "tftp", 123: "ntp",
	137: "netbios-ns", 138: "netbios-dgm", 161: "snmp", 162: "snmptrap",
	500: "isakmp", 514: "syslog", 520: "rip", 1900: "ssdp", 5353: "mdns",
}

// udpPayloads are protocol-correct probes that make an open service answer. A
// port with no entry gets a single null byte, which rarely elicits a reply — so
// its silence reads honestly as open|filtered, never as open.
var udpPayloads = map[int][]byte{
	53:   dnsRootQuery(),
	123:  ntpClientRequest(),
	161:  snmpGetPublic(),
	1900: ssdpDiscover(),
	5353: mdnsServiceQuery(),
}

func (e *Engine) udpCandidatePorts() []int {
	if len(e.opts.Ports) > 0 {
		return e.opts.Ports
	}
	return udpDefaultPorts
}

// probeUDP sends one budgeted, scope-checked UDP datagram and classifies the
// answer. Scope is re-checked here as defense in depth, exactly as the TCP path.
func (e *Engine) probeUDP(ctx context.Context, ip string, port int) probeResult {
	// Default before sending: FILTERED means "no packet went out, no evidence".
	pr := probeResult{
		port: port, proto: "udp", state: model.PortFiltered,
		source: "A3-udp", confidence: model.Potential,
	}
	if !e.guard.InScope(ip) || !e.budget.CanSend() {
		return pr
	}
	if err := e.budget.Acquire(ctx); err != nil {
		return pr
	}
	defer e.budget.Release()
	if err := e.budget.Throttle(ctx); err != nil {
		return pr
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := (&net.Dialer{Timeout: e.budget.ConnectTimeout}).DialContext(ctx, "udp", addr)
	if err != nil {
		return pr
	}
	defer conn.Close()

	payload := udpPayloads[port]
	if payload == nil {
		payload = []byte{0x00}
	}
	if _, err := conn.Write(payload); err != nil {
		return pr
	}

	_ = conn.SetReadDeadline(time.Now().Add(e.budget.ConnectTimeout))
	buf := make([]byte, udpReadBytes)
	n, err := conn.Read(buf)
	switch {
	case err == nil && n > 0:
		// A real reply from the port: open, and the host is provably up.
		pr.state = model.PortOpen
		pr.confidence = model.Confirmed
		pr.upProof = true
		pr.banner = udpEvidence(buf[:n])
	case isUnreachable(err):
		// ICMP port-unreachable, surfaced as ECONNREFUSED/RESET on a connected UDP
		// socket: the port is closed, which also proves the host is up.
		pr.state = model.PortClosed
		pr.upProof = true
	default:
		// Timeout or any other no-signal: honestly open|filtered, not proof of up.
		pr.state = model.PortOpenFiltered
	}
	return pr
}

// isUnreachable reports whether a UDP read error is an ICMP unreachable delivered
// to the socket (refused/reset/unreachable), which proves the port closed.
func isUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscallRefused) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "refused") ||
		strings.Contains(s, "reset") ||
		strings.Contains(s, "unreachable") ||
		strings.Contains(s, "forcibly closed")
}

// udpEvidence records a reply as its text if it is clean printable UTF-8 (e.g. an
// SSDP response), otherwise as a byte count — proof a reply arrived without
// smuggling raw binary into a string field.
func udpEvidence(b []byte) string {
	s := strings.TrimSpace(string(b))
	if s != "" && utf8.ValidString(s) {
		clean := true
		for _, r := range s {
			if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
				clean = false
				break
			}
		}
		if clean {
			return s
		}
	}
	return strconv.Itoa(len(b)) + " bytes"
}

// --- protocol-correct probe payloads ---------------------------------------

// dnsRootQuery is a standard query for the root NS records; an open resolver
// answers, and everything else stays silent.
func dnsRootQuery() []byte {
	return []byte{
		0x12, 0x34, // transaction id
		0x01, 0x00, // flags: standard query, recursion desired
		0x00, 0x01, // qdcount = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar = 0
		0x00,       // name = root
		0x00, 0x02, // qtype = NS
		0x00, 0x01, // qclass = IN
	}
}

// ntpClientRequest is a 48-byte NTPv3 client packet (LI=0, VN=3, Mode=3).
func ntpClientRequest() []byte {
	p := make([]byte, 48)
	p[0] = 0x1b
	return p
}

// snmpGetPublic is an SNMPv1 GET with community "public". An imperfect encoding
// simply goes unanswered and reads as open|filtered — never as a false open.
func snmpGetPublic() []byte {
	return []byte{
		0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
		0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
	}
}

// ssdpDiscover is the UPnP M-SEARCH discovery request (plain text).
func ssdpDiscover() []byte {
	return []byte(
		"M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 1\r\n" +
			"ST: ssdp:all\r\n\r\n")
}

// mdnsServiceQuery is a PTR query for _services._dns-sd._udp.local, the service
// enumeration name an mDNS responder answers.
func mdnsServiceQuery() []byte {
	q := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	q = append(q,
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00,
	)
	return append(q, 0x00, 0x0c, 0x00, 0x01) // qtype PTR, qclass IN
}
