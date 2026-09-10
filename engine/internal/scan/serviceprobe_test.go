package scan

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/eyadgamer1/banshee/engine/internal/model"
)

// Service/version identification must be match-only: a product and version are
// reported solely from bytes a service actually sent, never guessed from a port.
// These tests hold the -sV path to that promise, the same anti-fabrication bar
// the rest of the engine meets.

func TestMatchServiceIsMatchOnly(t *testing.T) {
	cases := []struct {
		name, banner, product, version string
		specific                       bool
	}{
		{"ssh", "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13", "OpenSSH", "6.6.1p1", true},
		{"ssh-short", "SSH-2.0-OpenSSH_9.6", "OpenSSH", "9.6", true},
		{"http-server", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 (Ubuntu)\r\n", "Apache", "2.4.7", true},
		{"ftp", "220 (vsFTPd 3.0.2)", "vsFTPd", "3.0.2", true},
		// Not a named signature — only the generic fallback fires, so this is
		// weaker evidence (PROBABLE, not CONFIRMED) even though a token matched.
		{"generic", "nginx/1.18.0", "nginx", "1.18.0", false},
		// Negative: a banner with no version token yields nothing — never a guess.
		{"no-version", "220 mail.example ESMTP ready", "", "", false},
		{"junk", "hello there", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, v, specific := matchService(c.banner)
			if p != c.product || v != c.version {
				t.Fatalf("matchService(%q) = (%q,%q), want (%q,%q)", c.banner, p, v, c.product, c.version)
			}
			if specific != c.specific {
				t.Fatalf("matchService(%q) specific = %v, want %v", c.banner, specific, c.specific)
			}
		})
	}
}

// The free layer: a server that speaks first is version-identified with no
// active probe and no -sV flag.
func TestServiceVersionFromServerFirstBanner(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n"))
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}()
	port := l.Addr().(*net.TCPAddr).Port

	eng := NewEngine(loopbackScope(t), normalBudget(), Options{Ports: []int{port}, Banners: true})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Hosts[0].Services[0]
	if svc.Product == nil || *svc.Product != "OpenSSH" || svc.Version == nil || *svc.Version != "8.9p1" {
		t.Fatalf("version not extracted from server-first banner: product=%v version=%v", svc.Product, svc.Version)
	}
	// SSH is a named signature: a match is CONFIRMED, not just PROBABLE.
	if svc.VersionConfidence == nil || *svc.VersionConfidence != model.Confirmed {
		t.Fatalf("named-signature match should be CONFIRMED, got %v", svc.VersionConfidence)
	}
}

// A banner that only matches the generic "Product/1.2.3" fallback (not a named
// signature) still reports product/version — but graded PROBABLE, since the
// token isn't tied to a recognized product family and could be spoofed or
// coincidental. This is the corroboration signal risk/__init__.py consumes to
// avoid presenting an unverified guess with the same weight as a real match.
func TestUnnamedProductMatchIsGradedProbable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("Definitely-Not-A-Honeypot/9.9.9\r\n"))
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}()
	port := l.Addr().(*net.TCPAddr).Port

	eng := NewEngine(loopbackScope(t), normalBudget(), Options{Ports: []int{port}, Banners: true})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Hosts[0].Services[0]
	if svc.Product == nil || *svc.Product != "Definitely-Not-A-Honeypot" {
		t.Fatalf("expected generic signature to still capture the token, got product=%v", svc.Product)
	}
	if svc.VersionConfidence == nil || *svc.VersionConfidence != model.Probable {
		t.Fatalf("unnamed product match should be graded PROBABLE, got %v", svc.VersionConfidence)
	}
}

// The active layer: -sV draws a Server header out of an HTTP port that does not
// speak first, and is inert on a non-HTTP port.
func TestActiveBannerElicitsVersionOnlyForHTTPPorts(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := c.Read(buf); err != nil { // wait for the GET
				c.Close()
				continue
			}
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: TestHTTPd/1.2.3\r\n\r\n"))
			c.Close()
		}
	}()
	addr := l.Addr().String()

	// HTTP-classed port -> probe fires, version extracted.
	c1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	got := activeBanner(c1, 80)
	if p, v, _ := matchService(got); p != "TestHTTPd" || v != "1.2.3" {
		t.Fatalf("active HTTP probe: matchService(%q) = (%q,%q), want (TestHTTPd,1.2.3)", got, p, v)
	}

	// Non-HTTP port -> no probe sent, no banner.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if got := activeBanner(c2, 22); got != "" {
		t.Fatalf("active probe fired on non-HTTP port 22: %q", got)
	}
}

// weakBanner/preferBanner are the pure decision logic behind -sV's
// disambiguating probe: does this passive capture deserve a second attempt,
// and if we made one, which result do we keep. Tested directly (the same
// pattern TestActiveBannerElicitsVersionOnlyForHTTPPorts already uses for
// activeBanner) rather than through a live socket, because the real trigger
// (httpLikePorts) is keyed on a fixed port list that a test can't bind to
// reliably — 80/8080/etc are shared, sometimes-privileged, sometimes-busy
// ports, unlike the ephemeral ports `net.Listen("tcp", "127.0.0.1:0")` hands
// out elsewhere in this file.
func TestWeakBannerDetectsMissingOrGenericMatch(t *testing.T) {
	cases := []struct {
		name, banner string
		weak         bool
	}{
		{"empty", "", true},
		{"no-match", "220 mail.example ESMTP ready", true},
		// Matches only the generic fallback ("HTTP" + "/1.1") — still weak.
		{"generic-http-line", "HTTP/1.1 200 OK\r\n\r\n", true},
		{"named-ssh", "SSH-2.0-OpenSSH_9.9p1 Test", false},
		{"named-server-header", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7\r\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := weakBanner(c.banner); got != c.weak {
				t.Fatalf("weakBanner(%q) = %v, want %v", c.banner, got, c.weak)
			}
		})
	}
}

func TestPreferBannerPicksTheStrongerIdentification(t *testing.T) {
	cases := []struct {
		name, passive, active, want string
	}{
		{
			name:    "active resolves an empty passive banner",
			passive: "", active: "HTTP/1.1 200 OK\r\nServer: TestHTTPd/1.2.3\r\n",
			want: "HTTP/1.1 200 OK\r\nServer: TestHTTPd/1.2.3\r\n",
		},
		{
			name:    "active disambiguates a weak passive banner",
			passive: "HTTP/1.1 200 OK\r\n\r\n", active: "HTTP/1.1 200 OK\r\nServer: TestHTTPd/1.2.3\r\n",
			want: "HTTP/1.1 200 OK\r\nServer: TestHTTPd/1.2.3\r\n",
		},
		{
			name:    "no active reply keeps the passive banner",
			passive: "HTTP/1.1 200 OK\r\n\r\n", active: "",
			want: "HTTP/1.1 200 OK\r\n\r\n",
		},
		{
			name:    "an equally weak active reply does not discard a real passive capture",
			passive: "nginx/1.18.0", active: "SomethingElse/9.9",
			want: "nginx/1.18.0",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := preferBanner(c.passive, c.active); got != c.want {
				t.Fatalf("preferBanner(%q, %q) = %q, want %q", c.passive, c.active, got, c.want)
			}
		})
	}
}

// A weak/no passive banner on a non-HTTP port must not be replaced by garbage:
// activeBanner's httpLikePorts gate makes the disambiguation attempt a no-op,
// so the original (possibly empty) banner is left exactly as it was.
func TestDisambiguationIsNoOpOnNonHTTPPorts(t *testing.T) {
	port := listen(t) // accepts then closes; never speaks
	eng := NewEngine(loopbackScope(t), normalBudget(), Options{
		Ports: []int{port}, Banners: true, ServiceScan: true,
	})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Hosts[0].Services[0]
	if svc.Product != nil || svc.Version != nil || svc.VersionConfidence != nil {
		t.Fatalf("non-HTTP silent port must stay unidentified: product=%v version=%v conf=%v",
			svc.Product, svc.Version, svc.VersionConfidence)
	}
}

// Honesty end to end: with -sV on, a silent non-HTTP open port is still reported
// with no product/version — silence is never turned into an identity.
func TestServiceScanNeverInventsVersionOnSilentPort(t *testing.T) {
	port := listen(t) // accepts then closes; never speaks
	eng := NewEngine(loopbackScope(t), normalBudget(), Options{
		Ports: []int{port}, Banners: true, ServiceScan: true,
	})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Hosts[0].Services[0]
	if svc.Product != nil || svc.Version != nil {
		t.Fatalf("silent port got a fabricated identity: product=%v version=%v", svc.Product, svc.Version)
	}
}
