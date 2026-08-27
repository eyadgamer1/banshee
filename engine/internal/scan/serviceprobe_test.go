package scan

import (
	"context"
	"net"
	"testing"
	"time"
)

// Service/version identification must be match-only: a product and version are
// reported solely from bytes a service actually sent, never guessed from a port.
// These tests hold the -sV path to that promise, the same anti-fabrication bar
// the rest of the engine meets.

func TestMatchServiceIsMatchOnly(t *testing.T) {
	cases := []struct {
		name, banner, product, version string
	}{
		{"ssh", "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13", "OpenSSH", "6.6.1p1"},
		{"ssh-short", "SSH-2.0-OpenSSH_9.6", "OpenSSH", "9.6"},
		{"http-server", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 (Ubuntu)\r\n", "Apache", "2.4.7"},
		{"ftp", "220 (vsFTPd 3.0.2)", "vsFTPd", "3.0.2"},
		{"generic", "nginx/1.18.0", "nginx", "1.18.0"},
		// Negative: a banner with no version token yields nothing — never a guess.
		{"no-version", "220 mail.example ESMTP ready", "", ""},
		{"junk", "hello there", "", ""},
		{"empty", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, v := matchService(c.banner)
			if p != c.product || v != c.version {
				t.Fatalf("matchService(%q) = (%q,%q), want (%q,%q)", c.banner, p, v, c.product, c.version)
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
	if p, v := matchService(got); p != "TestHTTPd" || v != "1.2.3" {
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
