package scope

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The scope guard is the tool's authoritative safety boundary: it refuses rather
// than warns, and there is no override flag. These tests pin that contract.

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad test prefix %q: %v", s, err)
	}
	return p
}

// writeScope writes a scope file and returns its path.
func writeScope(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadScope(t *testing.T, body string) *Guard {
	t.Helper()
	g, err := Load(writeScope(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func TestLoadRefusesEmptyAllowlist(t *testing.T) {
	_, err := Load(writeScope(t, "banner: TEST\nallowlist: []\ndenylist: []\n"))
	if err == nil {
		t.Fatal("Load accepted an empty allowlist; it must refuse to run with no scope")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("error should name the allowlist, got %v", err)
	}
}

func TestDenylistBeatsAllowlist(t *testing.T) {
	g := loadScope(t, "allowlist:\n  - 10.0.0.0/8\ndenylist:\n  - 10.1.2.0/24\n")
	if !g.InScope("10.9.9.9") {
		t.Error("10.9.9.9 should be in scope via the allowlist")
	}
	if g.InScope("10.1.2.3") {
		t.Error("a denied address inside an allowed range was reported in scope")
	}
	if g.InScope("192.0.2.1") {
		t.Error("an address in neither list was reported in scope; scope is allowlist-only")
	}
	if g.InScope("not-an-ip") {
		t.Error("an unparseable target was reported in scope")
	}
}

func TestBareAddressEntryIsASingleHost(t *testing.T) {
	g := loadScope(t, "allowlist:\n  - 192.0.2.10\n  - 2001:db8::1\n")
	if !g.InScope("192.0.2.10") || !g.InScope("2001:db8::1") {
		t.Error("a bare address entry should put exactly that host in scope")
	}
	if g.InScope("192.0.2.11") {
		t.Error("a bare address entry widened to its neighbours")
	}
}

func TestFilterPartitionsPreservingOrder(t *testing.T) {
	g := loadScope(t, "allowlist:\n  - 192.0.2.0/24\n")
	in, out := g.Filter([]string{"192.0.2.1", "10.0.0.1", "192.0.2.2", "bogus"})
	if want := []string{"192.0.2.1", "192.0.2.2"}; strings.Join(in, ",") != strings.Join(want, ",") {
		t.Errorf("in-scope = %v, want %v", in, want)
	}
	if want := []string{"10.0.0.1", "bogus"}; strings.Join(out, ",") != strings.Join(want, ",") {
		t.Errorf("out-of-scope = %v, want %v", out, want)
	}
}

// TestMaxPortsPerHostIsLoaded covers the parsing half of the setting whose
// enforcement half was missing entirely — a scope file that set it was parsed,
// stored, and then ignored by every probe path. The enforcement itself is
// pinned in the scan package (TestScopePortCapLimitsPortsProbed).
func TestMaxPortsPerHostIsLoaded(t *testing.T) {
	g := loadScope(t, "allowlist:\n  - 192.0.2.0/24\nmax_ports_per_host: 5\n")
	if g.MaxPortsPerHost != 5 {
		t.Fatalf("MaxPortsPerHost = %d, want 5", g.MaxPortsPerHost)
	}
}

func TestScopeDefaultsAreConservative(t *testing.T) {
	g := loadScope(t, "allowlist:\n  - 192.0.2.0/24\n")
	if g.MaxHostsPerScan != 1024 {
		t.Errorf("default MaxHostsPerScan = %d, want 1024", g.MaxHostsPerScan)
	}
	if g.MaxPortsPerHost != 1000 {
		t.Errorf("default MaxPortsPerHost = %d, want 1000", g.MaxPortsPerHost)
	}
	if g.Banner == "" {
		t.Error("an unset banner should fall back to the authorized-targets warning")
	}
}

func TestLoadRejectsMalformedEntries(t *testing.T) {
	if _, err := Load(writeScope(t, "allowlist:\n  - 192.0.2.0/33\n")); err == nil {
		t.Error("Load accepted an impossible prefix length")
	}
	if _, err := Load(writeScope(t, "allowlist:\n  - \"nonsense\"\n")); err == nil {
		t.Error("Load accepted a non-address allowlist entry")
	}
	if _, err := Load(writeScope(t, "allowlist: [oops\n")); err == nil {
		t.Error("Load accepted malformed YAML")
	}
}
