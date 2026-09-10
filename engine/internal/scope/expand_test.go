package scope

import (
	"errors"
	"reflect"
	"testing"
)

// Expansion is safety-critical in both directions: dropping a host means an
// operator believes an address was scanned and clean when it was never touched,
// and over-expanding means putting packets on addresses nobody authorised.

func TestExpandSlash31YieldsBothAddresses(t *testing.T) {
	// RFC 3021: a /31 is a point-to-point link and BOTH addresses are usable.
	// The old network/broadcast trim collapsed it to one, silently skipping the
	// far end of exactly the link an operator writes a /31 to reach.
	got, err := Expand([]string{"192.0.2.4/31"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.4", "192.0.2.5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("/31 expanded to %v, want %v (RFC 3021: both addresses are hosts)", got, want)
	}
}

func TestExpandSlash32YieldsExactlyOne(t *testing.T) {
	got, err := Expand([]string{"192.0.2.7/32"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("/32 expanded to %v, want %v", got, want)
	}
}

func TestExpandTrimsNetworkAndBroadcastFromSlash30AndLarger(t *testing.T) {
	// /30 and wider genuinely have a network and a broadcast address, so the
	// trim still applies there — the /31 fix must not have removed it.
	got, err := Expand([]string{"192.0.2.4/30"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.5", "192.0.2.6"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("/30 expanded to %v, want %v", got, want)
	}

	got, err = Expand([]string{"192.0.2.0/29"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("/29 expanded to %v, want %v", got, want)
	}
}

func TestExpandIPv6KeepsEveryAddress(t *testing.T) {
	// IPv6 has no broadcast address, so nothing is trimmed at any prefix length.
	got, err := Expand([]string{"2001:db8::4/126"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::4", "2001:db8::5", "2001:db8::6", "2001:db8::7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("/126 expanded to %v, want %v", got, want)
	}

	got, err = Expand([]string{"2001:db8::8/127"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"2001:db8::8", "2001:db8::9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("/127 expanded to %v, want %v", got, want)
	}
}

func TestExpandRefusesOversizeTokenRatherThanTruncating(t *testing.T) {
	_, err := Expand([]string{"10.0.0.0/8"}, 1024)
	var tooLarge *TooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("a /8 under a 1024 cap gave err=%v, want TooLargeError", err)
	}
	if tooLarge.Size != 1<<24 {
		t.Fatalf("TooLargeError.Size = %d, want %d", tooLarge.Size, 1<<24)
	}
	// The refusal must be arithmetic — a /8 is rejected without materialising
	// 16 million strings — which this test's runtime implicitly proves.
	if tooLarge.Limit != 1024 {
		t.Fatalf("TooLargeError.Limit = %d, want 1024", tooLarge.Limit)
	}
}

func TestExpandPassesThroughBareAddressesAndUnparseableTokens(t *testing.T) {
	got, err := Expand([]string{"192.0.2.9", " ", "not-a-cidr/xx"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	// Blank tokens are dropped; anything else is passed to the scope guard,
	// which is the component allowed to refuse it.
	want := []string{"192.0.2.9", "not-a-cidr/xx"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPrefixHostCountIsArithmetic(t *testing.T) {
	cases := map[string]uint64{
		"192.0.2.0/24":  256,
		"192.0.2.4/31":  2,
		"192.0.2.7/32":  1,
		"10.0.0.0/8":    1 << 24,
		"2001:db8::/96": 1 << 32,
		// 64 host bits would overflow uint64, so the count saturates. Any value
		// past the cap is already a refusal, so the exact number is irrelevant —
		// what matters is that it never wraps to a small, passing number.
		"2001:db8::/64": ^uint64(0),
	}
	for cidr, want := range cases {
		p := mustPrefix(t, cidr)
		if got := prefixHostCount(p); got != want {
			t.Errorf("prefixHostCount(%s) = %d, want %d", cidr, got, want)
		}
	}
}
