package scan

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The Python bridge deserializes this engine's JSON straight into pydantic
// models, which reject null for a list field. Go marshals a nil slice as null,
// so a host that answers with no open ports — or a scan that finds no hosts —
// must still emit [] for services/findings/hosts. This pins that contract; if it
// regresses, the --engine go path breaks with a pydantic list_type error.
func TestEmptyCollectionsSerializeAsArraysNotNull(t *testing.T) {
	closed := freePort(t) // refused connect proves the host up with no open ports
	eng := NewEngine(loopbackScope(t), normalBudget(), Options{Ports: []int{closed}})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("expected the refused host to be up, got %d hosts", len(res.Hosts))
	}

	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, bad := range []string{`"services":null`, `"findings":null`, `"hosts":null`} {
		if strings.Contains(s, bad) {
			t.Fatalf("wire contract broken: JSON contains %s in\n%s", bad, s)
		}
	}
	if !strings.Contains(s, `"services":[]`) || !strings.Contains(s, `"findings":[]`) {
		t.Fatalf("expected empty services/findings serialized as []: %s", s)
	}
}

// A scan with no in-scope hosts must still emit "hosts":[], not null.
func TestNoHostsSerializesAsEmptyArray(t *testing.T) {
	eng := NewEngine(loopbackScope(t), normalBudget(), Options{Ports: []int{freePort(t)}})
	res, err := eng.Run(context.Background(), []string{"8.8.8.8"}) // out of scope
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"hosts":null`) {
		t.Fatalf("empty scan emitted hosts:null: %s", raw)
	}
}
