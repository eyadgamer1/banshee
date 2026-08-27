package scan

import (
	"context"
	"net"
	"testing"

	"github.com/eyadgamer1/banshee/engine/internal/budget"
	"github.com/eyadgamer1/banshee/engine/internal/model"
)

// Ground truth for UDP, the hard part of an honest scanner. We bind real UDP
// sockets on loopback whose true state we control, then assert the engine's
// classification matches — including the one that matters most: a silent port is
// reported open|filtered and NEVER as a plain "open".

// udpResponder binds a UDP socket that replies to any datagram: provably OPEN.
func udpResponder(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo([]byte("PONG"), addr)
			_ = n
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// udpSilent binds a UDP socket that drains datagrams but never replies: the
// port is open, yet indistinguishable from filtered — must read open|filtered.
func udpSilent(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// closedUDPPort reserves a UDP port and releases it, so nothing is bound.
func closedUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return p
}

func TestUDPClassifiesOpenSilentClosedHonestly(t *testing.T) {
	open := udpResponder(t)
	silent := udpSilent(t)
	closed := closedUDPPort(t)

	eng := NewEngine(loopbackScope(t), normalBudget(), Options{
		UDP:   true,
		Ports: []int{open, silent, closed},
	})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("expected the responder to prove the host up, got %d hosts", len(res.Hosts))
	}
	svc := map[int]model.Service{}
	for _, s := range res.Hosts[0].Services {
		svc[s.Port] = s
	}

	// Open: a real reply is CONFIRMED open over udp.
	if s, ok := svc[open]; !ok || s.State != model.PortOpen ||
		s.Proto != "udp" || s.Confidence != model.Confirmed {
		t.Fatalf("responder port not CONFIRMED-open udp: %+v (present=%v)", svc[open], ok)
	}
	// Silent: the anti-fabrication invariant — open|filtered, POTENTIAL, never open.
	if s, ok := svc[silent]; !ok || s.State != model.PortOpenFiltered ||
		s.Confidence != model.Potential {
		t.Fatalf("silent port must be open|filtered/potential, got %+v (present=%v)", svc[silent], ok)
	}
	// Closed: whatever else, it must NEVER be reported open.
	if s, ok := svc[closed]; ok && s.State == model.PortOpen {
		t.Fatalf("closed udp port was fabricated as open: %+v", s)
	}
	if res.Stats.PacketsSent == 0 {
		t.Fatal("udp scan reported zero packets sent")
	}
}

func TestUDPSilenceAloneNeverInventsAHost(t *testing.T) {
	// A host whose only probed port is a silent UDP port is NOT proven up — silence
	// is no evidence — so nothing may be reported.
	silent := udpSilent(t)
	eng := NewEngine(loopbackScope(t), normalBudget(), Options{UDP: true, Ports: []int{silent}})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 0 {
		t.Fatalf("open|filtered silence invented a host: %+v", res.Hosts)
	}
}

func TestUDPPassiveSendsZeroPackets(t *testing.T) {
	open := udpResponder(t) // answering, but passive must not send a datagram
	passive := budget.New(budget.Options{Mode: budget.Passive})
	eng := NewEngine(loopbackScope(t), passive, Options{UDP: true, Ports: []int{open}})
	res, err := eng.Run(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.PacketsSent != 0 {
		t.Fatalf("passive udp sent %d packets; must send 0", res.Stats.PacketsSent)
	}
	if len(res.Hosts) != 0 {
		t.Fatal("passive udp claimed a host without sending a packet")
	}
}
