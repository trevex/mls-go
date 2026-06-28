package sim

import "testing"

// TestInvariantConvergencePass: a converged 2-member replica passes inv. 1/3/4.
func TestInvariantConvergencePass(t *testing.T) {
	s, _, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 100)
	sigA := makeSigner()
	dir.register("client-0", sigA)
	sigB := makeSigner()
	dir.register("client-1", sigB)
	cA := newClient(ActorID(0), suite, sigA, "client-0", b, s, dir, dsIDs, m, checker, 2)
	cB := newClient(ActorID(1), suite, sigB, "client-1", b, s, dir, dsIDs, m, checker, 2)
	cA.foundVNI(100)
	cB.prospectiveVNI(100)
	cA.reconcile(100, [][]byte{[]byte("client-0"), []byte("client-1")})
	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m)
	if !cB.vnis[100].joined {
		t.Fatal("B did not join")
	}
	intended := map[uint32]map[string]bool{100: {"client-0": true, "client-1": true}}
	r := checker.Evaluate([]*Client{cA, cB}, intended)
	if !r.InvariantsHeld {
		t.Fatalf("expected held; divergence=%v membership=%v packetLoss=%v",
			r.Divergence, r.Membership, r.PacketLoss)
	}
}

// TestInvariantPacketLossCaught: a recorded packet-loss event fails inv. 2.
func TestInvariantPacketLossCaught(t *testing.T) {
	_, _, _, _, _, checker, _, _, _, _ := buildClientHarness(t, 102)
	checker.packetLoss(300, 1, 5, 50)
	r := checker.Evaluate(nil, nil)
	if r.InvariantsHeld {
		t.Fatal("expected InvariantsHeld=false for packet loss")
	}
	if len(r.PacketLoss) != 1 || r.PacketLoss[0].VNI != 300 {
		t.Fatalf("unexpected PacketLoss: %+v", r.PacketLoss)
	}
}

// TestInvariantMembership: a missing intended member fails inv. 4.
func TestInvariantMembership(t *testing.T) {
	s, _, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 103)
	sigA := makeSigner()
	dir.register("client-0", sigA)
	sigB := makeSigner()
	dir.register("client-1", sigB)
	cA := newClient(ActorID(0), suite, sigA, "client-0", b, s, dir, dsIDs, m, checker, 2)
	cB := newClient(ActorID(1), suite, sigB, "client-1", b, s, dir, dsIDs, m, checker, 2)
	cA.foundVNI(100)
	cB.prospectiveVNI(100)
	cA.reconcile(100, [][]byte{[]byte("client-0"), []byte("client-1")})
	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m)

	ok := map[uint32]map[string]bool{100: {"client-0": true, "client-1": true}}
	if len(checker.Evaluate([]*Client{cA, cB}, ok).Membership) != 0 {
		t.Fatal("unexpected membership failure on correct set")
	}
	bad := map[uint32]map[string]bool{100: {"client-0": true, "client-1": true, "client-2": true}}
	r := checker.Evaluate([]*Client{cA, cB}, bad)
	if r.InvariantsHeld || len(r.Membership) == 0 {
		t.Fatal("expected membership failure when client-2 is absent")
	}
}
