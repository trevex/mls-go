package sim

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

// ─── shared harness ───────────────────────────────────────────────────────────

func buildClientHarness(t *testing.T, seed int64) (
	s *Scheduler, f *faultState, b *Bus, m *Metrics,
	dir *kpDirectory, checker *InvariantChecker, suite cipher.Suite,
	ds0, ds1 *DS, dsIDs []ActorID,
) {
	t.Helper()
	s = NewScheduler(seed)
	f = newFaultState(FaultConfig{Latency: 1})
	m = newMetrics()
	b = newBus(s, f, m)
	checker = newInvariantChecker()
	dir = newKPDirectory()
	var ok bool
	suite, ok = cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}
	ds0 = newDS(ActorID(10), b, f)
	ds1 = newDS(ActorID(11), b, f)
	dsIDs = []ActorID{10, 11}
	return
}

// drainAll pops all queued KindDeliver events and dispatches them.
// Events for unknown actors are silently dropped (simulates selective delivery).
func drainAll(s *Scheduler, clients []*Client, dss []*DS, m *Metrics) {
	actors := map[ActorID]*Client{}
	for _, c := range clients {
		actors[c.id] = c
	}
	dsMap := map[ActorID]*DS{}
	for _, d := range dss {
		dsMap[d.id] = d
	}
	for {
		e, ok := s.Pop()
		if !ok {
			break
		}
		if e.Kind != KindDeliver {
			continue
		}
		if c, ok2 := actors[e.Actor]; ok2 {
			c.onDeliver(e.Env)
		} else if d, ok2 := dsMap[e.Actor]; ok2 {
			d.handle(e.Env, m)
		}
		// Events for unlisted actors are dropped (simulates selective delivery)
	}
}

// ─── Task 6 tests ─────────────────────────────────────────────────────────────

// TestClientFounderCommitsAdd: founder reconciles an Add; new client joins via
// Welcome; both converge to the same epoch and EpochAuthenticator.
func TestClientFounderCommitsAdd(t *testing.T) {
	s, f, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 1)

	sigA := makeSigner()
	dir.register("A", sigA)
	cA := newClient(ActorID(0), suite, sigA, "A", b, s, dir, dsIDs, m, checker, 2)

	sigB := makeSigner()
	dir.register("B", sigB)
	cB := newClient(ActorID(1), suite, sigB, "B", b, s, dir, dsIDs, m, checker, 2)

	cA.foundVNI(100)
	cB.prospectiveVNI(100)

	// A reconciles: desired = {A, B} → produces commit + welcome for B
	cA.reconcile(100, [][]byte{[]byte("A"), []byte("B")})

	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m)

	if !cB.vnis[100].joined {
		t.Fatal("B did not join via Welcome")
	}
	epochA := cA.vnis[100].ctrl.Epoch()
	epochB := cB.vnis[100].ctrl.Epoch()
	if epochA != epochB {
		t.Fatalf("epoch mismatch: A=%d B=%d", epochA, epochB)
	}
	eaA := cA.vnis[100].ctrl.Group().EpochAuthenticator()
	eaB := cB.vnis[100].ctrl.Group().EpochAuthenticator()
	if !bytes.Equal(eaA, eaB) {
		t.Fatal("EpochAuthenticator mismatch after join")
	}
	_ = f
}

// TestClientHandleStaleCommitRejected: a commit for an already-advanced base is
// silently ignored (MLS first-wins; epoch does not advance).
func TestClientHandleStaleCommitRejected(t *testing.T) {
	s, f, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 2)
	_ = f

	sigA := makeSigner()
	dir.register("A", sigA)
	cA := newClient(ActorID(0), suite, sigA, "A", b, s, dir, dsIDs, m, checker, 2)
	cA.foundVNI(100)

	// Rekey: A advances from epoch 0 → 1
	cA.rekey(100)
	drainAll(s, []*Client{cA}, []*DS{ds0, ds1}, m)

	epochAfterRekey := cA.vnis[100].ctrl.Epoch()
	if epochAfterRekey <= 0 {
		t.Fatalf("expected epoch > 0 after rekey, got %d", epochAfterRekey)
	}

	// Deliver a stale (garbage) commit for base=0 → should be ignored
	stalePayload := []byte("not-a-valid-mls-commit-for-base-0")
	env := Envelope{
		VNI:     100,
		Type:    MsgCommit,
		Base:    0,
		Payload: stalePayload,
		Hash:    contentHash(stalePayload),
	}
	cA.onDeliver(env)

	if cA.vnis[100].ctrl.Epoch() != epochAfterRekey {
		t.Fatalf("stale commit advanced epoch: expected %d, got %d",
			epochAfterRekey, cA.vnis[100].ctrl.Epoch())
	}
}

// TestClientCatchupViaLog: a member that missed a commit catches up via a
// logRequest / logReply replay from the DS.
func TestClientCatchupViaLog(t *testing.T) {
	s, f, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 3)
	_ = f

	sigA := makeSigner()
	dir.register("A", sigA)
	cA := newClient(ActorID(0), suite, sigA, "A", b, s, dir, dsIDs, m, checker, 2)

	sigB := makeSigner()
	dir.register("B", sigB)
	cB := newClient(ActorID(1), suite, sigB, "B", b, s, dir, dsIDs, m, checker, 2)

	// Build a 2-member group
	cA.foundVNI(100)
	cB.prospectiveVNI(100)
	cA.reconcile(100, [][]byte{[]byte("A"), []byte("B")})
	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m)

	if !cB.vnis[100].joined {
		t.Fatal("B did not join in setup phase")
	}
	epochAfterJoin := cA.vnis[100].ctrl.Epoch()

	// B "goes offline": unsubscribe so it misses the next commit
	b.Unsubscribe(100, cB.id)

	// A rekeys — B misses this commit
	cA.rekey(100)
	drainAll(s, []*Client{cA}, []*DS{ds0, ds1}, m) // drain without B

	epochAfterRekey := cA.vnis[100].ctrl.Epoch()
	if epochAfterRekey <= epochAfterJoin {
		t.Fatalf("A did not advance via rekey: epoch still %d", epochAfterRekey)
	}
	if cB.vnis[100].ctrl.Epoch() != epochAfterJoin {
		t.Fatalf("B should still be at %d, got %d", epochAfterJoin, cB.vnis[100].ctrl.Epoch())
	}

	// B comes back online
	b.Subscribe(100, cB.id)

	// Simulate B discovering A is ahead (e.g., via heartbeat) and requesting catch-up
	cB.vnis[100].peerEpoch[cA.id] = epochAfterRekey
	cB.requestCatchup(100, cB.vnis[100].ctrl.Epoch())

	// Drain: DS serves logReply → B applies the missed commit
	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m)

	if cB.vnis[100].ctrl.Epoch() != epochAfterRekey {
		t.Fatalf("B did not catch up: expected epoch %d, got %d",
			epochAfterRekey, cB.vnis[100].ctrl.Epoch())
	}
	eaA := cA.vnis[100].ctrl.Group().EpochAuthenticator()
	eaB := cB.vnis[100].ctrl.Group().EpochAuthenticator()
	if !bytes.Equal(eaA, eaB) {
		t.Fatal("EpochAuthenticator mismatch after catch-up")
	}
}
