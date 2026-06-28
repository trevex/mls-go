package sim

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

// ─── shared harness ───────────────────────────────────────────────────────────

// buildClientHarness builds a scheduler/bus/two-reflector harness. Channel 100 is
// even ⇒ replica 0 ⇒ ordered by ds0 (ActorID 10).
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
	ds0 = newDS(ActorID(10), 0, b, f)
	ds1 = newDS(ActorID(11), 1, b, f)
	dsIDs = []ActorID{10, 11}
	return
}

// drainAll pops all queued KindDeliver events and dispatches them.
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
	}
}

// TestClientFounderCommitsAdd: founder commits an Add; the new client joins via
// Welcome; both converge to byte-equal epoch + EpochAuthenticator.
func TestClientFounderCommitsAdd(t *testing.T) {
	s, _, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 1)

	sigA := makeSigner()
	dir.register("client-0", sigA)
	cA := newClient(ActorID(0), suite, sigA, "client-0", b, s, dir, dsIDs, m, checker, 2)
	sigB := makeSigner()
	dir.register("client-1", sigB)
	cB := newClient(ActorID(1), suite, sigB, "client-1", b, s, dir, dsIDs, m, checker, 2)

	cA.foundVNI(100)
	cB.prospectiveVNI(100)

	cA.reconcile(100, [][]byte{[]byte("client-0"), []byte("client-1")})
	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m)

	if !cB.vnis[100].joined {
		t.Fatal("B did not join via Welcome")
	}
	if cA.vnis[100].ctrl.Epoch() != cB.vnis[100].ctrl.Epoch() {
		t.Fatalf("epoch mismatch: A=%d B=%d", cA.vnis[100].ctrl.Epoch(), cB.vnis[100].ctrl.Epoch())
	}
	if !bytes.Equal(cA.vnis[100].ctrl.Group().EpochAuthenticator(), cB.vnis[100].ctrl.Group().EpochAuthenticator()) {
		t.Fatal("EpochAuthenticator mismatch after join")
	}
}

// TestClientHandleStaleCommitRejected: a commit for an already-advanced base is ignored.
func TestClientHandleStaleCommitRejected(t *testing.T) {
	s, _, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 2)

	sigA := makeSigner()
	dir.register("client-0", sigA)
	cA := newClient(ActorID(0), suite, sigA, "client-0", b, s, dir, dsIDs, m, checker, 2)
	cA.foundVNI(100)

	cA.rekey(100)
	drainAll(s, []*Client{cA}, []*DS{ds0, ds1}, m)
	after := cA.vnis[100].ctrl.Epoch()
	if after == 0 {
		t.Fatal("rekey did not advance epoch")
	}

	stale := []byte("not-a-valid-mls-commit-for-base-0")
	cA.onDeliver(Envelope{VNI: 100, Type: MsgCommit, Base: 0, Payload: stale, Hash: contentHash(stale)})
	if cA.vnis[100].ctrl.Epoch() != after {
		t.Fatalf("stale commit advanced epoch: %d -> %d", after, cA.vnis[100].ctrl.Epoch())
	}
}

// TestClientCatchupViaLog: a member that missed a commit catches up via log replay.
func TestClientCatchupViaLog(t *testing.T) {
	s, _, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 3)

	sigA := makeSigner()
	dir.register("client-0", sigA)
	cA := newClient(ActorID(0), suite, sigA, "client-0", b, s, dir, dsIDs, m, checker, 2)
	sigB := makeSigner()
	dir.register("client-1", sigB)
	cB := newClient(ActorID(1), suite, sigB, "client-1", b, s, dir, dsIDs, m, checker, 2)

	cA.foundVNI(100)
	cB.prospectiveVNI(100)
	cA.reconcile(100, [][]byte{[]byte("client-0"), []byte("client-1")})
	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m)
	if !cB.vnis[100].joined {
		t.Fatal("B did not join in setup")
	}
	joinEpoch := cA.vnis[100].ctrl.Epoch()

	// B goes offline; A rekeys; B misses it.
	b.Unsubscribe(100, cB.id)
	cA.rekey(100)
	drainAll(s, []*Client{cA}, []*DS{ds0, ds1}, m)
	rekeyEpoch := cA.vnis[100].ctrl.Epoch()
	if rekeyEpoch <= joinEpoch {
		t.Fatalf("A did not advance via rekey")
	}
	if cB.vnis[100].ctrl.Epoch() != joinEpoch {
		t.Fatalf("B should still be at %d", joinEpoch)
	}

	// B returns and catches up via log replay.
	b.Subscribe(100, cB.id)
	cB.vnis[100].peerEpoch[cA.id] = rekeyEpoch
	cB.requestCatchup(100, cB.vnis[100].ctrl.Epoch())
	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m)

	if cB.vnis[100].ctrl.Epoch() != rekeyEpoch {
		t.Fatalf("B did not catch up: want %d got %d", rekeyEpoch, cB.vnis[100].ctrl.Epoch())
	}
	if !bytes.Equal(cA.vnis[100].ctrl.Group().EpochAuthenticator(), cB.vnis[100].ctrl.Group().EpochAuthenticator()) {
		t.Fatal("EpochAuthenticator mismatch after catch-up")
	}
}

// TestSACacheRetainsW: after > W epochs, saCache holds exactly the last W+1 epochs.
func TestSACacheRetainsW(t *testing.T) {
	s, _, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 20)

	sigA := makeSigner()
	dir.register("client-0", sigA)
	cA := newClient(ActorID(0), suite, sigA, "client-0", b, s, dir, dsIDs, m, checker, 2)
	cA.foundVNI(100)
	if len(cA.vnis[100].saCache) == 0 {
		t.Fatal("saCache empty after foundVNI")
	}

	W := cA.W
	for i := 0; i < W+3; i++ {
		cA.rekey(100)
		drainAll(s, []*Client{cA}, []*DS{ds0, ds1}, m)
	}
	cur := cA.vnis[100].ctrl.Epoch()
	cache := cA.vnis[100].saCache
	if len(cache) != W+1 {
		t.Fatalf("saCache size: want %d got %d", W+1, len(cache))
	}
	for e := range cache {
		if e < cur-uint64(W) || e > cur {
			t.Fatalf("out-of-window epoch %d (cur=%d W=%d)", e, cur, W)
		}
	}
}

// TestSendEpochIsMin: sendEpoch is the min over own + peer epochs.
func TestSendEpochIsMin(t *testing.T) {
	s, _, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 21)

	sigA := makeSigner()
	dir.register("client-0", sigA)
	cA := newClient(ActorID(0), suite, sigA, "client-0", b, s, dir, dsIDs, m, checker, 2)
	cA.foundVNI(100)

	if cA.sendEpoch(100) != 0 {
		t.Fatalf("sendEpoch no peers: want 0 got %d", cA.sendEpoch(100))
	}
	for i := 0; i < 3; i++ {
		cA.rekey(100)
		drainAll(s, []*Client{cA}, []*DS{ds0, ds1}, m)
	}
	if cA.sendEpoch(100) != 3 {
		t.Fatalf("sendEpoch no peers at 3: got %d", cA.sendEpoch(100))
	}
	cA.vnis[100].peerEpoch[ActorID(5)] = 1
	if cA.sendEpoch(100) != 1 {
		t.Fatalf("sendEpoch with peer 1: got %d", cA.sendEpoch(100))
	}
	cA.vnis[100].peerEpoch[ActorID(6)] = 2
	if cA.sendEpoch(100) != 1 {
		t.Fatalf("sendEpoch with peers 1,2: got %d", cA.sendEpoch(100))
	}
	delete(cA.vnis[100].peerEpoch, ActorID(5))
	if cA.sendEpoch(100) != 2 {
		t.Fatalf("sendEpoch after removing slow peer: got %d", cA.sendEpoch(100))
	}
}

// TestDataDecryptableUnderLag: a packet sent at the group min-epoch is decryptable
// by a lagging receiver under W=2 — zero key-loss.
func TestDataDecryptableUnderLag(t *testing.T) {
	s, _, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 22)

	sigA := makeSigner()
	dir.register("client-0", sigA)
	cA := newClient(ActorID(0), suite, sigA, "client-0", b, s, dir, dsIDs, m, checker, 2)
	sigB := makeSigner()
	dir.register("client-1", sigB)
	cB := newClient(ActorID(1), suite, sigB, "client-1", b, s, dir, dsIDs, m, checker, 2)

	cA.foundVNI(100)
	cB.prospectiveVNI(100)
	cA.reconcile(100, [][]byte{[]byte("client-0"), []byte("client-1")})
	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m)
	if !cB.vnis[100].joined {
		t.Fatal("B did not join")
	}

	cA.vnis[100].peerEpoch[cB.id] = cB.vnis[100].ctrl.Epoch()
	cA.vnis[100].heard[cB.id] = true

	// A rekeys; B misses → A ahead of B.
	cA.rekey(100)
	drainAll(s, []*Client{cA}, []*DS{ds0, ds1}, m)
	epochB := cB.vnis[100].ctrl.Epoch()
	cA.vnis[100].peerEpoch[cB.id] = epochB

	if cA.sendEpoch(100) != epochB {
		t.Fatalf("sendEpoch should lag to B's epoch %d, got %d", epochB, cA.sendEpoch(100))
	}
	if _, ok := cA.vnis[100].saCache[epochB]; !ok {
		t.Fatalf("A missing send-epoch SA %d", epochB)
	}

	// sendData is tenant-level: tenant = saVNI(0,0)=0 → channel 100 is saVNI(50,0).
	// Drive the per-pair sender directly via the tenant of channel 100.
	cA.sendData(tenantOf(100))
	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m)

	if len(checker.lossEvents) > 0 {
		t.Fatalf("packet loss under W=2 lag=1: %+v", checker.lossEvents)
	}
	if m.DataDecryptable == 0 {
		t.Fatal("no DataDecryptable events recorded")
	}
}
