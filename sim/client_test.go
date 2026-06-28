package sim

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
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

// ─── Task 7 tests ─────────────────────────────────────────────────────────────

// TestForkResolveSingleLoser: client C is placed on a non-canonical fork branch
// by injecting seen/applied state directly. After forkResolve is called, C must
// AutoRecover to the canonical GroupInfo (A's branch), broadcast a recovery
// commit, and all members converge to byte-equal EpochAuthenticator + SA key.
// With stub forkResolve (Task 6), C stays at baseEpoch and the epoch assertion
// fires → this test FAILS until the real implementation is in place.
func TestForkResolveSingleLoser(t *testing.T) {
	s, _, b, m, dir, checker, suite, ds0, ds1, dsIDs := buildClientHarness(t, 10)

	// Build a 3-member group (A = committer, B, C).
	sigA := makeSigner(); dir.register("A", sigA)
	sigB := makeSigner(); dir.register("B", sigB)
	sigC := makeSigner(); dir.register("C", sigC)

	cA := newClient(ActorID(0), suite, sigA, "A", b, s, dir, dsIDs, m, checker, 2)
	cB := newClient(ActorID(1), suite, sigB, "B", b, s, dir, dsIDs, m, checker, 2)
	cC := newClient(ActorID(2), suite, sigC, "C", b, s, dir, dsIDs, m, checker, 2)

	cA.foundVNI(100)
	cB.prospectiveVNI(100)
	cC.prospectiveVNI(100)

	cA.reconcile(100, [][]byte{[]byte("A"), []byte("B")})
	drainAll(s, []*Client{cA, cB, cC}, []*DS{ds0, ds1}, m)
	if !cB.vnis[100].joined {
		t.Fatal("B did not join")
	}
	cA.reconcile(100, [][]byte{[]byte("A"), []byte("B"), []byte("C")})
	drainAll(s, []*Client{cA, cB, cC}, []*DS{ds0, ds1}, m)
	if !cC.vnis[100].joined {
		t.Fatal("C did not join")
	}

	baseEpoch := cA.vnis[100].ctrl.Epoch()

	// A rekeys (canonical branch). Drain for A and B only; C silently misses it.
	cA.rekey(100)
	drainAll(s, []*Client{cA, cB}, []*DS{ds0, ds1}, m) // C's events silently dropped

	if cA.vnis[100].ctrl.Epoch() <= baseEpoch {
		t.Fatal("A did not advance via rekey")
	}
	if cC.vnis[100].ctrl.Epoch() != baseEpoch {
		t.Fatalf("C should still be at baseEpoch=%d, got %d",
			baseEpoch, cC.vnis[100].ctrl.Epoch())
	}

	// canonicalRef = the commit hash B successfully applied at baseEpoch.
	canonicalRef := string(cB.vnis[100].applied[baseEpoch])
	if canonicalRef == "" {
		t.Fatal("B did not record applied ref for baseEpoch")
	}

	// Get A's canonical GroupInfo at epoch baseEpoch+1.
	gi, err := cA.vnis[100].ctrl.PublishGroupInfo()
	if err != nil {
		t.Fatal("PublishGroupInfo:", err)
	}
	gb, _ := gi.MarshalMLS()

	// Craft a fake competing ref (distinct hash from canonical).
	fakeRef := contentHash([]byte("fake-non-canonical-commit"))

	// Determine which ref is canonical; set C's applied to the NON-canonical one
	// so that forkResolve detects C is off-canonical and triggers AutoRecover.
	refs := []group.CommitRef{[]byte(fakeRef), []byte(canonicalRef)}
	winner := sequencer.CanonicalCommit(suite, refs)
	var appliedRef string
	if string(winner) == canonicalRef {
		appliedRef = fakeRef
	} else {
		appliedRef = canonicalRef
	}

	// Inject fork state into C: two refs seen, C applied the non-canonical one.
	// Store the valid GroupInfo for BOTH refs so fetchGI always succeeds.
	key := vniKey(100, baseEpoch)
	cC.vnis[100].seen[key] = [][]byte{[]byte(fakeRef), []byte(canonicalRef)}
	cC.vnis[100].applied[baseEpoch] = []byte(appliedRef)
	cC.vnis[100].giByRef[fakeRef] = gb
	cC.vnis[100].giByRef[canonicalRef] = gb

	// forkResolve: with stub → no-op, C stays at baseEpoch → epoch assertion fails.
	// With real impl → C calls AutoRecover → C advances, broadcasts recovery commit.
	cC.forkResolve(100, baseEpoch)

	// Drain: C's recovery commit propagates to A and B (they advance too).
	drainAll(s, []*Client{cA, cB, cC}, []*DS{ds0, ds1}, m)

	epochA := cA.vnis[100].ctrl.Epoch()
	epochC := cC.vnis[100].ctrl.Epoch()
	if epochA != epochC {
		t.Fatalf("epoch mismatch after recovery: A=%d C=%d (fork not resolved)", epochA, epochC)
	}
	eaA := cA.vnis[100].ctrl.Group().EpochAuthenticator()
	eaC := cC.vnis[100].ctrl.Group().EpochAuthenticator()
	if !bytes.Equal(eaA, eaC) {
		t.Fatal("EpochAuthenticator mismatch after fork resolution")
	}
	saA, _ := cA.vnis[100].ctrl.CurrentSA()
	saC, _ := cC.vnis[100].ctrl.CurrentSA()
	if !bytes.Equal(saA.Key, saC.Key) {
		t.Fatal("SA key mismatch after fork resolution")
	}
}

// TestForkResolveTwoLosers: verifies CanonicalCommit tie-break is
// order-independent (the core invariant for multi-loser convergence — de-risk
// #2 finding). Any two losers independently computing CanonicalCommit on the
// same ref set always agree on the winner.
func TestForkResolveTwoLosers(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}

	// Use real suite hashes to simulate two competing commit refs.
	commitRef1 := group.CommitRef(suite.Hash([]byte("competing-branch-A")))
	commitRef2 := group.CommitRef(suite.Hash([]byte("competing-branch-B")))

	refs := []group.CommitRef{commitRef1, commitRef2}
	canon := sequencer.CanonicalCommit(suite, refs)
	if canon == nil {
		t.Fatal("CanonicalCommit returned nil for non-empty candidates")
	}
	if string(canon) != string(commitRef1) && string(canon) != string(commitRef2) {
		t.Fatal("CanonicalCommit returned unexpected ref")
	}

	// Order-independence: reversed input → same winner.
	refs2 := []group.CommitRef{commitRef2, commitRef1}
	canon2 := sequencer.CanonicalCommit(suite, refs2)
	if string(canon) != string(canon2) {
		t.Fatal("CanonicalCommit is NOT order-independent (multi-loser convergence broken)")
	}

	// Three-way tie: add a third ref; winner is still deterministic.
	commitRef3 := group.CommitRef(suite.Hash([]byte("competing-branch-C")))
	refs3 := []group.CommitRef{commitRef1, commitRef2, commitRef3}
	canon3a := sequencer.CanonicalCommit(suite, refs3)
	canon3b := sequencer.CanonicalCommit(suite, []group.CommitRef{commitRef3, commitRef1, commitRef2})
	if string(canon3a) != string(canon3b) {
		t.Fatal("CanonicalCommit not order-independent for 3 candidates")
	}
}

// TestForkDetectedRegistry: the shared EpochAuthenticatorRegistry flags a fork
// when two distinct authenticators are reported for the same (vni, epoch).
func TestForkDetectedRegistry(t *testing.T) {
	checker := newInvariantChecker()

	ea1 := []byte("authenticator-branch-1")
	ea2 := []byte("authenticator-branch-2")

	checker.reportAuth(100, 3, ea1)
	if checker.far.Divergent(group.GroupID(ironcore.GroupID(100)), 3) {
		t.Fatal("should not be divergent after first report")
	}

	checker.reportAuth(100, 3, ea2)
	if !checker.far.Divergent(group.GroupID(ironcore.GroupID(100)), 3) {
		t.Fatal("should be divergent after two distinct authenticators")
	}

	// Idempotent: same EA again does not change divergent status.
	checker.reportAuth(100, 3, ea1)
	if !checker.far.Divergent(group.GroupID(ironcore.GroupID(100)), 3) {
		t.Fatal("still divergent after duplicate report")
	}

	// Different epoch is independent.
	checker.reportAuth(100, 4, ea1)
	if checker.far.Divergent(group.GroupID(ironcore.GroupID(100)), 4) {
		t.Fatal("epoch 4 should not be divergent with only one authenticator")
	}
}
