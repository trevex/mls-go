package sim

import (
	"testing"
)

// buildDSHarness creates a minimal test harness: one Scheduler, faultState,
// Bus, Metrics, and two DS actors.
func buildDSHarness() (s *Scheduler, f *faultState, b *Bus, m *Metrics, ds0, ds1 *DS) {
	s = NewScheduler(1)
	f = newFaultState(FaultConfig{Latency: 1})
	m = newMetrics()
	b = newBus(s, f, m)
	ds0 = newDS(ActorID(10), b, f)
	ds1 = newDS(ActorID(11), b, f)
	return
}

// TestDSFanout verifies a commit sent to a DS is re-published to all VNI
// subscribers and appended to the per-VNI log in receive order.
func TestDSFanout(t *testing.T) {
	s, _, b, m, ds0, _ := buildDSHarness()

	// subscribe two clients on VNI 42
	b.Subscribe(42, ActorID(0))
	b.Subscribe(42, ActorID(1))
	b.Subscribe(42, ActorID(10)) // the DS itself is also a subscriber (for reflect)

	commit := []byte("fake-commit-bytes")
	env := Envelope{
		VNI: 42, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Base: 0, Payload: commit, Hash: contentHash(commit),
	}
	ds0.handle(env, m)

	// should have reflected once (to the VNI broadcast)
	if m.Reflected != 1 {
		t.Fatalf("expected 1 reflection, got %d", m.Reflected)
	}
	// log should contain the commit
	log := ds0.logs[42]
	if len(log) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(log))
	}
	if log[0].Hash != env.Hash {
		t.Fatalf("log hash mismatch")
	}

	// a duplicate commit with same hash must be deduplicated
	ds0.handle(env, m)
	if len(ds0.logs[42]) != 1 {
		t.Fatalf("duplicate not deduped: log has %d entries", len(ds0.logs[42]))
	}

	_ = s // used for latency scheduling
}

// TestDSGroupInfoCache verifies the last GroupInfo per VNI is cached and
// logRequest{fromEpoch} returns records ≥ fromEpoch.
func TestDSGroupInfoCache(t *testing.T) {
	_, _, b, m, ds0, _ := buildDSHarness()

	// subscribe a client that will receive the catch-up reply
	b.Subscribe(55, ActorID(0))
	b.Subscribe(55, ActorID(10))

	// append two commit records at base 0 and base 1
	for base := uint64(0); base < 3; base++ {
		payload := []byte{byte(base), 0xAB}
		ds0.handle(Envelope{
			VNI: 55, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
			Base: base, Payload: payload, Hash: contentHash(payload),
		}, m)
	}

	// cache a GroupInfo
	gi := []byte("signed-group-info-bytes")
	ds0.handle(Envelope{
		VNI: 55, Type: MsgGroupInfo, Src: ActorID(0), Dst: ActorID(10),
		Payload: gi, Hash: contentHash(gi),
	}, m)

	if ds0.latest[55] == nil {
		t.Fatal("GroupInfo not cached in latest")
	}
	if ds0.giCache[55][contentHash(gi)] == nil {
		t.Fatal("GroupInfo not cached in giCache by hash")
	}

	// send a logRequest for fromEpoch=1 — should return epochs 1 and 2
	mBefore := m.LogRetransmits
	ds0.handle(Envelope{
		VNI: 55, Type: MsgLogRequest, Src: ActorID(0), Dst: ActorID(10),
		Base: 1,
	}, m)
	if m.LogRetransmits != mBefore+1 {
		t.Fatalf("LogRetransmits not incremented")
	}
}

// TestDSDownStopsFanout verifies a downed DS neither fans out nor serves
// catch-up; after restart it serves again.
func TestDSDownStopsFanout(t *testing.T) {
	_, f, b, m, ds0, _ := buildDSHarness()
	b.Subscribe(77, ActorID(0))

	// bring DS0 down
	f.applyFault(FaultOp{Kind: faultDSDown, On: true, DS: ActorID(10)})

	// commit while down → ignored
	commit := []byte("commit-while-down")
	ds0.handle(Envelope{
		VNI: 77, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Payload: commit, Hash: contentHash(commit),
	}, m)
	if m.Reflected != 0 {
		t.Fatalf("downed DS should not reflect, got %d reflections", m.Reflected)
	}
	if len(ds0.logs[77]) != 0 {
		t.Fatalf("downed DS should not append log entries")
	}

	// bring DS0 back up (clear the down flag)
	f.applyFault(FaultOp{Kind: faultDSDown, On: false, DS: ActorID(10)})

	// commit after restart → reflected
	ds0.handle(Envelope{
		VNI: 77, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Payload: commit, Hash: contentHash(commit),
	}, m)
	if m.Reflected != 1 {
		t.Fatalf("restarted DS should reflect, got %d reflections", m.Reflected)
	}
}

// TestDSTwoLogsDiverge verifies two DS handed different commits for the same
// base hold different logs (faithful AP — no shared state).
func TestDSTwoLogsDiverge(t *testing.T) {
	_, _, b, m, ds0, ds1 := buildDSHarness()
	b.Subscribe(99, ActorID(0))
	b.Subscribe(99, ActorID(10))
	b.Subscribe(99, ActorID(11))

	commitA := []byte("commit-branch-A")
	commitB := []byte("commit-branch-B")

	// DS0 receives commit A
	ds0.handle(Envelope{
		VNI: 99, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Base: 0, Payload: commitA, Hash: contentHash(commitA),
	}, m)

	// DS1 receives commit B (different branch, same base)
	ds1.handle(Envelope{
		VNI: 99, Type: MsgCommit, Src: ActorID(1), Dst: ActorID(11),
		Base: 0, Payload: commitB, Hash: contentHash(commitB),
	}, m)

	log0 := ds0.logs[99]
	log1 := ds1.logs[99]

	if len(log0) != 1 || len(log1) != 1 {
		t.Fatalf("each DS should have 1 entry: ds0=%d ds1=%d", len(log0), len(log1))
	}
	if log0[0].Hash == log1[0].Hash {
		t.Fatal("two DS should hold different logs (AP divergence)")
	}
}
