package sim

import "testing"

// buildDSHarness creates a minimal harness with two reflectors (R0=replica 0,
// R1=replica 1), each with its own accept-once register.
func buildDSHarness() (s *Scheduler, f *faultState, b *Bus, m *Metrics, ds0, ds1 *DS) {
	s = NewScheduler(1)
	f = newFaultState(FaultConfig{Latency: 1})
	m = newMetrics()
	b = newBus(s, f, m)
	ds0 = newDS(ActorID(10), 0, b, f)
	ds1 = newDS(ActorID(11), 1, b, f)
	return
}

// TestDSSerializeAndFanout: a commit accepted by the register is logged + fanned
// out; a re-submitted identical commit is idempotent (no duplicate log entry).
func TestDSSerializeAndFanout(t *testing.T) {
	_, _, b, m, ds0, _ := buildDSHarness()
	b.Subscribe(42, ActorID(0))
	b.Subscribe(42, ActorID(1))

	commit := []byte("fake-commit-bytes")
	env := Envelope{VNI: 42, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Base: 0, Payload: commit, Hash: contentHash(commit)}
	ds0.handle(env, m)

	if m.Reflected != 1 {
		t.Fatalf("expected 1 reflection, got %d", m.Reflected)
	}
	if len(ds0.logs[42]) != 1 || ds0.logs[42][0].Hash != env.Hash {
		t.Fatalf("log not recorded correctly: %+v", ds0.logs[42])
	}

	// Idempotent resend: same hash → accepted again but log de-duped.
	ds0.handle(env, m)
	if len(ds0.logs[42]) != 1 {
		t.Fatalf("idempotent resend duplicated the log: %d entries", len(ds0.logs[42]))
	}
}

// TestDSRegisterRejectsCompetingCommit: a DIFFERENT commit for an already-decided
// (channel, epoch) is rejected by the local register — the total-order guarantee.
func TestDSRegisterRejectsCompetingCommit(t *testing.T) {
	_, _, b, m, ds0, _ := buildDSHarness()
	b.Subscribe(42, ActorID(0))

	a := []byte("commit-A")
	ds0.handle(Envelope{VNI: 42, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Base: 0, Payload: a, Hash: contentHash(a)}, m)

	bcommit := []byte("commit-B-different")
	rejBefore := m.CommitRejected
	ds0.handle(Envelope{VNI: 42, Type: MsgCommit, Src: ActorID(1), Dst: ActorID(10),
		Base: 0, Payload: bcommit, Hash: contentHash(bcommit)}, m)

	if m.CommitRejected != rejBefore+1 {
		t.Fatalf("competing commit not rejected by register")
	}
	if len(ds0.logs[42]) != 1 {
		t.Fatalf("rejected commit must not be logged: %d entries", len(ds0.logs[42]))
	}
}

// TestDSCatchupServesLog: logRequest{fromEpoch} returns records ≥ fromEpoch.
func TestDSCatchupServesLog(t *testing.T) {
	_, _, b, m, ds0, _ := buildDSHarness()
	b.Subscribe(55, ActorID(0))

	for base := uint64(0); base < 3; base++ {
		payload := []byte{byte(base), 0xAB}
		ds0.handle(Envelope{VNI: 55, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
			Base: base, Payload: payload, Hash: contentHash(payload)}, m)
	}

	before := m.LogRetransmits
	ds0.handle(Envelope{VNI: 55, Type: MsgLogRequest, Src: ActorID(0), Dst: ActorID(10), Base: 1}, m)
	if m.LogRetransmits != before+1 {
		t.Fatalf("LogRetransmits not incremented")
	}
}

// TestDSDownStopsFanout: a downed reflector neither serializes nor fans out; after
// restart it serves again.
func TestDSDownStopsFanout(t *testing.T) {
	_, f, b, m, ds0, _ := buildDSHarness()
	b.Subscribe(77, ActorID(0))

	f.applyFault(FaultOp{Kind: faultDSDown, On: true, DS: ActorID(10)})
	commit := []byte("commit-while-down")
	ds0.handle(Envelope{VNI: 77, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Base: 0, Payload: commit, Hash: contentHash(commit)}, m)
	if m.Reflected != 0 || len(ds0.logs[77]) != 0 {
		t.Fatalf("downed DS reflected/logged: reflected=%d log=%d", m.Reflected, len(ds0.logs[77]))
	}

	f.applyFault(FaultOp{Kind: faultDSDown, On: false, DS: ActorID(10)})
	ds0.handle(Envelope{VNI: 77, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Base: 0, Payload: commit, Hash: contentHash(commit)}, m)
	if m.Reflected != 1 {
		t.Fatalf("restarted DS should reflect, got %d", m.Reflected)
	}
}
