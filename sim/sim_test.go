package sim

import (
	"testing"
)

func TestRunNominalConverges(t *testing.T) {
	r := Run(Nominal(), 1)
	if !r.InvariantsHeld {
		t.Fatalf("seed 1 nominal: InvariantsHeld=false divergence=%v fork=%v membership=%v packetLoss=%d",
			r.Divergence, r.Fork, r.Membership, len(r.PacketLoss))
	}
}

func TestEncryptedChurnHidesHandshakes(t *testing.T) {
	r := Run(EncryptedChurn(), 1)
	if !r.InvariantsHeld {
		t.Fatalf("encrypted_churn invariants failed: divergence=%v membership=%v packetLoss=%d exposures=%d",
			r.Divergence, r.Membership, len(r.PacketLoss), r.Metrics.PlaintextHandshakeExposures)
	}
	if r.Metrics.PlaintextHandshakeExposures != 0 {
		t.Fatalf("reflector observed %d plaintext member handshakes, want 0", r.Metrics.PlaintextHandshakeExposures)
	}
	if r.Metrics.CommitMsgs == 0 {
		t.Fatal("scenario produced no commits to protect")
	}
}

func TestDeterminism(t *testing.T) {
	// Same seed ⇒ byte-identical run: the event structure is determined entirely
	// by the seeded scheduler RNG. The dual single-sequencer model has no forks and
	// no HPKE-randomness-dependent branching, so every scenario replays identically.
	r1 := Run(Nominal(), 7)
	r2 := Run(Nominal(), 7)
	if len(r1.Trace) != len(r2.Trace) {
		t.Fatalf("trace length mismatch: %d vs %d", len(r1.Trace), len(r2.Trace))
	}
	for i := range r1.Trace {
		if r1.Trace[i] != r2.Trace[i] {
			t.Fatalf("trace diverged at line %d:\n  run1: %s\n  run2: %s", i, r1.Trace[i], r2.Trace[i])
		}
	}
	// Compare only the deterministic integer counters; CPU wall-clock timing
	// (cpuNanos) is measured and intentionally varies across runs.
	m1, m2 := r1.Metrics, r2.Metrics
	type deterministicMetrics struct {
		Delivered, Reflected, CtrlDropped, DataDropped, Blocked int
		CatchupRequests, LogRetransmits                         int
		DataSent, DataDecryptable, ReplayDrops                  int
		CommitMsgs, CommitBytes                                 int
		MaxOverlap                                              int
		MaxSendLag                                              uint64
		PlaintextHandshakeExposures                             int
		CommitsIssued, CommitDeliveries, CommitsApplied         int
		Horizon, MaxConvergeTicks                               uint64
	}
	snap := func(m *Metrics) deterministicMetrics {
		return deterministicMetrics{
			m.Delivered, m.Reflected, m.CtrlDropped, m.DataDropped, m.Blocked,
			m.CatchupRequests, m.LogRetransmits,
			m.DataSent, m.DataDecryptable, m.ReplayDrops, m.CommitMsgs, m.CommitBytes,
			m.MaxOverlap, m.MaxSendLag,
			m.PlaintextHandshakeExposures,
			m.CommitsIssued, m.CommitDeliveries, m.CommitsApplied,
			m.Horizon, m.MaxConvergeTicks,
		}
	}
	if snap(m1) != snap(m2) {
		t.Fatalf("deterministic metric counters not identical across same-seed runs:\n  run1: %+v\n  run2: %+v",
			snap(m1), snap(m2))
	}
}
