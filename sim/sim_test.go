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

func TestDeterminism(t *testing.T) {
	// Use Nominal (no forks, no CanonicalCommit-dependent branching) so the event
	// structure is determined entirely by the seeded scheduler RNG, not by HPKE
	// randomness in commit bytes. SplitBrain cannot be byte-identical across runs
	// because HPKE-randomised commit hashes affect which CanonicalCommit branch
	// is chosen and therefore how many recovery events fire.
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
		Delivered, Reflected, CtrlDropped, DataDropped, Blocked   int
		CatchupRequests, LogRetransmits, Recoveries, LostRekeys   int
		Forks, DataSent, DataDecryptable, CommitMsgs, CommitBytes int
		MaxOverlap                                                int
		MaxSendLag                                                uint64
	}
	snap := func(m *Metrics) deterministicMetrics {
		return deterministicMetrics{
			m.Delivered, m.Reflected, m.CtrlDropped, m.DataDropped, m.Blocked,
			m.CatchupRequests, m.LogRetransmits, m.Recoveries, m.LostRekeys,
			m.Forks, m.DataSent, m.DataDecryptable, m.CommitMsgs, m.CommitBytes,
			m.MaxOverlap, m.MaxSendLag,
		}
	}
	if snap(m1) != snap(m2) {
		t.Fatalf("deterministic metric counters not identical across same-seed runs:\n  run1: %+v\n  run2: %+v",
			snap(m1), snap(m2))
	}
}
