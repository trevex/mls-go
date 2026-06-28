package sim

import (
	"math/rand"
	"testing"
)

// TestDropDeterministic verifies same seed ⇒ same drop coin sequence; dropProb=0
// never drops; dropProb=1 always drops.
func TestDropDeterministic(t *testing.T) {
	rng1 := rand.New(rand.NewSource(42))
	rng2 := rand.New(rand.NewSource(42))

	f := newFaultState(FaultConfig{DropProb: 0.5})

	// same seed ⇒ same results
	for i := 0; i < 100; i++ {
		d1 := f.drop(rng1)
		d2 := f.drop(rng2)
		if d1 != d2 {
			t.Fatalf("iteration %d: drop not deterministic: %v vs %v", i, d1, d2)
		}
	}

	// dropProb=0 ⇒ never drop
	fNone := newFaultState(FaultConfig{DropProb: 0})
	rng3 := rand.New(rand.NewSource(1))
	for i := 0; i < 1000; i++ {
		if fNone.drop(rng3) {
			t.Fatal("dropProb=0 should never drop")
		}
	}

	// dropProb=1 ⇒ always drop
	fAll := newFaultState(FaultConfig{DropProb: 1})
	rng4 := rand.New(rand.NewSource(1))
	for i := 0; i < 1000; i++ {
		if !fAll.drop(rng4) {
			t.Fatal("dropProb=1 should always drop")
		}
	}
}

// TestPartitionBlocks verifies src→dst is blocked iff they are on opposite sides;
// symmetric.
func TestPartitionBlocks(t *testing.T) {
	f := newFaultState(FaultConfig{})
	f.applyFault(FaultOp{
		Kind:  faultPartition,
		On:    true,
		SideA: []ActorID{0, 1},
		SideB: []ActorID{2, 3},
	})

	// opposite sides are blocked
	if !f.blocked(0, 2) {
		t.Error("0→2 should be blocked")
	}
	if !f.blocked(2, 0) {
		t.Error("2→0 should be blocked (symmetric)")
	}
	if !f.blocked(1, 3) {
		t.Error("1→3 should be blocked")
	}

	// same side is not blocked
	if f.blocked(0, 1) {
		t.Error("0→1 (same side) should not be blocked")
	}
	if f.blocked(2, 3) {
		t.Error("2→3 (same side) should not be blocked")
	}

	// actor not in partition is not blocked
	if f.blocked(0, 4) {
		t.Error("0→4 (unpartitioned) should not be blocked")
	}

	// lift partition
	f.applyFault(FaultOp{Kind: faultPartition, On: false})
	if f.blocked(0, 2) {
		t.Error("0→2 should not be blocked after lift")
	}
}

// TestLatencyJitterBounded verifies latency(rng) ∈ [base, base+jitter] and is
// at least 1 (minimum causality tick).
func TestLatencyJitterBounded(t *testing.T) {
	f := newFaultState(FaultConfig{Latency: 5, Jitter: 10})
	rng := rand.New(rand.NewSource(7))

	for i := 0; i < 1000; i++ {
		d := f.latency(rng)
		if d < 5 {
			t.Fatalf("latency %d < base 5", d)
		}
		if d > 15 {
			t.Fatalf("latency %d > base+jitter 15", d)
		}
	}

	// zero latency + zero jitter ⇒ still at least 1 tick
	fZero := newFaultState(FaultConfig{Latency: 0, Jitter: 0})
	rng2 := rand.New(rand.NewSource(1))
	for i := 0; i < 100; i++ {
		if d := fZero.latency(rng2); d < 1 {
			t.Fatalf("latency must be ≥ 1, got %d", d)
		}
	}
}
