package sim

import (
	"testing"
)

// Each property test asserts all dual-redundancy invariants hold across seeds 1..20.

func TestScenarioNominal(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		r := Run(Nominal(), seed)
		if !r.InvariantsHeld {
			t.Fatalf("seed %d: %s", seed, failureSummary(r))
		}
	}
}

func TestScenarioDrops(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		r := Run(Drops(), seed)
		if !r.InvariantsHeld {
			t.Fatalf("seed %d: %s", seed, failureSummary(r))
		}
	}
}

// TestScenarioDSDown: R0 stops mid-run → replica 0 stalls. Assert all invariants
// AND that data still flowed (replica 1 carried it) with ZERO key-loss.
func TestScenarioDSDown(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		r := Run(DSDown(), seed)
		if !r.InvariantsHeld {
			t.Fatalf("seed %d: %s", seed, failureSummary(r))
		}
		if len(r.PacketLoss) != 0 {
			t.Fatalf("seed %d: ds_down had %d key-loss events (redundancy headline broken)", seed, len(r.PacketLoss))
		}
		if r.Metrics.DataDecryptable == 0 {
			t.Fatalf("seed %d: ds_down decrypted zero data packets — traffic did not flow", seed)
		}
	}
}

// TestScenarioPartitionRecover: a client subset is cut from R0 and rides replica 1,
// then catches up replica 0 on heal — with ZERO key-loss throughout.
func TestScenarioPartitionRecover(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		r := Run(PartitionRecover(), seed)
		if !r.InvariantsHeld {
			t.Fatalf("seed %d: %s", seed, failureSummary(r))
		}
		if len(r.PacketLoss) != 0 {
			t.Fatalf("seed %d: partition_recover had %d key-loss events", seed, len(r.PacketLoss))
		}
		if r.Metrics.DataDecryptable == 0 {
			t.Fatalf("seed %d: partition_recover decrypted zero data packets", seed)
		}
	}
}

func TestScenarioBothRekey(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		r := Run(BothRekey(), seed)
		if !r.InvariantsHeld {
			t.Fatalf("seed %d: %s", seed, failureSummary(r))
		}
	}
}

// TestNegativeControl_PacketLoss: ONE replica + W=0 + no sender-lag MUST produce
// undecryptable data packets (inv. 2 fails). Proves the zero-loss checker has teeth.
func TestNegativeControl_PacketLoss(t *testing.T) {
	found := false
	for seed := int64(1); seed <= 20; seed++ {
		r := Run(NegativeControl(), seed)
		if !r.InvariantsHeld && len(r.PacketLoss) > 0 {
			found = true
			t.Logf("seed %d: correctly reported %d PACKET-LOSS events (inv. 2 fires as expected)", seed, len(r.PacketLoss))
			break
		}
	}
	if !found {
		t.Fatalf("negative control never produced a PACKET-LOSS failure across seeds 1..20 — checker is vacuous")
	}
}
