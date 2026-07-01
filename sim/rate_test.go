package sim

import "testing"

func TestRateMetricsPopulated(t *testing.T) {
	r := Run(Nominal(), 1)
	m := r.Metrics
	if m.CommitsIssued == 0 {
		t.Fatal("no commits issued")
	}
	if m.CommitsApplied == 0 {
		t.Fatal("no commits applied")
	}
	if m.CommitDeliveries < m.CommitsApplied {
		t.Fatalf("deliveries (%d) should be >= applied (%d)", m.CommitDeliveries, m.CommitsApplied)
	}
	if m.Horizon == 0 {
		t.Fatal("horizon (max tick) not recorded")
	}
}

func TestFanoutAmplificationExceedsOne(t *testing.T) {
	// Each issued commit is fanned out to multiple subscribers, so realized
	// deliveries per issued commit must exceed 1 in a multi-member scenario.
	r := Run(Nominal(), 1)
	amp := r.Metrics.FanoutAmplification()
	if amp <= 1.0 {
		t.Fatalf("fanout amplification = %v, want > 1", amp)
	}
}

func TestConvergenceTicksRecorded(t *testing.T) {
	r := Run(Nominal(), 1)
	if r.Metrics.MaxConvergeTicks == 0 {
		t.Fatal("expected a positive worst-case commit convergence gap")
	}
}
