package sim

import "testing"

func TestMigrationChurnConverges(t *testing.T) {
	r := Run(MigrationChurn(), 1)
	if !r.InvariantsHeld {
		t.Fatalf("migration_churn invariants failed: %s", failureSummary(r))
	}
	// A migration issues Remove commits; assert some leaves actually happened by
	// checking commits were produced (removes + adds both commit).
	if r.Metrics.CommitMsgs == 0 {
		t.Fatal("migration scenario produced no commits")
	}
}

func TestMigrationChurnDeterministic(t *testing.T) {
	a := Run(MigrationChurn(), 5)
	b := Run(MigrationChurn(), 5)
	if len(a.Trace) != len(b.Trace) {
		t.Fatalf("trace length mismatch: %d vs %d", len(a.Trace), len(b.Trace))
	}
	for i := range a.Trace {
		if a.Trace[i] != b.Trace[i] {
			t.Fatalf("trace diverged at %d", i)
		}
	}
}
