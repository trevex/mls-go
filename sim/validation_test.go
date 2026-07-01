package sim

import "testing"

// TestFanoutMatchesModelStructure validates the Tier-2 reflector_fwd formula's
// (M-1) fan-out term against the Tier-3 real-stack sim: realized commit
// deliveries per issued commit should track the mean subscriber count, which is
// what scaling.Project multiplies bytes_per_commit by. We assert the measured
// amplification is within the plausible band (1, 3*Clients] — every issued
// commit reaches multiple members, and the loose ceiling accommodates reflector
// re-reflects on resends (it is a sanity bound, not a tight one).
func TestFanoutMatchesModelStructure(t *testing.T) {
	sc := Nominal() // 5 clients, 2 VNIs, dual replica ⇒ small bounded membership
	r := Run(sc, 1)
	amp := r.Metrics.FanoutAmplification()

	if amp <= 1.0 || amp > float64(sc.Clients)*3 {
		t.Fatalf("fanout amplification %v outside (1, %d] — model (M-1) term not matched by real fan-out",
			amp, sc.Clients*3)
	}
}

// TestReflectorForwardsScaleWithMembership sanity-checks that a larger member
// set yields more realized deliveries per commit than a smaller one — the
// monotonicity the reflector_fwd ∝ (M-1) term predicts.
func TestReflectorForwardsScaleWithMembership(t *testing.T) {
	small := Run(withClients(Nominal(), 3), 1)
	large := Run(withClients(Nominal(), 8), 1)
	if large.Metrics.FanoutAmplification() <= small.Metrics.FanoutAmplification() {
		t.Fatalf("expected fan-out to grow with membership: small=%v large=%v",
			small.Metrics.FanoutAmplification(), large.Metrics.FanoutAmplification())
	}
}

func withClients(s Scenario, clients int) Scenario {
	s.Clients = clients
	s.Churn = churnPlan(clients, s.VNIs)
	return s
}
