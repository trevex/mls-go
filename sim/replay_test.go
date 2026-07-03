package sim

import "testing"

// Per-sender SPIs ⇒ every sender has its own anti-replay window ⇒ no legitimate
// packet is ever dropped as a replay, even with many concurrent senders.
func TestPerSenderNoReplayDrops(t *testing.T) {
	r := Run(Nominal(), 1)
	if r.Metrics.ReplayDrops != 0 {
		t.Fatalf("per-sender SPI must yield 0 replay drops, got %d", r.Metrics.ReplayDrops)
	}
	if r.Metrics.DataDecryptable == 0 {
		t.Fatal("scenario delivered no decryptable data")
	}
	if !r.InvariantsHeld {
		t.Fatalf("invariants failed: %s", failureSummary(r))
	}
}
