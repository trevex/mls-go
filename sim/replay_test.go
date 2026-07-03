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

// Negative control: force all senders onto the single group SPI (one shared
// window). Concurrent senders then collide on sequence numbers, so the receiver
// MUST drop some legitimate packets as replays — proving the anti-replay checker
// has teeth. This is an EXPECTED failure mode, so InvariantsHeld may be false;
// we assert the drops occurred.
func TestSharedSPIProducesReplayDrops(t *testing.T) {
	r := Run(SharedSPIReplayControl(), 1)
	if r.Metrics.ReplayDrops == 0 {
		t.Fatal("shared-SPI control produced 0 replay drops — checker has no teeth")
	}
}
