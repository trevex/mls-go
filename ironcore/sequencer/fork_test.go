package sequencer_test

import (
	"testing"

	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

// TestForkRegistryUnit exercises EpochAuthenticatorRegistry in isolation with
// synthetic authenticators (§5.6 fork detection unit gate).
func TestForkRegistryUnit(t *testing.T) {
	reg := sequencer.NewEpochAuthenticatorRegistry()
	gid := group.GroupID([]byte("fork-group"))
	epoch := uint64(5)

	authA := []byte("authenticator-branch-A")
	authB := []byte("authenticator-branch-B")

	// First report — no fork yet.
	if fork := reg.Report(gid, epoch, authA); fork {
		t.Fatal("first report: expected fork=false")
	}

	// Same authenticator again — idempotent, still no fork.
	if fork := reg.Report(gid, epoch, authA); fork {
		t.Fatal("second report same auth: expected fork=false")
	}

	// Second distinct authenticator — fork detected.
	if fork := reg.Report(gid, epoch, authB); !fork {
		t.Fatal("different auth: expected fork=true")
	}

	// Divergent confirms the fork.
	if !reg.Divergent(gid, epoch) {
		t.Fatal("Divergent: expected true after two distinct authenticators")
	}

	// A different (group, epoch) is fully independent — no fork there.
	epoch2 := uint64(6)
	if fork := reg.Report(gid, epoch2, authA); fork {
		t.Fatal("independent epoch: expected fork=false")
	}
	if reg.Divergent(gid, epoch2) {
		t.Fatal("independent epoch: Divergent expected false")
	}

	// Reporting an already-known auth when fork already set still returns true
	// (the set is already diverged).
	if fork := reg.Report(gid, epoch, authA); !fork {
		t.Fatal("re-report known auth after fork: expected fork=true (already diverged)")
	}
}
