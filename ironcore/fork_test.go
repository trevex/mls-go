package ironcore_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/trevex/mls-go/ironcore/sequencer"
	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
)

// TestSplitBrainForkDetected is the §5.2/§5.3/§5.6 integration gate.
//
// It uses the *real* MLS engine (X-Wing 0xF001 suite) to demonstrate that:
//   - Two members committing from the same epoch without processing each other's
//     commit produce epoch n+1 with **distinct** epoch_authenticators (§5.2:
//     incompatible epoch n+1 states ⇒ different authenticators → fork detectable).
//   - Two independent MemorySequencers each accept their own branch's CommitRef
//     (both return ok=true) — this IS the split-brain fork that two registers
//     cannot prevent (§5.3: two registers = two "winners" = a real fork).
//   - The EpochAuthenticatorRegistry flags the fork on the second report (§5.6:
//     active fork detection by out-of-band authenticator comparison).
//
// Lesson: route both branches to ONE MemorySequencer and only the first wins
// (§5.1 single-register safety) — the fork is impossible. Two registers ⇒ fork;
// one register ⇒ safe. The contrast is the proof.
func TestSplitBrainForkDetected(t *testing.T) {
	suiteID := cipher.XWING_AES256GCM_SHA256_Ed25519
	suite, ok := cipher.Lookup(suiteID)
	if !ok {
		t.Skipf("suite %#x not registered", suiteID)
	}

	const vni = uint32(0xDEAD_0001)

	// Step 1: Build a converged 3-member VNI group (epoch 2 after two Add commits).
	nodes := buildVNIGroup(t, suite, vni, 3)
	gid := group.GroupID(nodes[0].GroupID())
	epoch := nodes[0].Epoch() // base epoch (2) — the epoch being committed FROM

	// Step 2: Two competing empty commits from the SAME base epoch.
	// Neither node processes the other's commit → two divergent branches.
	commitA, _, err := nodes[0].Group().Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("node-0 Commit: %v", err)
	}
	commitB, _, err := nodes[1].Group().Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("node-1 Commit: %v", err)
	}

	// Step 3: CommitRefs are distinct (the two commits are cryptographically different).
	refA := group.CommitRef(suite.Hash(commitA))
	refB := group.CommitRef(suite.Hash(commitB))
	if bytes.Equal(refA, refB) {
		t.Fatal("refA == refB: the two empty commits should produce distinct hashes")
	}

	// Step 4: TWO independent MemorySequencers — one per RR branch.
	// Both accept their own branch → ok=true for BOTH. This is the split-brain
	// fork: without a single linearization point, two registers = two winners.
	//
	// If both CommitRefs were routed to ONE MemorySequencer instead, only the
	// first would win (§5.1 single-register safety eliminates the fork).
	regA := sequencer.NewMemorySequencer()
	regB := sequencer.NewMemorySequencer()

	okA, err := regA.AcceptCommit(context.Background(), gid, epoch, refA)
	if err != nil {
		t.Fatalf("regA.AcceptCommit: %v", err)
	}
	if !okA {
		t.Fatal("regA: expected ok=true (first and only entry)")
	}

	okB, err := regB.AcceptCommit(context.Background(), gid, epoch, refB)
	if err != nil {
		t.Fatalf("regB.AcceptCommit: %v", err)
	}
	if !okB {
		t.Fatal("regB: expected ok=true (first and only entry in an independent register)")
	}

	// Two winners for the same (group, epoch) — confirmed fork (§5.3).
	t.Logf("fork confirmed: regA accepted refA=%x… regB accepted refB=%x…",
		refA[:4], refB[:4])

	// Step 5: The two branches are at the same new epoch number but have diverged —
	// their epoch_authenticators must differ (§5.2: different Commits at epoch n
	// yield cryptographically incompatible epoch n+1 states).
	newEpoch := nodes[0].Epoch() // epoch after node-0's commit (= base epoch + 1)
	authA := nodes[0].Group().EpochAuthenticator()
	authB := nodes[1].Group().EpochAuthenticator()
	if bytes.Equal(authA, authB) {
		t.Fatalf("authA == authB: epoch_authenticators should differ for diverged branches\n  authA=%x\n  authB=%x", authA, authB)
	}
	t.Logf("§5.2 confirmed: distinct epoch_authenticators at epoch %d\n  authA=%x…\n  authB=%x…",
		newEpoch, authA[:4], authB[:4])

	// Step 6: EpochAuthenticatorRegistry flags the fork on the second report (§5.6).
	far := sequencer.NewEpochAuthenticatorRegistry()

	// First report — no fork detected yet.
	fork := far.Report(gid, newEpoch, authA)
	if fork {
		t.Fatal("first Report: expected fork=false (only one authenticator seen)")
	}

	// Second report with a different authenticator — fork detected.
	fork = far.Report(gid, newEpoch, authB)
	if !fork {
		t.Fatal("second Report (distinct auth): expected fork=true")
	}

	// Divergent confirms the active detection.
	if !far.Divergent(gid, newEpoch) {
		t.Fatal("Divergent: expected true after two distinct authenticators")
	}

	t.Logf("§5.6 confirmed: EpochAuthenticatorRegistry detected fork at (gid=%x…, epoch=%d)",
		gid[:4], newEpoch)

	// Single-register contrast (§5.1): route BOTH competing CommitRefs to ONE
	// MemorySequencer for the same (gid, epoch). Only the first wins; the second
	// is rejected (ok=false). One register ⇒ one winner ⇒ no fork possible.
	singleReg := sequencer.NewMemorySequencer()

	ok1, err := singleReg.AcceptCommit(context.Background(), gid, epoch, refA)
	if err != nil {
		t.Fatalf("singleReg first AcceptCommit: %v", err)
	}
	if !ok1 {
		t.Fatal("singleReg: expected ok=true for first commit (refA)")
	}

	ok2, err := singleReg.AcceptCommit(context.Background(), gid, epoch, refB)
	if err != nil {
		t.Fatalf("singleReg second AcceptCommit: %v", err)
	}
	if ok2 {
		t.Fatal("singleReg: expected ok=false for competing refB — one register, one winner, no fork")
	}

	t.Logf("§5.1 single-register contrast confirmed: one MemorySequencer for (gid=%x…, epoch=%d) ⇒ refB rejected (ok=false), no fork",
		gid[:4], epoch)
}
