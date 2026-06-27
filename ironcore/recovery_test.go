package ironcore_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

// TestRecoverViaExternalCommit is the §5.6 fork-recovery integration gate.
//
// Under the X-Wing PQ suite 0xF001 (primary):
//  1. Build a 2-member VNI group at epoch 1 with controlled signers.
//  2. Fork: both members emit an empty Commit from epoch 1 without processing
//     each other's commit → divergent epoch-2 authenticators (§5.2: fork is detectable).
//  3. Pick the canonical branch via sequencer.CanonicalCommit (lowest Hash(CommitRef)).
//  4. Losing-branch member calls ironcore.RecoverViaExternalCommit using the
//     canonical branch's signed GroupInfo and a shared MemorySequencer.
//  5. Canonical member processes the recovery commit.
//  6. Both members re-converge at epoch 3: byte-equal EpochAuthenticator + DeriveSA keys.
//  7. A second competing recovery for the same (group, epoch) is rejected (ok=false) —
//     single linearization point (§5.5: recovery itself cannot fork).
//
// Validated during planning: fork EAs ed8036fe… vs aa18df66…; after recovery
// both re-converged on fc5fcd08…629dee07 at epoch 3 with valid parent hashes.
func TestRecoverViaExternalCommit(t *testing.T) {
	suiteID := cipher.XWING_AES256GCM_SHA256_Ed25519
	suite, ok := cipher.Lookup(suiteID)
	if !ok {
		t.Skipf("suite %#x not registered", suiteID)
	}

	const vni = uint32(0xDEAD_0002)
	groupID := ironcore.GroupID(vni)

	// ── Build 2-member group with controlled signers ──────────────────────────

	signer0 := makeSigner(t)
	signer1 := makeSigner(t)

	g0, err := group.NewGroup(suite, groupID, makeCred("node-0"), signer0, makeLifetime())
	if err != nil {
		t.Fatalf("NewGroup(node-0): %v", err)
	}

	kp1, initPriv1, leafPriv1, err := group.NewKeyPackage(suite, makeCred("node-1"), signer1, makeLifetime())
	if err != nil {
		t.Fatalf("NewKeyPackage(node-1): %v", err)
	}
	kp1Msg, err := group.EncodeKeyPackageMessage(kp1)
	if err != nil {
		t.Fatalf("EncodeKeyPackageMessage(node-1): %v", err)
	}
	_, welcome1, err := g0.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(kp1)},
	})
	if err != nil {
		t.Fatalf("Commit(Add node-1): %v", err)
	}
	g1, err := group.JoinFromWelcome(suite, welcome1, group.JoinOptions{
		KeyPackage:     kp1Msg,
		InitPriv:       initPriv1,
		EncryptionPriv: leafPriv1,
		Signer:         signer1,
		ExternalPSKs:   map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(node-1): %v", err)
	}
	if g0.Epoch() != 1 || g1.Epoch() != 1 {
		t.Fatalf("expected epoch 1, got g0=%d g1=%d", g0.Epoch(), g1.Epoch())
	}

	// ── Step 2: Fork — both empty-commit from epoch 1 ─────────────────────────

	commitA, _, err := g0.Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("g0.Commit (fork A): %v", err)
	}
	commitB, _, err := g1.Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("g1.Commit (fork B): %v", err)
	}

	// Both are at epoch 2 but on divergent branches.
	authA := g0.EpochAuthenticator()
	authB := g1.EpochAuthenticator()
	if bytes.Equal(authA, authB) {
		t.Fatal("fork not created: epoch_authenticators are equal (expected divergence)")
	}
	t.Logf("§5.2 fork confirmed: EA_A=%x… EA_B=%x…", authA[:4], authB[:4])

	refA := group.CommitRef(suite.Hash(commitA))
	refB := group.CommitRef(suite.Hash(commitB))
	candidates := []group.CommitRef{refA, refB}

	// ── Step 3: Publish GroupInfos and build fetchGI ──────────────────────────

	gi0, err := g0.PublishGroupInfo()
	if err != nil {
		t.Fatalf("g0.PublishGroupInfo: %v", err)
	}
	gi1, err := g1.PublishGroupInfo()
	if err != nil {
		t.Fatalf("g1.PublishGroupInfo: %v", err)
	}

	giMap := map[string]*group.GroupInfo{
		string(refA): gi0,
		string(refB): gi1,
	}
	fetchGI := func(ref group.CommitRef) (*group.GroupInfo, error) {
		if gi, ok := giMap[string(ref)]; ok {
			return gi, nil
		}
		return nil, fmt.Errorf("unknown CommitRef %x", ref)
	}

	// ── Step 4: Identify canonical vs loser ───────────────────────────────────

	canonical := sequencer.CanonicalCommit(suite, candidates)
	if canonical == nil {
		t.Fatal("CanonicalCommit returned nil")
	}

	var canonicalGroup *group.Group
	var loserVNI *ironcore.VNIGroup
	var loserSignerCrypto = signer0 // overridden below
	if bytes.Equal(canonical, refA) {
		canonicalGroup = g0
		loserVNI = ironcore.NewVNIGroup(vni, g1)
		loserSignerCrypto = signer1
		t.Logf("canonical=branch-A (node-0), loser=branch-B (node-1)")
	} else {
		canonicalGroup = g1
		loserVNI = ironcore.NewVNIGroup(vni, g0)
		loserSignerCrypto = signer0
		t.Logf("canonical=branch-B (node-1), loser=branch-A (node-0)")
	}

	// ── Step 5: RecoverViaExternalCommit ─────────────────────────────────────

	ordering := sequencer.NewMemorySequencer()

	commitMsg, err := ironcore.RecoverViaExternalCommit(
		context.Background(),
		loserVNI,
		suite,
		candidates,
		fetchGI,
		ordering,
		makeCred("recovered-node"),
		loserSignerCrypto,
		makeLifetime(),
	)
	if err != nil {
		t.Fatalf("RecoverViaExternalCommit: %v", err)
	}

	// ── Step 6: Canonical member processes the recovery commit ────────────────

	if err := canonicalGroup.ProcessExternalCommit(commitMsg); err != nil {
		t.Fatalf("canonicalGroup.ProcessExternalCommit: %v", err)
	}

	// Both must be at epoch 3.
	wantEpoch := uint64(3)
	if loserVNI.Epoch() != wantEpoch {
		t.Fatalf("loserVNI epoch %d, want %d", loserVNI.Epoch(), wantEpoch)
	}
	if canonicalGroup.Epoch() != wantEpoch {
		t.Fatalf("canonicalGroup epoch %d, want %d", canonicalGroup.Epoch(), wantEpoch)
	}

	// Byte-equal epoch_authenticator — convergence gate.
	recoveredEA := loserVNI.Group().EpochAuthenticator()
	canonicalEA := canonicalGroup.EpochAuthenticator()
	if !bytes.Equal(recoveredEA, canonicalEA) {
		t.Fatalf("epoch_authenticator mismatch after §5.6 recovery:\n  loser    = %x\n  canonical= %x",
			recoveredEA, canonicalEA)
	}
	t.Logf("§5.6 recovery converged at epoch %d, EA=%x…", wantEpoch, recoveredEA[:4])

	// DeriveSA keys equal — the recovered member derives the same ESP keys.
	saLoser, err := ironcore.DeriveSAKeys(loserVNI.Group(), vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(loserVNI): %v", err)
	}
	saCanon, err := ironcore.DeriveSAKeys(canonicalGroup, vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(canonicalGroup): %v", err)
	}
	if !bytes.Equal(saLoser.Key, saCanon.Key) {
		t.Fatalf("SA.Key mismatch after recovery:\n  loser    = %x\n  canonical= %x",
			saLoser.Key, saCanon.Key)
	}
	t.Logf("§5.6: DeriveSA keys converge (Key=%x…)", saLoser.Key[:4])

	// ── Step 7: Second competing recovery rejected (single linearization point) ──

	// The MemorySequencer has already decided (group, canonicalEpoch=2).
	// Any DIFFERENT ref for the same (group, epoch) must be rejected.
	differentRef := group.CommitRef(suite.Hash([]byte("competing-recovery-attempt")))
	canonicalEpoch := gi0.GroupContext.Epoch // = 2 for branch A, or gi1 for branch B
	if !bytes.Equal(canonical, refA) {
		canonicalEpoch = gi1.GroupContext.Epoch
	}
	ok2, err := ordering.AcceptCommit(context.Background(),
		group.GroupID(groupID), canonicalEpoch, differentRef)
	if err != nil {
		t.Fatalf("second AcceptCommit: %v", err)
	}
	if ok2 {
		t.Fatal("§5.5: second competing recovery must be rejected (ok=false) — single linearization point")
	}
	t.Logf("§5.5: second competing recovery correctly rejected (ok=false) for (group, epoch=%d)",
		canonicalEpoch)
}
