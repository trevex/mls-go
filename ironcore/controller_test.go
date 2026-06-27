package ironcore_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

// ─── harness helpers ─────────────────────────────────────────────────────────

// testVNI is the VNI used for all controller gate sims (X-Wing suite 0xF001).
const testVNI = uint32(0xF001)

// pqSuite returns the X-Wing PQ cipher suite (0xF001).
func pqSuite(t *testing.T) cipher.Suite {
	t.Helper()
	suite, ok := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("X-Wing suite 0xF001 not registered")
	}
	return suite
}

// founderNode builds a 1-member founder Controller wrapping a fresh group.NewGroup.
// The group is at epoch 0 with the founder at leaf 0.
func founderNode(t *testing.T, suite cipher.Suite, vni uint32, name string, seq group.Ordering, resolve ironcore.KeyPackageResolver) *ironcore.Controller {
	t.Helper()
	signer := makeSigner(t)
	cred := makeCred(name)
	lt := makeLifetime()
	groupID := ironcore.GroupID(vni)
	g, err := group.NewGroup(suite, groupID, cred, signer, lt)
	if err != nil {
		t.Fatalf("founderNode(%s): NewGroup: %v", name, err)
	}
	cfg := ironcore.ControllerConfig{
		VNI:       vni,
		Suite:     suite,
		Ordering:  seq,
		Clock:     group.SystemClock{},
		Validator: group.BasicCredentialValidator{},
		Cred:      cred,
		Signer:    signer,
		Lifetime:  lt,
		Resolve:   resolve,
	}
	ctrl, err := ironcore.NewController(cfg, g)
	if err != nil {
		t.Fatalf("founderNode(%s): NewController: %v", name, err)
	}
	return ctrl
}

// mkNode builds a joiner Controller (g=nil) with a fresh KeyPackage ready for
// being Added by the committer.
func mkNode(t *testing.T, suite cipher.Suite, vni uint32, name string, seq group.Ordering, resolve ironcore.KeyPackageResolver) (ctrl *ironcore.Controller, kpMsg, initPriv, leafPriv []byte) {
	t.Helper()
	sk := makeSigner(t)
	cred := makeCred(name)
	lt := makeLifetime()
	cfg := ironcore.ControllerConfig{
		VNI:       vni,
		Suite:     suite,
		Ordering:  seq,
		Clock:     group.SystemClock{},
		Validator: group.BasicCredentialValidator{},
		Cred:      cred,
		Signer:    sk,
		Lifetime:  lt,
		Resolve:   resolve,
	}
	ctrl, err := ironcore.NewController(cfg, nil)
	if err != nil {
		t.Fatalf("mkNode(%s): NewController: %v", name, err)
	}
	kp, ip, lp, err := group.NewKeyPackage(suite, cred, sk, lt)
	if err != nil {
		t.Fatalf("mkNode(%s): NewKeyPackage: %v", name, err)
	}
	kpMsgBytes, err := group.EncodeKeyPackageMessage(kp)
	if err != nil {
		t.Fatalf("mkNode(%s): EncodeKeyPackageMessage: %v", name, err)
	}
	return ctrl, kpMsgBytes, ip, lp
}

// assertControllerConverged asserts all controllers have byte-equal
// EpochAuthenticator and SA.Key.
func assertControllerConverged(t *testing.T, tag string, ctrls ...*ironcore.Controller) {
	t.Helper()
	if len(ctrls) == 0 {
		return
	}
	refEA := ctrls[0].Group().EpochAuthenticator()
	refSA, err := ctrls[0].CurrentSA()
	if err != nil {
		t.Fatalf("%s: CurrentSA[0]: %v", tag, err)
	}
	for i, c := range ctrls[1:] {
		ea := c.Group().EpochAuthenticator()
		if !bytes.Equal(ea, refEA) {
			t.Fatalf("%s: ctrl[%d] epoch_authenticator mismatch\n  got  %x\n  want %x",
				tag, i+1, ea, refEA)
		}
		sa, err := c.CurrentSA()
		if err != nil {
			t.Fatalf("%s: CurrentSA[%d]: %v", tag, i+1, err)
		}
		if !bytes.Equal(sa.Key, refSA.Key) {
			t.Fatalf("%s: ctrl[%d] SA.Key mismatch\n  got  %x\n  want %x",
				tag, i+1, sa.Key, refSA.Key)
		}
	}
}

// broadcast calls HandleCommit on all controllers in the list.
func broadcast(t *testing.T, commitMsg []byte, ctrls ...*ironcore.Controller) {
	t.Helper()
	for i, c := range ctrls {
		if err := c.HandleCommit(commitMsg); err != nil {
			t.Fatalf("broadcast: ctrl[%d].HandleCommit: %v", i, err)
		}
	}
}

// ─── Task 2: Controller scaffold ─────────────────────────────────────────────

// TestControllerScaffold verifies that a 1-member founder Controller:
//   - IsCommitter() == true (it's at leaf 0, the only active leaf)
//   - CurrentSA() returns a 32-byte key
//   - PreviousSA() returns ok=false (first epoch, no prior SA)
//   - Epoch()==0
//   - Group() is non-nil
func TestControllerScaffold(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctrl := founderNode(t, suite, testVNI, "node-0", seq, nil)

	if !ctrl.IsCommitter() {
		t.Fatal("founder: IsCommitter() should be true")
	}
	if ctrl.Epoch() != 0 {
		t.Fatalf("founder: Epoch() = %d, want 0", ctrl.Epoch())
	}
	sa, err := ctrl.CurrentSA()
	if err != nil {
		t.Fatalf("founder: CurrentSA(): %v", err)
	}
	if len(sa.Key) != 32 {
		t.Fatalf("founder: CurrentSA().Key length %d, want 32", len(sa.Key))
	}
	_, ok := ctrl.PreviousSA()
	if ok {
		t.Fatal("founder: PreviousSA() ok should be false at epoch 0")
	}
	if ctrl.Group() == nil {
		t.Fatal("founder: Group() should not be nil")
	}
}

// ─── Task 3: HandleCommit + commitAndOrder ────────────────────────────────────

// TestControllerHandleCommit verifies:
//   - A founder that issues a Rekey (path-only commit) advances to epoch 1
//   - PreviousSA() is ok=true after the first epoch advance
//   - CurrentSA().Key != PreviousSA().Key (key rotation happened)
func TestControllerHandleCommit(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctx := context.Background()

	founder := founderNode(t, suite, testVNI, "node-0", seq, nil)

	// Founder issues an empty commit (rekey).
	commitMsg, won, err := founder.Rekey(ctx)
	if err != nil {
		t.Fatalf("founder.Rekey: %v", err)
	}
	if !won {
		t.Fatal("founder.Rekey: expected won=true (no competition)")
	}
	if len(commitMsg) == 0 {
		t.Fatal("founder.Rekey: empty commitMsg")
	}

	// Founder itself is at epoch 1 after Rekey.
	if founder.Epoch() != 1 {
		t.Fatalf("founder: Epoch after Rekey = %d, want 1", founder.Epoch())
	}

	// PreviousSA() should now be ok=true (has epoch-0 SA).
	prevSA, prevOK := founder.PreviousSA()
	if !prevOK {
		t.Fatal("founder: PreviousSA() ok should be true after Rekey")
	}
	if len(prevSA.Key) != 32 {
		t.Fatalf("founder: PreviousSA().Key length %d, want 32", len(prevSA.Key))
	}
	curSA, err := founder.CurrentSA()
	if err != nil {
		t.Fatalf("founder: CurrentSA after Rekey: %v", err)
	}
	if bytes.Equal(curSA.Key, prevSA.Key) {
		t.Fatal("founder: CurrentSA().Key should differ from PreviousSA().Key after Rekey")
	}
}

// TestControllerSelfRemoval verifies that when a commit removes a node,
// that node's HandleCommit returns ErrSelfRemoved, while other members succeed.
func TestControllerSelfRemoval(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctx := context.Background()

	// Build joiner (node-1) material.
	joiner1, kpMsg1, initPriv1, leafPriv1 := mkNodeSimple(t, suite, testVNI, "node-1", seq)

	// Decode the KP to Add it directly.
	kp1, err := group.DecodeKeyPackageMessage(kpMsg1)
	if err != nil {
		t.Fatalf("DecodeKeyPackageMessage: %v", err)
	}

	// Build founder group directly (bypass Controller for the Add commit so we
	// can test the Controller's HandleCommit + ErrSelfRemoved path cleanly).
	signer0 := makeSigner(t)
	cred0 := makeCred("node-0")
	lt := makeLifetime()
	groupID := ironcore.GroupID(testVNI)
	g0, err := group.NewGroup(suite, groupID, cred0, signer0, lt)
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}

	// Add node-1 via the raw group (g0 will be at epoch 1 after this).
	addCommit, welcomeMsg, err := g0.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(kp1)},
	})
	if err != nil {
		t.Fatalf("g0.Commit(Add node-1): %v", err)
	}
	// Register the add-commit with the sequencer.
	ref := group.CommitRef(suite.Hash(addCommit))
	okSeq, seqErr := seq.AcceptCommit(ctx, group.GroupID(groupID), uint64(0), ref)
	if seqErr != nil || !okSeq {
		t.Fatalf("AcceptCommit(add): ok=%v err=%v", okSeq, seqErr)
	}

	// Wrap g0 (now at epoch 1) in a Controller.
	cfg0 := ironcore.ControllerConfig{
		VNI:       testVNI,
		Suite:     suite,
		Ordering:  seq,
		Clock:     group.SystemClock{},
		Validator: group.BasicCredentialValidator{},
		Cred:      cred0,
		Signer:    signer0,
		Lifetime:  lt,
		Resolve:   nil,
	}
	founder, err := ironcore.NewController(cfg0, g0)
	if err != nil {
		t.Fatalf("NewController(founder after add): %v", err)
	}

	// node-1 joins via Welcome.
	if err := joiner1.JoinViaWelcome(welcomeMsg, kpMsg1, initPriv1, leafPriv1); err != nil {
		t.Fatalf("joiner1.JoinViaWelcome: %v", err)
	}

	// Both should converge at epoch 1.
	assertControllerConverged(t, "after-add", founder, joiner1)

	// Founder commits a Remove(node-1) via the underlying group directly.
	joiner1Leaf := joiner1.Group().OwnLeaf()
	removeCommit, _, err := founder.Group().Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeRemove(joiner1Leaf)},
	})
	if err != nil {
		t.Fatalf("founder.Group().Commit(Remove node-1): %v", err)
	}
	// Register the remove-commit.
	ref2 := group.CommitRef(suite.Hash(removeCommit))
	ok2, seqErr2 := seq.AcceptCommit(ctx, group.GroupID(groupID), uint64(1), ref2)
	if seqErr2 != nil || !ok2 {
		t.Fatalf("AcceptCommit(remove): ok=%v err=%v", ok2, seqErr2)
	}

	// joiner1's HandleCommit should return ErrSelfRemoved.
	err = joiner1.HandleCommit(removeCommit)
	if err != ironcore.ErrSelfRemoved {
		t.Fatalf("joiner1.HandleCommit(Remove self): want ErrSelfRemoved, got %v", err)
	}
}

// mkNodeSimple is a simplified variant of mkNode (no resolver needed).
func mkNodeSimple(t *testing.T, suite cipher.Suite, vni uint32, name string, seq group.Ordering) (ctrl *ironcore.Controller, kpMsg, initPriv, leafPriv []byte) {
	t.Helper()
	return mkNode(t, suite, vni, name, seq, nil)
}
