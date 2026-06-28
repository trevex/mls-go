package ironcore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/trevex/mls-go/ironcore"
	"github.com/trevex/mls-go/ironcore/sequencer"
	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
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
// The group is at epoch 0 with the founder at leaf 0. An optional privacy argument
// overrides the default HandshakePrivacy (HandshakeEncrypted) in the config.
func founderNode(t *testing.T, suite cipher.Suite, vni uint32, name string, seq group.Ordering, resolve ironcore.KeyPackageResolver, privacy ...ironcore.HandshakePrivacy) *ironcore.Controller {
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
	if len(privacy) > 0 {
		cfg.HandshakePrivacy = privacy[0]
	}
	ctrl, err := ironcore.NewController(cfg, g)
	if err != nil {
		t.Fatalf("founderNode(%s): NewController: %v", name, err)
	}
	return ctrl
}

// mkNode builds a joiner Controller (g=nil) with a fresh KeyPackage ready for
// being Added by the committer. An optional privacy argument overrides the
// default HandshakePrivacy (HandshakeEncrypted) in the config.
func mkNode(t *testing.T, suite cipher.Suite, vni uint32, name string, seq group.Ordering, resolve ironcore.KeyPackageResolver, privacy ...ironcore.HandshakePrivacy) (ctrl *ironcore.Controller, kpMsg, initPriv, leafPriv []byte) {
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
	if len(privacy) > 0 {
		cfg.HandshakePrivacy = privacy[0]
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

// TestControllerNoGroupAccessors verifies the not-yet-joined (g==nil) accessor
// guards: a joiner controller minted by mkNode has no group state yet.
func TestControllerNoGroupAccessors(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctrl, _, _, _ := mkNode(t, suite, testVNI, "joiner", seq, nil)

	if got := ctrl.Epoch(); got != 0 {
		t.Errorf("no-group Epoch() = %d, want 0", got)
	}
	if ctrl.IsCommitter() {
		t.Error("no-group IsCommitter() = true, want false")
	}
	if ctrl.Group() != nil {
		t.Error("no-group Group() != nil")
	}
	if _, err := ctrl.CurrentSA(); !errors.Is(err, ironcore.ErrNoGroup) {
		t.Errorf("no-group CurrentSA() err = %v, want ErrNoGroup", err)
	}
	if _, err := ctrl.PublishGroupInfo(); !errors.Is(err, ironcore.ErrNoGroup) {
		t.Errorf("no-group PublishGroupInfo() err = %v, want ErrNoGroup", err)
	}
	if _, ok := ctrl.PreviousSA(); ok {
		t.Error("no-group PreviousSA() ok = true, want false")
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

// ─── Task 4: Reconcile + GATE 1 (lifecycle convergence) ──────────────────────

// joinerInfo holds the pre-generated material for a prospective joiner node.
type joinerInfo struct {
	name     string
	ctrl     *ironcore.Controller
	kpMsg    []byte
	initPriv []byte
	leafPriv []byte
}

// TestControllerLifecycle is Gate 1: N nodes form a VNI under 0xF001; the
// designated committer Reconciles a series of membership changes (adds then a
// remove); all nodes converge (byte-equal epoch_authenticator + ESP SA Key)
// after each.
func TestControllerLifecycle(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctx := context.Background()

	// Pre-generate KP material for nodes 1, 2, 3 so we can publish them in the
	// resolver before calling Reconcile.
	joiners := make([]joinerInfo, 3)
	kpMsgByName := map[string][]byte{}
	for i := range joiners {
		name := fmt.Sprintf("node-%d", i+1)
		joiners[i].name = name
		ctrl, kpMsg, ip, lp := mkNode(t, suite, testVNI, name, seq, nil)
		joiners[i].ctrl = ctrl
		joiners[i].kpMsg = kpMsg
		joiners[i].initPriv = ip
		joiners[i].leafPriv = lp
		kpMsgByName[name] = kpMsg
	}

	// Resolver maps identity → published KeyPackage.
	resolver := ironcore.KeyPackageResolver(func(identity []byte) ([]byte, bool) {
		kp, ok := kpMsgByName[string(identity)]
		return kp, ok
	})

	// Build founder (node-0) with resolver.
	node0 := founderNode(t, suite, testVNI, "node-0", seq, resolver)

	// Reconcile: desired = [node-0, node-1, node-2, node-3].
	desired := [][]byte{
		[]byte("node-0"), []byte("node-1"), []byte("node-2"), []byte("node-3"),
	}
	result, err := node0.Reconcile(ctx, desired)
	if err != nil {
		t.Fatalf("node-0.Reconcile(add 3): %v", err)
	}
	if !result.Committed {
		t.Fatalf("Reconcile: Committed=false, want true (node-0 is committer)")
	}
	if !result.Won {
		t.Fatalf("Reconcile: Won=false, want true (no competition)")
	}
	if len(result.Added) != 3 {
		t.Fatalf("Reconcile: Added=%v, want 3 identities", result.Added)
	}
	if len(result.WelcomeMsg) == 0 {
		t.Fatal("Reconcile: WelcomeMsg is empty, want a Welcome for added members")
	}
	if len(result.Pending) != 0 {
		t.Fatalf("Reconcile: Pending=%v, want none", result.Pending)
	}

	// Each joiner joins via Welcome.
	for i, jn := range joiners {
		if err := jn.ctrl.JoinViaWelcome(result.WelcomeMsg, jn.kpMsg, jn.initPriv, jn.leafPriv); err != nil {
			t.Fatalf("node-%d.JoinViaWelcome: %v", i+1, err)
		}
	}

	// All 4 nodes converge at epoch 1.
	all4 := []*ironcore.Controller{node0, joiners[0].ctrl, joiners[1].ctrl, joiners[2].ctrl}
	assertControllerConverged(t, "gate1-epoch1", all4...)
	for _, c := range all4 {
		if c.Epoch() != 1 {
			t.Fatalf("expected epoch 1, got %d", c.Epoch())
		}
	}
	t.Logf("Gate1: 4 nodes converged at epoch 1, EA=%x", node0.Group().EpochAuthenticator())

	// Non-committer Reconcile is a no-op (node-1 is not the committer).
	node1 := joiners[0].ctrl
	nopResult, err := node1.Reconcile(ctx, desired)
	if err != nil {
		t.Fatalf("node-1.Reconcile (non-committer): %v", err)
	}
	if nopResult.Committed {
		t.Fatal("non-committer Reconcile: Committed should be false")
	}

	// Reconcile removes node-2: desired = [node-0, node-1, node-3].
	desired2 := [][]byte{[]byte("node-0"), []byte("node-1"), []byte("node-3")}
	result2, err := node0.Reconcile(ctx, desired2)
	if err != nil {
		t.Fatalf("node-0.Reconcile(remove node-2): %v", err)
	}
	if !result2.Committed || !result2.Won {
		t.Fatalf("Reconcile(remove): Committed=%v Won=%v, want both true",
			result2.Committed, result2.Won)
	}
	if len(result2.Removed) != 1 {
		t.Fatalf("Reconcile(remove): Removed=%v, want 1 leaf", result2.Removed)
	}

	// node-2's HandleCommit returns ErrSelfRemoved.
	node2 := joiners[1].ctrl
	if err := node2.HandleCommit(result2.CommitMsg); err != ironcore.ErrSelfRemoved {
		t.Fatalf("node-2.HandleCommit: want ErrSelfRemoved, got %v", err)
	}

	// Survivors process the commit.
	node3 := joiners[2].ctrl
	if err := node1.HandleCommit(result2.CommitMsg); err != nil {
		t.Fatalf("node-1.HandleCommit(remove node-2): %v", err)
	}
	if err := node3.HandleCommit(result2.CommitMsg); err != nil {
		t.Fatalf("node-3.HandleCommit(remove node-2): %v", err)
	}

	// 3 survivors converge at epoch 2.
	survivors := []*ironcore.Controller{node0, node1, node3}
	assertControllerConverged(t, "gate1-epoch2", survivors...)
	for _, c := range survivors {
		if c.Epoch() != 2 {
			t.Fatalf("expected epoch 2, got %d", c.Epoch())
		}
	}
	t.Logf("Gate1: 3 survivors converged at epoch 2, EA=%x", node0.Group().EpochAuthenticator())
}

// ─── Task 5: Rekey + GATE 3 (periodic rekey, PCS, make-before-break) ──────────

// TestControllerRekeyPCS is Gate 3:
//   - committer Rekey() advances epoch, SA.Key rotates, all converge
//   - PreviousSA() exposes the pre-rekey SA (make-before-break, §10.4)
//   - a non-committer Rekey() is a no-op (nil, false, nil)
//   - PCS: removed node-2's stale SA.Key ≠ post-removal SA.Key (forward secrecy)
func TestControllerRekeyPCS(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctx := context.Background()

	// Build a converged 3-member group (node-0 committer, node-1, node-2).
	node1, kpMsg1, initPriv1, leafPriv1 := mkNode(t, suite, testVNI, "node-1", seq, nil)
	node2, kpMsg2, initPriv2, leafPriv2 := mkNode(t, suite, testVNI, "node-2", seq, nil)

	kpResolver := ironcore.KeyPackageResolver(func(identity []byte) ([]byte, bool) {
		switch string(identity) {
		case "node-1":
			return kpMsg1, true
		case "node-2":
			return kpMsg2, true
		}
		return nil, false
	})
	node0 := founderNode(t, suite, testVNI, "node-0", seq, kpResolver)

	result, err := node0.Reconcile(ctx, [][]byte{[]byte("node-0"), []byte("node-1"), []byte("node-2")})
	if err != nil || !result.Committed || !result.Won {
		t.Fatalf("Reconcile add: %+v err=%v", result, err)
	}
	if err := node1.JoinViaWelcome(result.WelcomeMsg, kpMsg1, initPriv1, leafPriv1); err != nil {
		t.Fatalf("node-1.JoinViaWelcome: %v", err)
	}
	if err := node2.JoinViaWelcome(result.WelcomeMsg, kpMsg2, initPriv2, leafPriv2); err != nil {
		t.Fatalf("node-2.JoinViaWelcome: %v", err)
	}
	all3 := []*ironcore.Controller{node0, node1, node2}
	assertControllerConverged(t, "pre-rekey", all3...)

	// Non-committer Rekey is a no-op.
	nopMsg, nopWon, nopErr := node1.Rekey(ctx)
	if nopErr != nil || nopWon || len(nopMsg) != 0 {
		t.Fatalf("non-committer Rekey: got commitMsg=%x won=%v err=%v, want (nil,false,nil)",
			nopMsg, nopWon, nopErr)
	}

	// Capture pre-rekey SA.
	preRekeySA, err := node0.CurrentSA()
	if err != nil {
		t.Fatalf("pre-rekey CurrentSA: %v", err)
	}

	// Committer Rekey.
	commitMsg, won, err := node0.Rekey(ctx)
	if err != nil || !won {
		t.Fatalf("node0.Rekey: won=%v err=%v", won, err)
	}
	if len(commitMsg) == 0 {
		t.Fatal("node0.Rekey: empty commitMsg")
	}

	// Broadcast rekey commit to all members.
	if err := node1.HandleCommit(commitMsg); err != nil {
		t.Fatalf("node-1.HandleCommit(rekey): %v", err)
	}
	if err := node2.HandleCommit(commitMsg); err != nil {
		t.Fatalf("node-2.HandleCommit(rekey): %v", err)
	}
	assertControllerConverged(t, "post-rekey", all3...)
	t.Logf("Gate3: 3 nodes converged after Rekey, EA=%x", node0.Group().EpochAuthenticator())

	// SA.Key should have rotated.
	postRekeySA, err := node0.CurrentSA()
	if err != nil {
		t.Fatalf("post-rekey CurrentSA: %v", err)
	}
	if bytes.Equal(preRekeySA.Key, postRekeySA.Key) {
		t.Fatal("SA.Key should differ after Rekey (key rotation)")
	}

	// PreviousSA exposes the pre-rekey SA (make-before-break §10.4).
	prevSA, prevOK := node0.PreviousSA()
	if !prevOK {
		t.Fatal("PreviousSA() ok should be true after Rekey")
	}
	if !bytes.Equal(prevSA.Key, preRekeySA.Key) {
		t.Fatalf("PreviousSA().Key should equal pre-rekey SA.Key\n  got  %x\n  want %x",
			prevSA.Key, preRekeySA.Key)
	}

	// PCS: capture node-2's stale SA, remove it, rekey survivors, assert stale ≠ new.
	staleNode2SA, err := node2.CurrentSA()
	if err != nil {
		t.Fatalf("node-2 stale CurrentSA: %v", err)
	}

	result2, err := node0.Reconcile(ctx, [][]byte{[]byte("node-0"), []byte("node-1")})
	if err != nil || !result2.Committed || !result2.Won {
		t.Fatalf("Reconcile remove node-2: %+v err=%v", result2, err)
	}
	if err := node2.HandleCommit(result2.CommitMsg); err != ironcore.ErrSelfRemoved {
		t.Fatalf("node-2.HandleCommit: want ErrSelfRemoved, got %v", err)
	}
	if err := node1.HandleCommit(result2.CommitMsg); err != nil {
		t.Fatalf("node-1.HandleCommit(remove node-2): %v", err)
	}
	assertControllerConverged(t, "post-remove", node0, node1)

	// Rekey survivors (PCS: forward secret from removed node-2).
	rekeyMsg2, won2, err := node0.Rekey(ctx)
	if err != nil || !won2 {
		t.Fatalf("second Rekey: won=%v err=%v", won2, err)
	}
	if err := node1.HandleCommit(rekeyMsg2); err != nil {
		t.Fatalf("node-1.HandleCommit(second rekey): %v", err)
	}
	assertControllerConverged(t, "gate3-post-second-rekey", node0, node1)

	// Post-rekey SA ≠ stale SA of removed node-2 (PCS property §10.3).
	postRemovalSA, err := node0.CurrentSA()
	if err != nil {
		t.Fatalf("post-removal CurrentSA: %v", err)
	}
	if bytes.Equal(staleNode2SA.Key, postRemovalSA.Key) {
		t.Fatal("PCS: removed node-2 stale SA.Key should differ from post-removal SA.Key")
	}
	t.Logf("Gate3: PCS confirmed — stale %x… ≠ post-removal %x…",
		staleNode2SA.Key[:4], postRemovalSA.Key[:4])
}

// ─── Task 6: GATE 2 (committer handover) ──────────────────────────────────────

// TestControllerHandover is Gate 2:
//   - removing the sitting committer (node-0) → node-0's own Reconcile is a no-op
//   - the lowest surviving leaf (node-1 = committer-elect) commits the removal
//   - node-0 gets ErrSelfRemoved; IsCommitter() flips to node-1
//   - node-1 drives a follow-on Rekey; node-1 + node-2 converge
func TestControllerHandover(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctx := context.Background()

	// node-1 is the committer-elect in the handover.
	node1, kpMsg1, initPriv1, leafPriv1 := mkNode(t, suite, testVNI, "node-1", seq, nil)
	node2, kpMsg2, initPriv2, leafPriv2 := mkNode(t, suite, testVNI, "node-2", seq, nil)

	kpResolver := ironcore.KeyPackageResolver(func(identity []byte) ([]byte, bool) {
		switch string(identity) {
		case "node-1":
			return kpMsg1, true
		case "node-2":
			return kpMsg2, true
		}
		return nil, false
	})
	node0 := founderNode(t, suite, testVNI, "node-0", seq, kpResolver)

	result, err := node0.Reconcile(ctx, [][]byte{[]byte("node-0"), []byte("node-1"), []byte("node-2")})
	if err != nil || !result.Committed || !result.Won {
		t.Fatalf("Reconcile add: %+v err=%v", result, err)
	}
	if err := node1.JoinViaWelcome(result.WelcomeMsg, kpMsg1, initPriv1, leafPriv1); err != nil {
		t.Fatalf("node-1.JoinViaWelcome: %v", err)
	}
	if err := node2.JoinViaWelcome(result.WelcomeMsg, kpMsg2, initPriv2, leafPriv2); err != nil {
		t.Fatalf("node-2.JoinViaWelcome: %v", err)
	}
	assertControllerConverged(t, "pre-handover", node0, node1, node2)

	// Verify initial committer assignment.
	if !node0.IsCommitter() {
		t.Fatal("node-0 should be committer before handover")
	}
	if node1.IsCommitter() || node2.IsCommitter() {
		t.Fatal("node-1/node-2 should not be committer before handover")
	}

	// desired2 removes node-0.
	desired2 := [][]byte{[]byte("node-1"), []byte("node-2")}

	// node-0's own Reconcile: no-op (§12.1.3 — committer in removeSet → handover;
	// node-0 != committer-elect (node-1) → returns Committed=false).
	result0, err := node0.Reconcile(ctx, desired2)
	if err != nil {
		t.Fatalf("node-0.Reconcile(remove self): %v", err)
	}
	if result0.Committed {
		t.Fatal("node-0.Reconcile(remove self): Committed should be false (handover no-op)")
	}

	// node-1 is the committer-elect; it commits Remove(node-0).
	result1, err := node1.Reconcile(ctx, desired2)
	if err != nil {
		t.Fatalf("node-1.Reconcile(handover commit): %v", err)
	}
	if !result1.Committed {
		t.Fatal("node-1.Reconcile: Committed should be true (node-1 is committer-elect)")
	}
	if !result1.Won {
		t.Fatalf("node-1.Reconcile: Won should be true, got false")
	}
	if len(result1.Removed) != 1 {
		t.Fatalf("node-1.Reconcile: Removed=%v, want 1 leaf (node-0)", result1.Removed)
	}

	// node-0's HandleCommit → ErrSelfRemoved.
	if err := node0.HandleCommit(result1.CommitMsg); err != ironcore.ErrSelfRemoved {
		t.Fatalf("node-0.HandleCommit: want ErrSelfRemoved, got %v", err)
	}

	// node-2 processes the commit.
	if err := node2.HandleCommit(result1.CommitMsg); err != nil {
		t.Fatalf("node-2.HandleCommit(handover): %v", err)
	}
	// Intermediate convergence: survivors agree at the post-removal epoch.
	assertControllerConverged(t, "gate2-post-removal", node1, node2)

	// IsCommitter() flips to node-1 (lowest active leaf is now 1).
	if !node1.IsCommitter() {
		t.Fatal("node-1 should be committer after handover")
	}
	if node2.IsCommitter() {
		t.Fatal("node-2 should not be committer after handover")
	}
	t.Logf("Gate2: handover confirmed — node-1 is committer at epoch %d", node1.Epoch())

	// node-1 (new committer) drives a follow-on Rekey; both converge.
	rekeyMsg, won, err := node1.Rekey(ctx)
	if err != nil || !won {
		t.Fatalf("node-1.Rekey: won=%v err=%v", won, err)
	}
	if err := node2.HandleCommit(rekeyMsg); err != nil {
		t.Fatalf("node-2.HandleCommit(post-handover rekey): %v", err)
	}
	assertControllerConverged(t, "gate2-converged", node1, node2)
	t.Logf("Gate2: node-1 and node-2 converged at epoch %d, EA=%x",
		node1.Epoch(), node1.Group().EpochAuthenticator())
}

// ─── Task 7: Join paths (JoinViaExternalCommit + PublishGroupInfo) ─────────────

// TestControllerJoinViaExternalCommit verifies:
//   - a new node joins an existing converged group via external commit
//   - existing members HandleCommit the external commit; all converge
//   - a superseded external join (stale GroupInfo) returns ErrJoinSuperseded
func TestControllerJoinViaExternalCommit(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctx := context.Background()

	// Build a converged 2-member group (node-0 + node-1 via Welcome).
	node1, kpMsg1, initPriv1, leafPriv1 := mkNode(t, suite, testVNI, "node-1", seq, nil)
	kpResolver := ironcore.KeyPackageResolver(func(identity []byte) ([]byte, bool) {
		if string(identity) == "node-1" {
			return kpMsg1, true
		}
		return nil, false
	})
	node0 := founderNode(t, suite, testVNI, "node-0", seq, kpResolver)

	result, err := node0.Reconcile(ctx, [][]byte{[]byte("node-0"), []byte("node-1")})
	if err != nil || !result.Committed || !result.Won {
		t.Fatalf("Reconcile add node-1: %+v err=%v", result, err)
	}
	if err := node1.JoinViaWelcome(result.WelcomeMsg, kpMsg1, initPriv1, leafPriv1); err != nil {
		t.Fatalf("node-1.JoinViaWelcome: %v", err)
	}
	assertControllerConverged(t, "pre-external-join", node0, node1)

	// Publish GroupInfo at current epoch for external join.
	gi, err := node0.PublishGroupInfo()
	if err != nil {
		t.Fatalf("node0.PublishGroupInfo: %v", err)
	}

	// node-2 joins via external commit against the current GroupInfo.
	node2, _, _, _ := mkNode(t, suite, testVNI, "node-2", seq, nil)
	extCommitMsg, err := node2.JoinViaExternalCommit(ctx, gi)
	if err != nil {
		t.Fatalf("node-2.JoinViaExternalCommit: %v", err)
	}

	// Existing members process the external commit.
	if err := node0.HandleCommit(extCommitMsg); err != nil {
		t.Fatalf("node-0.HandleCommit(ext-join): %v", err)
	}
	if err := node1.HandleCommit(extCommitMsg); err != nil {
		t.Fatalf("node-1.HandleCommit(ext-join): %v", err)
	}

	// All 3 nodes converge.
	assertControllerConverged(t, "post-external-join", node0, node1, node2)
	t.Logf("Task7: 3 nodes converged after external-commit join, EA=%x",
		node0.Group().EpochAuthenticator())

	// ErrJoinSuperseded: a competing external join at the now-decided epoch.
	// node-3 uses the same stale GroupInfo (epoch already decided by node-2's join).
	node3, _, _, _ := mkNode(t, suite, testVNI, "node-3", seq, nil)
	_, err = node3.JoinViaExternalCommit(ctx, gi)
	if err != ironcore.ErrJoinSuperseded {
		t.Fatalf("stale external join: want ErrJoinSuperseded, got %v", err)
	}
}

// ─── Task 8: AutoRecover + GATE 4 (fork → auto-recovery) ─────────────────────

// TestControllerAutoRecovery is Gate 4:
//   - 2-member group; committer Rekey wins the linearization slot
//   - a concurrent competing commit at the same epoch gets ok=false (fork)
//   - the losing controller AutoRecovers via external commit onto the canonical branch
//   - both converge (byte-equal EA + SA.Key) at the recovered epoch
func TestControllerAutoRecovery(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctx := context.Background()

	// Build a 2-member group: node-0 (committer, leaf 0), node-1 (leaf 1).
	node1, kpMsg1, initPriv1, leafPriv1 := mkNode(t, suite, testVNI, "node-1", seq, nil)
	kpResolver := ironcore.KeyPackageResolver(func(identity []byte) ([]byte, bool) {
		if string(identity) == "node-1" {
			return kpMsg1, true
		}
		return nil, false
	})
	node0 := founderNode(t, suite, testVNI, "node-0", seq, kpResolver)

	result, err := node0.Reconcile(ctx, [][]byte{[]byte("node-0"), []byte("node-1")})
	if err != nil || !result.Committed || !result.Won {
		t.Fatalf("Reconcile add node-1: %+v err=%v", result, err)
	}
	if err := node1.JoinViaWelcome(result.WelcomeMsg, kpMsg1, initPriv1, leafPriv1); err != nil {
		t.Fatalf("node-1.JoinViaWelcome: %v", err)
	}
	assertControllerConverged(t, "pre-fork", node0, node1)

	// Capture base epoch before the fork.
	baseEpoch := node1.Epoch() // == node0.Epoch() (both at the same epoch after join)

	// node-0 (committer) Rekeys — wins the linearization slot at baseEpoch.
	rekeyMsg, won, err := node0.Rekey(ctx)
	if err != nil || !won {
		t.Fatalf("node0.Rekey: won=%v err=%v", won, err)
	}
	_ = rekeyMsg // node-1 has NOT processed it (simulating concurrent competing commit)

	// node-1 makes a competing commit at baseEpoch (still at baseEpoch since it
	// hasn't seen node-0's Rekey commit). This simulates the §5.3 fork scenario.
	forkCommit, _, forkErr := node1.Group().Commit(group.CommitOptions{})
	if forkErr != nil {
		t.Fatalf("node-1 fork commit: %v", forkErr)
	}
	forkRef := group.CommitRef(suite.Hash(forkCommit))

	// Register the fork commit with the shared sequencer → must be rejected (ok=false)
	// because node-0's Rekey already won the (gid, baseEpoch) slot.
	gid := group.GroupID(ironcore.GroupID(testVNI))
	okFork, err := seq.AcceptCommit(ctx, gid, baseEpoch, forkRef)
	if err != nil {
		t.Fatalf("AcceptCommit(fork): %v", err)
	}
	if okFork {
		t.Fatal("fork commit should be rejected (ok=false); node-0's Rekey already won the slot")
	}
	// node-1 is now on the dead fork branch (baseEpoch+1, diverged from canonical).

	// Retrieve the canonical ref (the commit that won the baseEpoch slot).
	canonRef, found := seq.Decided(gid, baseEpoch)
	if !found {
		t.Fatal("sequencer has no decided commit for baseEpoch")
	}

	// node-0 publishes GroupInfo at the canonical epoch (baseEpoch+1).
	gi, err := node0.PublishGroupInfo()
	if err != nil {
		t.Fatalf("node0.PublishGroupInfo: %v", err)
	}

	// node-1 auto-recovers onto the canonical branch.
	// candidates = [canonRef] (the decided winner); fetchGI returns node-0's GroupInfo.
	recoveryMsg, err := node1.AutoRecover(ctx,
		[]group.CommitRef{canonRef},
		func(_ group.CommitRef) (*group.GroupInfo, error) {
			return gi, nil
		},
	)
	if err != nil {
		t.Fatalf("node1.AutoRecover: %v", err)
	}

	// node-0 processes the recovery external commit (advances to recovered epoch).
	if err := node0.HandleCommit(recoveryMsg); err != nil {
		t.Fatalf("node0.HandleCommit(recovery): %v", err)
	}

	// Both converge at the recovered epoch.
	assertControllerConverged(t, "gate4-recovered", node0, node1)
	t.Logf("Gate4: fork recovered — node-0 and node-1 converged at epoch %d, EA=%x",
		node0.Epoch(), node0.Group().EpochAuthenticator())
}

// ─── Gate 4 extended: ErrLostRace→AutoRecover through the Controller API ──────

// TestControllerLostRaceAutoRecover proves the DoD Gate-4 claim
// ("the losing committer detects ErrLostRace and AutoRecovers") through the
// public Controller API surface.
//
// Construction: two 1-member founder controllers share the SAME VNI (GroupID)
// and the SAME sequencer — simulating two nodes that raced to commit at epoch 0.
// Both are IsCommitter()==true (each is the sole member of its own founder
// group). The winner calls Rekey() first, claiming the epoch-0 slot. The loser
// then calls Reconcile() which internally invokes commitAndOrder → AcceptCommit
// (gid, 0, …) → ok=false (already decided) and returns ErrLostRace with
// result.Won==false. The loser then AutoRecovers via external commit onto the
// winner's branch; the winner processes the recovery commit; both converge.
func TestControllerLostRaceAutoRecover(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctx := context.Background()

	// Pre-generate a joiner KP so the loser has a concrete Add proposal to put
	// through commitAndOrder. The joiner is never actually added (the loser loses
	// the race), but its KP drives the real commitAndOrder code path.
	_, joinerKPMsg, _, _ := mkNode(t, suite, testVNI, "joiner", seq, nil)
	joinerResolver := ironcore.KeyPackageResolver(func(identity []byte) ([]byte, bool) {
		if string(identity) == "joiner" {
			return joinerKPMsg, true
		}
		return nil, false
	})

	// Both winner and loser are 1-member founders at epoch 0 with the SAME groupID.
	// Both are IsCommitter()==true; only one can win the epoch-0 slot.
	winner := founderNode(t, suite, testVNI, "winner", seq, nil)
	loser := founderNode(t, suite, testVNI, "loser", seq, joinerResolver)

	// Step 1 — winner claims epoch 0 via Rekey.
	winnerCommit, won, err := winner.Rekey(ctx)
	if err != nil || !won {
		t.Fatalf("winner.Rekey: won=%v err=%v", won, err)
	}
	_ = winnerCommit // winner is now at epoch 1; commit not yet broadcast

	// Step 2 — loser tries Reconcile(add "joiner") at the same epoch 0.
	// Its commitAndOrder calls AcceptCommit(gid, 0, …) → ok=false (already
	// decided by winner).  Reconcile must return ErrLostRace with Won==false.
	// This is the production commitAndOrder path — NOT a direct sequencer call.
	lostResult, lostErr := loser.Reconcile(ctx, [][]byte{[]byte("loser"), []byte("joiner")})
	if !errors.Is(lostErr, ironcore.ErrLostRace) {
		t.Fatalf("loser.Reconcile: want errors.Is(ErrLostRace), got %v", lostErr)
	}
	if lostResult.Won {
		t.Fatalf("loser.Reconcile: result.Won want false, got true")
	}
	t.Logf("ErrLostRace confirmed through Reconcile→commitAndOrder (not via direct sequencer call)")

	// Step 3 — retrieve the canonical branch information for recovery.
	gid := group.GroupID(ironcore.GroupID(testVNI))
	canonRef, found := seq.Decided(gid, 0)
	if !found {
		t.Fatal("sequencer: no decided ref for epoch 0")
	}
	gi, err := winner.PublishGroupInfo()
	if err != nil {
		t.Fatalf("winner.PublishGroupInfo: %v", err)
	}

	// Step 4 — loser AutoRecovers onto the canonical branch.
	// AutoRecover calls RecoverViaExternalCommit which issues an external commit
	// against the winner's GroupInfo and routes it through the ordering register.
	recoveryMsg, err := loser.AutoRecover(ctx,
		[]group.CommitRef{canonRef},
		func(_ group.CommitRef) (*group.GroupInfo, error) { return gi, nil },
	)
	if err != nil {
		t.Fatalf("loser.AutoRecover: %v", err)
	}

	// Step 5 — winner processes the loser's external-commit recovery, advancing
	// to the recovered epoch.
	if err := winner.HandleCommit(recoveryMsg); err != nil {
		t.Fatalf("winner.HandleCommit(recovery): %v", err)
	}

	// Both must converge: byte-equal epoch_authenticator + SA.Key.
	assertControllerConverged(t, "lost-race-recovered", winner, loser)
	t.Logf("Gate4+: ErrLostRace→AutoRecover proven through Controller API; "+
		"both converged at epoch %d, EA=%x",
		winner.Epoch(), winner.Group().EpochAuthenticator())
}
