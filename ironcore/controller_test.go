package ironcore_test

import (
	"bytes"
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
