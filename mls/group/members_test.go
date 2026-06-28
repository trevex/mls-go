package group_test

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
	"github.com/trevex/mls-go/mls/tree"
)

// TestActiveLeaves verifies the ActiveLeaves accessor on a small group.
func TestActiveLeaves(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite not registered")
	}

	groupID := []byte("test-active-leaves")

	// Build a 3-member group: alice (leaf 0), bob (leaf 1), carol (leaf 2).
	aliceSigner := makeSigner(t)
	alice, err := group.NewGroup(suite, groupID, makeCred("alice"), aliceSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewGroup(alice): %v", err)
	}

	// Alice alone: ActiveLeaves == [0].
	leaves := alice.ActiveLeaves()
	if len(leaves) != 1 || leaves[0] != 0 {
		t.Fatalf("1-member: want [0], got %v", leaves)
	}

	// Add Bob (leaf 1).
	bobSigner := makeSigner(t)
	bobKP, bobInit, bobLeaf, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewKeyPackage(bob): %v", err)
	}
	bobKPMsg, _ := group.EncodeKeyPackageMessage(bobKP)
	commitMsg, welcomeMsg, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
	})
	if err != nil {
		t.Fatalf("alice.Commit(Add bob): %v", err)
	}
	_ = commitMsg
	bob, err := group.JoinFromWelcome(suite, welcomeMsg, group.JoinOptions{
		KeyPackage: bobKPMsg, InitPriv: bobInit, EncryptionPriv: bobLeaf,
		Signer: bobSigner, ExternalPSKs: map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(bob): %v", err)
	}

	// Add Carol (leaf 2).
	carolSigner := makeSigner(t)
	carolKP, carolInit, carolLeaf, err := group.NewKeyPackage(suite, makeCred("carol"), carolSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewKeyPackage(carol): %v", err)
	}
	carolKPMsg, _ := group.EncodeKeyPackageMessage(carolKP)
	commitMsg2, welcomeMsg2, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(carolKP)},
	})
	if err != nil {
		t.Fatalf("alice.Commit(Add carol): %v", err)
	}
	if err := bob.ProcessCommit(nil, commitMsg2); err != nil {
		t.Fatalf("bob.ProcessCommit(Add carol): %v", err)
	}
	carol, err := group.JoinFromWelcome(suite, welcomeMsg2, group.JoinOptions{
		KeyPackage: carolKPMsg, InitPriv: carolInit, EncryptionPriv: carolLeaf,
		Signer: carolSigner, ExternalPSKs: map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(carol): %v", err)
	}

	// 3-member group: alice/bob/carol see [0,1,2] ascending.
	for _, g := range []*group.Group{alice, bob, carol} {
		got := g.ActiveLeaves()
		if len(got) != 3 {
			t.Fatalf("3-member: want 3 leaves, got %v", got)
		}
		for i, v := range got {
			if uint32(i) != v {
				t.Fatalf("3-member: want ascending [0,1,2], got %v", got)
			}
		}
		// Must be ascending.
		for i := 1; i < len(got); i++ {
			if got[i] <= got[i-1] {
				t.Fatalf("ActiveLeaves not ascending: %v", got)
			}
		}
	}

	// Remove Bob (leaf 1); now leaves should be [0,2].
	bobLeafIdx := bob.OwnLeaf()
	commitMsg3, _, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeRemove(bobLeafIdx)},
	})
	if err != nil {
		t.Fatalf("alice.Commit(Remove bob): %v", err)
	}
	if err := carol.ProcessCommit(nil, commitMsg3); err != nil {
		t.Fatalf("carol.ProcessCommit(Remove bob): %v", err)
	}

	// After Remove(bob): survivors should see [0,2].
	for _, g := range []*group.Group{alice, carol} {
		got := g.ActiveLeaves()
		if len(got) != 2 {
			t.Fatalf("after Remove(bob): want 2 leaves, got %v", got)
		}
		if got[0] != 0 || got[1] != 2 {
			t.Fatalf("after Remove(bob): want [0,2], got %v", got)
		}
		// Still ascending.
		if got[1] <= got[0] {
			t.Fatalf("ActiveLeaves not ascending after remove: %v", got)
		}
	}
}

// TestLeafCredential verifies the LeafCredential accessor.
func TestLeafCredential(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite not registered")
	}

	groupID := []byte("test-leaf-cred")
	aliceSigner := makeSigner(t)
	alice, err := group.NewGroup(suite, groupID, makeCred("alice"), aliceSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewGroup(alice): %v", err)
	}

	// Leaf 0 exists — should return alice's basic-credential identity.
	cred, sigPub, err := alice.LeafCredential(0)
	if err != nil {
		t.Fatalf("LeafCredential(0): %v", err)
	}
	if cred.CredentialType != tree.CredentialTypeBasic {
		t.Fatalf("LeafCredential(0): want Basic, got %v", cred.CredentialType)
	}
	if !bytes.Equal(cred.Identity, []byte("alice")) {
		t.Fatalf("LeafCredential(0): want identity=alice, got %q", cred.Identity)
	}
	if len(sigPub) == 0 {
		t.Fatal("LeafCredential(0): sigPub is empty")
	}

	// Out-of-range leaf must return an error.
	_, _, err = alice.LeafCredential(99)
	if err == nil {
		t.Fatal("LeafCredential(99): want error for out-of-range leaf, got nil")
	}

	// Blank leaf must return an error. Add Bob, remove Bob to blank leaf 1.
	bobSigner := makeSigner(t)
	bobKP, bobInit, bobLeaf, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewKeyPackage(bob): %v", err)
	}
	bobKPMsg, _ := group.EncodeKeyPackageMessage(bobKP)
	_, welcomeMsg, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
	})
	if err != nil {
		t.Fatalf("alice.Commit(Add bob): %v", err)
	}
	bob, err := group.JoinFromWelcome(suite, welcomeMsg, group.JoinOptions{
		KeyPackage: bobKPMsg, InitPriv: bobInit, EncryptionPriv: bobLeaf,
		Signer: bobSigner, ExternalPSKs: map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(bob): %v", err)
	}
	bobLeafIdx := bob.OwnLeaf()
	commitRemove, _, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeRemove(bobLeafIdx)},
	})
	if err != nil {
		t.Fatalf("alice.Commit(Remove bob): %v", err)
	}
	_ = commitRemove

	// Now leaf 1 is blank in alice's tree; LeafCredential(1) must error.
	_, _, err = alice.LeafCredential(1)
	if err == nil {
		t.Fatal("LeafCredential(blank leaf): want error, got nil")
	}
}
