package group_test

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// TestPublishGroupInfo verifies that a group member at epoch >= 1 can produce a
// signed, well-formed GroupInfo (Task 1 gate). It checks:
//   - PublishGroupInfo() succeeds and signature verifies.
//   - ratchet_tree extension (0x0002) is present.
//   - external_pub extension (0x0004) is present with the right size.
//   - GroupContext.TreeHash in the GroupInfo matches the actual tree hash.
func TestPublishGroupInfo(t *testing.T) {
	suites := []cipher.CipherSuite{
		cipher.XWING_AES256GCM_SHA256_Ed25519, // PQ primary
		cipher.X25519_AES128GCM_SHA256_Ed25519,
	}
	executed := 0
	for _, csID := range suites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			// Build a 2-member group {alice, bob} at epoch 1.
			aliceSigner := makeSigner(t)
			alice, err := group.NewGroup(suite, []byte("grp-pubgi"), makeCred("alice"), aliceSigner, makeLifetime())
			if err != nil {
				t.Fatalf("NewGroup(alice): %v", err)
			}
			bobSigner := makeSigner(t)
			bobKP, bobInitPriv, bobLeafPriv, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
			if err != nil {
				t.Fatalf("NewKeyPackage(bob): %v", err)
			}
			bobKPMsg, err := group.EncodeKeyPackageMessage(bobKP)
			if err != nil {
				t.Fatalf("EncodeKeyPackageMessage(bob): %v", err)
			}
			commitMsg, welcomeMsg, err := alice.Commit(group.CommitOptions{
				ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
			})
			if err != nil {
				t.Fatalf("alice.Commit(Add bob): %v", err)
			}
			_ = commitMsg
			bob, err := group.JoinFromWelcome(suite, welcomeMsg, group.JoinOptions{
				KeyPackage:     bobKPMsg,
				InitPriv:       bobInitPriv,
				EncryptionPriv: bobLeafPriv,
				Signer:         bobSigner,
				ExternalPSKs:   map[string][]byte{},
			})
			if err != nil {
				t.Fatalf("JoinFromWelcome(bob): %v", err)
			}
			_ = bob

			// alice.PublishGroupInfo() — the primary focus of Task 1.
			gi, err := alice.PublishGroupInfo()
			if err != nil {
				t.Fatalf("alice.PublishGroupInfo(): %v", err)
			}

			// Signature verification: the signer is alice (ownLeaf = 0).
			// Parse the ratchet tree to get alice's SignatureKey.
			rtData := gi.RatchetTreeExtension()
			if rtData == nil {
				t.Fatal("RatchetTreeExtension() is nil")
			}
			rt, err := tree.ParseRatchetTree(suite, rtData)
			if err != nil {
				t.Fatalf("ParseRatchetTree: %v", err)
			}
			signerLeaf := gi.Signer // == alice.OwnLeaf() == 0
			ln, err := rt.LeafNodeAt(signerLeaf)
			if err != nil {
				t.Fatalf("LeafNodeAt(%d): %v", signerLeaf, err)
			}
			ok2, err := gi.VerifySignature(suite, ln.SignatureKey)
			if err != nil {
				t.Fatalf("VerifySignature: %v", err)
			}
			if !ok2 {
				t.Fatal("GroupInfo signature verification failed")
			}

			// external_pub extension must be present.
			extPub := gi.ExternalPubExtension()
			if extPub == nil {
				t.Fatal("ExternalPubExtension() is nil")
			}

			// ExternalInitEncap must accept it as a valid public key.
			kemOut, ssEnc, err := suite.ExternalInitEncap(extPub)
			if err != nil {
				t.Fatalf("ExternalInitEncap(extPub): %v", err)
			}
			if len(kemOut) == 0 || len(ssEnc) == 0 {
				t.Fatal("ExternalInitEncap returned empty output")
			}
			if len(ssEnc) != suite.HashLen() {
				t.Fatalf("init_secret len %d, want %d (HashLen)", len(ssEnc), suite.HashLen())
			}

			// GroupContext.TreeHash must match the actual tree root hash.
			rootHash, err := rt.RootTreeHash()
			if err != nil {
				t.Fatalf("RootTreeHash: %v", err)
			}
			if !bytes.Equal(rootHash, gi.GroupContext.TreeHash) {
				t.Fatalf("tree hash mismatch:\n gi  %x\n tree %x", gi.GroupContext.TreeHash, rootHash)
			}

			// Epoch must match alice's current epoch (1).
			if gi.GroupContext.Epoch != 1 {
				t.Fatalf("GroupInfo epoch %d, want 1", gi.GroupContext.Epoch)
			}
		})
	}
	if executed == 0 {
		t.Fatal("no registered suites executed")
	}
}
