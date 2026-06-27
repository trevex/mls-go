package tree_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

func TestNewRatchetTree(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite not registered")
	}
	_, encPub, err := suite.GenerateHPKEKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	leaf := tree.LeafNode{
		EncryptionKey:  encPub,
		SignatureKey:   []byte("placeholder-sig-key"),
		Credential:     tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte("alice")},
		Capabilities:   tree.Capabilities{Versions: []tree.ProtocolVersion{tree.ProtocolVersionMLS10}},
		LeafNodeSource: tree.LeafNodeSourceKeyPackage,
		Lifetime:       &tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)},
		Signature:      []byte("placeholder"),
	}
	rt := tree.NewRatchetTree(suite, leaf)
	if rt.Width() != 1 {
		t.Fatalf("Width=%d, want 1", rt.Width())
	}
	got, err := rt.LeafNodeAt(0)
	if err != nil {
		t.Fatalf("LeafNodeAt(0): %v", err)
	}
	if string(got.EncryptionKey) != string(encPub) {
		t.Fatalf("EncryptionKey mismatch")
	}
	if _, err := rt.RootTreeHash(); err != nil {
		t.Fatalf("RootTreeHash: %v", err)
	}
}

func TestSignLeafNodeKeyPackage(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite not registered")
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sigKey, err := suite.SignaturePublicKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	_, encPub, err := suite.GenerateHPKEKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ln := tree.LeafNode{
		EncryptionKey:  encPub,
		SignatureKey:   sigKey,
		Credential:     tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte("alice")},
		Capabilities:   tree.Capabilities{Versions: []tree.ProtocolVersion{tree.ProtocolVersionMLS10}},
		LeafNodeSource: tree.LeafNodeSourceKeyPackage,
		Lifetime:       &tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)},
	}
	if err := tree.SignLeafNode(suite, signer, &ln, nil, 0); err != nil {
		t.Fatalf("SignLeafNode: %v", err)
	}
	rt := tree.NewRatchetTree(suite, ln)
	if err := rt.VerifyLeafSignatures(nil); err != nil {
		t.Fatalf("VerifyLeafSignatures: %v", err)
	}
}

// TestGenerateUpdatePathGapFillSkip verifies that GenerateUpdatePath omits
// encrypted path secrets for newly-added members (RFC 9420 §7.5).
//
// Topology: 4-leaf tree, committer at leaf 3. Remove leaf 1 (creates a gap),
// then Add a new leaf (refills leaf 1). The committer's copath at the root has
// resolution [node0, node2]. node2 = 2*leaf1 is in newlyAdded → its ciphertext
// must be omitted, leaving exactly 1 ciphertext in Nodes[1].EncryptedPathSecret.
func TestGenerateUpdatePathGapFillSkip(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite not registered")
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sigKeyBytes, err := suite.SignaturePublicKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	cred := tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte("member")}
	caps := tree.Capabilities{
		Versions:     []tree.ProtocolVersion{tree.ProtocolVersionMLS10},
		CipherSuites: []cipher.CipherSuite{suite.ID},
		Credentials:  []tree.CredentialType{tree.CredentialTypeBasic},
	}

	makeLeaf := func() tree.LeafNode {
		_, encPub, err := suite.GenerateHPKEKeyPair()
		if err != nil {
			t.Helper()
			t.Fatalf("GenerateHPKEKeyPair: %v", err)
		}
		ln := tree.LeafNode{
			EncryptionKey:  encPub,
			SignatureKey:   sigKeyBytes,
			Credential:     cred,
			Capabilities:   caps,
			LeafNodeSource: tree.LeafNodeSourceKeyPackage,
			Lifetime:       &tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)},
		}
		if err := tree.SignLeafNode(suite, signer, &ln, nil, 0); err != nil {
			t.Helper()
			t.Fatalf("SignLeafNode: %v", err)
		}
		return ln
	}

	// Build a 4-leaf tree: NewRatchetTree(leaf0) + AddLeaf(leaf1) + AddLeaf(leaf2) + AddLeaf(leaf3).
	rt := tree.NewRatchetTree(suite, makeLeaf())
	for i := 0; i < 3; i++ {
		if _, err := rt.AddLeaf(makeLeaf()); err != nil {
			t.Fatalf("AddLeaf %d: %v", i+1, err)
		}
	}

	// Remove leaf 1 to create a gap.
	if err := rt.RemoveLeaf(1); err != nil {
		t.Fatalf("RemoveLeaf(1): %v", err)
	}

	// Add a new leaf — it should refill the blank slot at leaf index 1.
	addedIdx, err := rt.AddLeaf(makeLeaf())
	if err != nil {
		t.Fatalf("AddLeaf (refill): %v", err)
	}
	if addedIdx != 1 {
		t.Fatalf("expected refill at leaf 1, got %d", addedIdx)
	}

	// Generate an UpdatePath from leaf 3 with newlyAdded=[1].
	groupID := []byte("test-group")
	leafSecret := make([]byte, suite.HashLen())
	if _, err := rand.Read(leafSecret); err != nil {
		t.Fatal(err)
	}
	mkGC := func(treeHash []byte) ([]byte, error) {
		gc := keyschedule.GroupContext{
			Version:     tree.ProtocolVersionMLS10,
			CipherSuite: suite.ID,
			GroupID:     groupID,
			Epoch:       1,
			TreeHash:    treeHash,
		}
		return gc.MarshalMLS()
	}

	up, _, _, err := rt.GenerateUpdatePath(3, leafSecret, signer, groupID, []uint32{1}, mkGC)
	if err != nil {
		t.Fatalf("GenerateUpdatePath: %v", err)
	}

	// In a 4-leaf tree, leaf 3's filtered direct path has 2 nodes:
	//   [node5 (copath=node4=leaf2), node3/root (copath=node1)].
	// After Remove(1)+Add(newLeaf@1):
	//   Resolution(node1) = [node0, node2].
	//   node2 = 2*leaf1 is in newlyAdded → ciphertext omitted.
	// So Nodes[1].EncryptedPathSecret must have exactly 1 entry (for node0).
	if len(up.Nodes) < 2 {
		t.Fatalf("expected ≥2 UpdatePath nodes, got %d", len(up.Nodes))
	}
	gotCount := len(up.Nodes[1].EncryptedPathSecret)
	if gotCount != 1 {
		t.Fatalf("Nodes[1].EncryptedPathSecret: got %d ciphertexts, want 1 (resolution=2, minus 1 newlyAdded)", gotCount)
	}
}
