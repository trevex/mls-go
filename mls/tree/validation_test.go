package tree

import (
	"crypto/ed25519"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

// Build a clean 2-leaf tree where the committer's leaf (index 0, node 0) and
// the parent (node 1) form a valid parent-hash chain, and both leaves are
// validly signed. This exercises VerifyParentHashes and VerifyLeafSignatures
// end-to-end without the KAT.
func TestVerifyParentHashesAndSignatures(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	groupID := []byte("g")

	// Parent node P at index 1, with no unmerged leaves and root parent_hash "".
	parent := &ParentNode{EncryptionKey: []byte("penc"), ParentHash: nil}

	// Sibling S of node 0 is node 2 (leaf 1). Committer leaf is node 0 (leaf 0),
	// child C of P on the committer's side; sibling S = node 2.
	// Committer leaf's parent_hash = Hash(ParentHashInput{P.enc, "", origSibTH}).
	tr := &RatchetTree{suite: suite, nodes: []*Node{nil, {Parent: parent}, nil}}

	// Build leaf 1 (the sibling subtree) first so its tree hash is fixed.
	pub1, priv1, _ := ed25519.GenerateKey(nil)
	leaf1 := &LeafNode{
		EncryptionKey: []byte("e1"), SignatureKey: []byte(pub1),
		Credential:   Credential{CredentialType: CredentialTypeBasic, Identity: []byte("1")},
		Capabilities: sampleCapabilities(), LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime: &Lifetime{NotBefore: 0, NotAfter: 1}, Extensions: []Extension{},
	}
	tbs1, _ := leaf1.tbs(groupID, 1)
	leaf1.Signature, _ = suite.SignWithLabel(priv1, "LeafNodeTBS", tbs1)
	tr.nodes[2] = &Node{Leaf: leaf1}

	// Committer leaf 0, source=commit, parent_hash = parentHashOf(P=1, S=2).
	wantPH, err := tr.parentHashOf(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	pub0, priv0, _ := ed25519.GenerateKey(nil)
	leaf0 := &LeafNode{
		EncryptionKey: []byte("e0"), SignatureKey: []byte(pub0),
		Credential:   Credential{CredentialType: CredentialTypeBasic, Identity: []byte("0")},
		Capabilities: sampleCapabilities(), LeafNodeSource: LeafNodeSourceCommit,
		ParentHash: wantPH, Extensions: []Extension{},
	}
	tbs0, _ := leaf0.tbs(groupID, 0)
	leaf0.Signature, _ = suite.SignWithLabel(priv0, "LeafNodeTBS", tbs0)
	tr.nodes[0] = &Node{Leaf: leaf0}

	ok, err := tr.VerifyParentHashes()
	if err != nil || !ok {
		t.Fatalf("VerifyParentHashes ok=%v err=%v", ok, err)
	}
	if err := tr.VerifyLeafSignatures(groupID); err != nil {
		t.Fatalf("VerifyLeafSignatures: %v", err)
	}

	// Corrupt the committer's parent_hash -> verification must fail.
	bad := *tr
	badNodes := append([]*Node{}, tr.nodes...)
	badLeaf := *leaf0
	badLeaf.ParentHash = append([]byte{0xff}, wantPH...)
	badNodes[0] = &Node{Leaf: &badLeaf}
	bad.nodes = badNodes
	if ok, _ := bad.VerifyParentHashes(); ok {
		t.Fatal("expected parent-hash verification to fail after corruption")
	}
}

func TestVerifyLeafSignaturesRejectsDuplicateKeys(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	groupID := []byte("g")
	pub, priv, _ := ed25519.GenerateKey(nil)
	mk := func(id byte) *Node {
		l := &LeafNode{
			EncryptionKey: []byte("same-enc"), SignatureKey: []byte(pub),
			Credential:   Credential{CredentialType: CredentialTypeBasic, Identity: []byte{id}},
			Capabilities: sampleCapabilities(), LeafNodeSource: LeafNodeSourceKeyPackage,
			Lifetime: &Lifetime{NotBefore: 0, NotAfter: 1}, Extensions: []Extension{},
		}
		tbs, _ := l.tbs(groupID, 0)
		l.Signature, _ = suite.SignWithLabel(priv, "LeafNodeTBS", tbs)
		return &Node{Leaf: l}
	}
	tr := &RatchetTree{suite: suite, nodes: []*Node{mk('a'), {Parent: &ParentNode{EncryptionKey: []byte("p")}}, mk('b')}}
	if err := tr.VerifyLeafSignatures(groupID); err == nil {
		t.Fatal("expected duplicate-key error")
	}
}
