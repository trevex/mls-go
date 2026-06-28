package tree

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
)

// minLeaf returns a minimal valid LeafNode with the given encryptionKey.
// The LeafNodeSource is KeyPackage so it carries a Lifetime (required by marshal).
func minLeaf(encKey []byte) *Node {
	lt := &Lifetime{NotBefore: 0, NotAfter: 1 << 62}
	return &Node{Leaf: &LeafNode{
		EncryptionKey:  encKey,
		SignatureKey:   []byte{0xff},
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("test")},
		Capabilities:   Capabilities{},
		LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime:       lt,
		Extensions:     nil,
		Signature:      []byte{0xfe},
	}}
}

// minParent returns a minimal ParentNode.
func minParent(encKey []byte) *Node {
	return &Node{Parent: &ParentNode{EncryptionKey: encKey}}
}

// buildTree constructs a RatchetTree directly from a nodes slice and
// round-trips through MarshalMLS/ParseRatchetTree so Clone also works.
func buildTree(t *testing.T, suite cipher.Suite, nodes []*Node) *RatchetTree {
	t.Helper()
	rt := &RatchetTree{suite: suite, nodes: nodes}
	data, err := rt.MarshalMLS()
	if err != nil {
		t.Fatalf("buildTree MarshalMLS: %v", err)
	}
	parsed, err := ParseRatchetTree(suite, data)
	if err != nil {
		t.Fatalf("buildTree ParseRatchetTree: %v", err)
	}
	return parsed
}

func testSuite(t *testing.T) cipher.Suite {
	t.Helper()
	s, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite 1 not registered")
	}
	return s
}

func TestMutate_LeafNodeAt(t *testing.T) {
	suite := testSuite(t)
	// 2-leaf tree: [l0, parent, l1]
	rt := buildTree(t, suite, []*Node{
		minLeaf([]byte{0x01}),
		minParent([]byte{0x05}),
		minLeaf([]byte{0x06}),
	})

	ln0, err := rt.LeafNodeAt(0)
	if err != nil {
		t.Fatalf("LeafNodeAt(0): %v", err)
	}
	if !bytes.Equal(ln0.EncryptionKey, []byte{0x01}) {
		t.Errorf("leaf 0 enc key: got %x, want 01", ln0.EncryptionKey)
	}

	ln1, err := rt.LeafNodeAt(1)
	if err != nil {
		t.Fatalf("LeafNodeAt(1): %v", err)
	}
	if !bytes.Equal(ln1.EncryptionKey, []byte{0x06}) {
		t.Errorf("leaf 1 enc key: got %x, want 06", ln1.EncryptionKey)
	}

	// After growing (leaf 2 is blank after AddLeaf from a full tree – test via
	// LeafNodeAt on a blank slot, which requires a tree with blank leaves).
	// For now just check out-of-range doesn't panic.
	_, err = rt.LeafNodeAt(99)
	if err == nil {
		t.Error("LeafNodeAt(99): expected error on out-of-range blank")
	}
}

func TestMutate_FindLeafByEncryptionKey(t *testing.T) {
	suite := testSuite(t)
	rt := buildTree(t, suite, []*Node{
		minLeaf([]byte{0x01}),
		minParent([]byte{0x05}),
		minLeaf([]byte{0x06}),
	})

	idx, ok := rt.FindLeafByEncryptionKey([]byte{0x01})
	if !ok || idx != 0 {
		t.Errorf("FindLeafByEncryptionKey(01): got idx=%d ok=%v, want 0/true", idx, ok)
	}
	idx, ok = rt.FindLeafByEncryptionKey([]byte{0x06})
	if !ok || idx != 1 {
		t.Errorf("FindLeafByEncryptionKey(06): got idx=%d ok=%v, want 1/true", idx, ok)
	}
	_, ok = rt.FindLeafByEncryptionKey([]byte{0xAA})
	if ok {
		t.Error("FindLeafByEncryptionKey(AA): expected not found")
	}
}

func TestMutate_Clone(t *testing.T) {
	suite := testSuite(t)
	rt := buildTree(t, suite, []*Node{
		minLeaf([]byte{0x01}),
		minParent([]byte{0x05}),
		minLeaf([]byte{0x06}),
	})

	clone, err := rt.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}

	// Mutating the clone's leaf 0 should not affect the original.
	newLeaf := LeafNode{
		EncryptionKey:  []byte{0xAA},
		SignatureKey:   []byte{0xff},
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("mutated")},
		Capabilities:   Capabilities{},
		LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime:       &Lifetime{NotAfter: 1 << 62},
		Signature:      []byte{0xfe},
	}
	if err := clone.UpdateLeaf(0, newLeaf); err != nil {
		t.Fatalf("clone.UpdateLeaf: %v", err)
	}

	// Original leaf 0 must still be 0x01.
	orig0, err := rt.LeafNodeAt(0)
	if err != nil {
		t.Fatalf("LeafNodeAt(0) on original: %v", err)
	}
	if !bytes.Equal(orig0.EncryptionKey, []byte{0x01}) {
		t.Errorf("original leaf 0 mutated: got %x, want 01", orig0.EncryptionKey)
	}

	// Clone leaf 0 must be 0xAA.
	cl0, err := clone.LeafNodeAt(0)
	if err != nil {
		t.Fatalf("LeafNodeAt(0) on clone: %v", err)
	}
	if !bytes.Equal(cl0.EncryptionKey, []byte{0xAA}) {
		t.Errorf("clone leaf 0: got %x, want AA", cl0.EncryptionKey)
	}
}

func TestMutate_UpdateLeaf(t *testing.T) {
	suite := testSuite(t)
	// 2-leaf tree: root is at index 1.
	rt := buildTree(t, suite, []*Node{
		minLeaf([]byte{0x01}),
		minParent([]byte{0x05}), // root / direct path of both leaves
		minLeaf([]byte{0x06}),
	})

	newLeaf := LeafNode{
		EncryptionKey:  []byte{0x02},
		SignatureKey:   []byte{0xff},
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("updated")},
		Capabilities:   Capabilities{},
		LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime:       &Lifetime{NotAfter: 1 << 62},
		Signature:      []byte{0xfe},
	}
	if err := rt.UpdateLeaf(0, newLeaf); err != nil {
		t.Fatalf("UpdateLeaf: %v", err)
	}

	// Leaf 0 should now have encKey=02.
	ln0, err := rt.LeafNodeAt(0)
	if err != nil {
		t.Fatalf("LeafNodeAt(0): %v", err)
	}
	if !bytes.Equal(ln0.EncryptionKey, []byte{0x02}) {
		t.Errorf("leaf 0 after update: got %x, want 02", ln0.EncryptionKey)
	}

	// Direct path of leaf 0 (node 0) for a 2-leaf tree: parent is node 1 (root).
	// It must be blanked.
	if rt.NodeAt(1) != nil {
		t.Error("UpdateLeaf: direct path (node 1) should be blank after update")
	}
}

func TestMutate_RemoveLeaf(t *testing.T) {
	suite := testSuite(t)
	// 2-leaf tree: [l0, parent, l1]
	rt := buildTree(t, suite, []*Node{
		minLeaf([]byte{0x01}),
		minParent([]byte{0x05}),
		minLeaf([]byte{0x06}),
	})

	if err := rt.RemoveLeaf(1); err != nil {
		t.Fatalf("RemoveLeaf(1): %v", err)
	}

	// Leaf 1 should be blank.
	_, err := rt.LeafNodeAt(1)
	if err == nil {
		t.Error("RemoveLeaf: leaf 1 should be blank")
	}

	// Direct path of leaf 1 (node 2) for a 2-leaf tree: parent is node 1 (root).
	// It must be blanked.
	if rt.NodeAt(1) != nil {
		t.Error("RemoveLeaf: direct path (node 1) should be blank")
	}

	// Leaf 0 should still be present.
	ln0, err := rt.LeafNodeAt(0)
	if err != nil {
		t.Fatalf("LeafNodeAt(0) after remove: %v", err)
	}
	if !bytes.Equal(ln0.EncryptionKey, []byte{0x01}) {
		t.Errorf("leaf 0 after remove: got %x, want 01", ln0.EncryptionKey)
	}
}

func TestMutate_AddLeaf_GrowsTree(t *testing.T) {
	suite := testSuite(t)
	// 2-leaf tree (full): [l0, parent(root), l1]
	rt := buildTree(t, suite, []*Node{
		minLeaf([]byte{0x01}),
		minParent([]byte{0x05}),
		minLeaf([]byte{0x06}),
	})

	if rt.LeafCount() != 2 {
		t.Fatalf("initial leaf count: got %d, want 2", rt.LeafCount())
	}

	newLeaf := LeafNode{
		EncryptionKey:  []byte{0x11},
		SignatureKey:   []byte{0xff},
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("charlie")},
		Capabilities:   Capabilities{},
		LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime:       &Lifetime{NotAfter: 1 << 62},
		Signature:      []byte{0xfe},
	}
	idx, err := rt.AddLeaf(newLeaf)
	if err != nil {
		t.Fatalf("AddLeaf: %v", err)
	}
	if idx != 2 {
		t.Errorf("AddLeaf: got leaf index %d, want 2", idx)
	}

	// Tree grew to 4-leaf capacity.
	if rt.LeafCount() != 4 {
		t.Errorf("after AddLeaf: leaf count = %d, want 4", rt.LeafCount())
	}

	// New leaf appears at node 4.
	ln2, err := rt.LeafNodeAt(2)
	if err != nil {
		t.Fatalf("LeafNodeAt(2): %v", err)
	}
	if !bytes.Equal(ln2.EncryptionKey, []byte{0x11}) {
		t.Errorf("new leaf enc key: got %x, want 11", ln2.EncryptionKey)
	}

	// Leaf 4 (index 3) should be blank.
	_, err = rt.LeafNodeAt(3)
	if err == nil {
		t.Error("leaf 3 (4th slot) should be blank after growing to 4-leaf tree")
	}
}

func TestMutate_AddLeaf_FillsBlank(t *testing.T) {
	suite := testSuite(t)
	// 3-leaf tree padded to 4-leaf-wide: l0, p01, l1, ROOT, l2
	// root at node 3 (non-nil), leaf3 slot (node 6) is blank.
	rt := buildTree(t, suite, []*Node{
		minLeaf([]byte{0x01}),   // 0
		minParent([]byte{0x05}), // 1
		minLeaf([]byte{0x06}),   // 2
		minParent([]byte{0x07}), // 3 (ROOT)
		minLeaf([]byte{0x08}),   // 4
		// nodes 5,6 will be nil after padding
	})
	// After ParseRatchetTree the tree is padded to fullWidth(5)=7:
	// [l0, p01, l1, ROOT, l2, nil, nil]
	// leafCount=4, leaf3 (node 6) is blank.

	if rt.LeafCount() != 4 {
		t.Fatalf("initial leaf count: got %d, want 4", rt.LeafCount())
	}

	newLeaf := LeafNode{
		EncryptionKey:  []byte{0x22},
		SignatureKey:   []byte{0xff},
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("dave")},
		Capabilities:   Capabilities{},
		LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime:       &Lifetime{NotAfter: 1 << 62},
		Signature:      []byte{0xfe},
	}
	idx, err := rt.AddLeaf(newLeaf)
	if err != nil {
		t.Fatalf("AddLeaf: %v", err)
	}
	if idx != 3 {
		t.Errorf("AddLeaf: got leaf index %d, want 3", idx)
	}

	// New leaf at node 6.
	ln3, err := rt.LeafNodeAt(3)
	if err != nil {
		t.Fatalf("LeafNodeAt(3): %v", err)
	}
	if !bytes.Equal(ln3.EncryptionKey, []byte{0x22}) {
		t.Errorf("new leaf enc key: got %x, want 22", ln3.EncryptionKey)
	}

	// Root (node 3) should have leaf 3 in its UnmergedLeaves.
	// Direct path of leaf3 (node 6): Parent(6,4)=5 (nil), Parent(5,4)=3 (ROOT, populated).
	// So ROOT.UnmergedLeaves should include leaf index 3.
	rootNode := rt.NodeAt(3)
	if rootNode == nil || rootNode.Parent == nil {
		t.Fatal("ROOT (node 3) should still be populated")
	}
	found := false
	for _, ul := range rootNode.Parent.UnmergedLeaves {
		if ul == 3 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ROOT.UnmergedLeaves = %v, expected to contain 3", rootNode.Parent.UnmergedLeaves)
	}
}

func TestMutate_LeafNodeAt_Blank(t *testing.T) {
	suite := testSuite(t)
	// 3-leaf tree with leaf3 blank.
	rt := buildTree(t, suite, []*Node{
		minLeaf([]byte{0x01}),
		minParent([]byte{0x05}),
		minLeaf([]byte{0x06}),
		minParent([]byte{0x07}),
		minLeaf([]byte{0x08}),
	})
	// Leaf 3 (node 6) is blank.
	_, err := rt.LeafNodeAt(3)
	if err == nil {
		t.Error("LeafNodeAt(3): expected error on blank leaf")
	}
}
