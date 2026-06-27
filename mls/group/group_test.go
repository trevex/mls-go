package group

// Internal unit tests (package group) for commonAncestor, levelOf, and
// the §12.3 proposal application order.

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func testSuiteGroup(t *testing.T) cipher.Suite {
	t.Helper()
	s, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite 1 not registered")
	}
	return s
}

// buildTestTree encodes nodes as the ratchet_tree wire format and parses it
// with tree.ParseRatchetTree, giving a valid RatchetTree accessible from
// package group without touching unexported tree internals.
func buildTestTree(t *testing.T, suite cipher.Suite, nodes []*tree.Node) *tree.RatchetTree {
	t.Helper()
	// Build the inner body: optional<Node>* where each optional<Node> is
	// 0x00 (blank) or 0x01 + Node.MarshalMLS() bytes.
	inner := syntax.NewBuilder()
	for _, n := range nodes {
		if n == nil {
			inner.WriteUint8(0) // absent
		} else {
			inner.WriteUint8(1) // present
			nb, err := n.MarshalMLS()
			if err != nil {
				t.Fatalf("Node.MarshalMLS: %v", err)
			}
			inner.WriteRaw(nb)
		}
	}
	// Wrap in vector<V> (varint length prefix).
	outer := syntax.NewBuilder()
	if err := outer.WriteOpaqueV(inner.Bytes()); err != nil {
		t.Fatalf("WriteOpaqueV: %v", err)
	}
	rt, err := tree.ParseRatchetTree(suite, outer.Bytes())
	if err != nil {
		t.Fatalf("ParseRatchetTree: %v", err)
	}
	return rt
}

// minTestLeaf builds a minimal LeafNode node (KeyPackage source, all-dummy keys).
func minTestLeaf(encKey []byte) *tree.Node {
	return &tree.Node{Leaf: &tree.LeafNode{
		EncryptionKey:  encKey,
		SignatureKey:   []byte{0xff},
		Credential:     tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte("test")},
		Capabilities:   tree.Capabilities{},
		LeafNodeSource: tree.LeafNodeSourceKeyPackage,
		Lifetime:       &tree.Lifetime{NotBefore: 0, NotAfter: 1 << 62},
		Extensions:     nil,
		Signature:      []byte{0xfe},
	}}
}

// minTestParent builds a minimal ParentNode with the given encryption key.
func minTestParent(encKey []byte) *tree.Node {
	return &tree.Node{Parent: &tree.ParentNode{EncryptionKey: encKey}}
}

// ─── TestCommonAncestor ───────────────────────────────────────────────────────

func TestCommonAncestor(t *testing.T) {
	// 4-leaf tree: NodeWidth=7, leaves at 0,2,4,6.
	// Tree structure:
	//   parent 1 covers leaves 0,2
	//   parent 5 covers leaves 4,6
	//   root   3 covers all
	nLeaves := uint32(4)
	tests := []struct {
		name     string
		x, y     uint32
		wantNode uint32
	}{
		{"same leaf (0,0)", 0, 0, 0},
		{"siblings leaves 0 and 2", 0, 2, 1},
		{"cousins leaves 0 and 4", 0, 4, 3}, // root
		{"cousins leaves 0 and 6", 0, 6, 3}, // root
		{"siblings leaves 4 and 6", 4, 6, 5},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := commonAncestor(tc.x, tc.y, nLeaves)
			if got != tc.wantNode {
				t.Errorf("commonAncestor(%d,%d,%d) = %d, want %d",
					tc.x, tc.y, nLeaves, got, tc.wantNode)
			}
		})
	}
}

// ─── TestApplyProposals ───────────────────────────────────────────────────────

func TestApplyProposals(t *testing.T) {
	suite := testSuiteGroup(t)

	// 2-leaf tree: [leaf0(enc=0x01), parent(enc=0x05), leaf1(enc=0x06)]
	rt := buildTestTree(t, suite, []*tree.Node{
		minTestLeaf([]byte{0x01}),
		minTestParent([]byte{0x05}),
		minTestLeaf([]byte{0x06}),
	})
	if rt.LeafCount() != 2 {
		t.Fatalf("initial leaf count: got %d, want 2", rt.LeafCount())
	}

	// Build a Commit with by-value Remove(leaf 1) then Add(new leaf enc=0x07).
	// §12.3 order = Remove before Add → the Add fills the slot vacated by Remove.
	newLeaf := tree.LeafNode{
		EncryptionKey:  []byte{0x07},
		SignatureKey:   []byte{0xff},
		Credential:     tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte("new")},
		Capabilities:   tree.Capabilities{},
		LeafNodeSource: tree.LeafNodeSourceKeyPackage,
		Lifetime:       &tree.Lifetime{NotBefore: 0, NotAfter: 1 << 62},
		Signature:      []byte{0xfe},
	}
	cm := Commit{
		Proposals: []ProposalOrRef{
			{
				Type: ProposalOrRefTypeProposal,
				Proposal: &Proposal{
					Type:   ProposalTypeRemove,
					Remove: &Remove{Removed: 1},
				},
			},
			{
				Type: ProposalOrRefTypeProposal,
				Proposal: &Proposal{
					Type: ProposalTypeAdd,
					Add:  &Add{KeyPackage: KeyPackage{LeafNode: newLeaf}},
				},
			},
		},
	}

	cache := make(map[string]cachedProposal)
	provisionalExt, psks, pathRequired, _, err := applyProposals(
		suite, rt, cm, cache, nil, nil, nil, nil, 0,
	)
	if err != nil {
		t.Fatalf("applyProposals: %v", err)
	}

	if !pathRequired {
		t.Error("pathRequired should be true (Remove + Add)")
	}
	if len(provisionalExt) != 0 {
		t.Errorf("provisionalExt: got %v, want nil/empty (no GCE proposal)", provisionalExt)
	}
	if len(psks) != 0 {
		t.Errorf("psks: got %v, want empty", psks)
	}

	// With correct §12.3 order (Remove first, then Add), the Add fills slot 1.
	ln0, err := rt.LeafNodeAt(0)
	if err != nil {
		t.Fatalf("LeafNodeAt(0): %v", err)
	}
	if !bytes.Equal(ln0.EncryptionKey, []byte{0x01}) {
		t.Errorf("leaf 0 enc key: got %x, want 01 (unchanged)", ln0.EncryptionKey)
	}

	ln1, err := rt.LeafNodeAt(1)
	if err != nil {
		t.Fatalf("LeafNodeAt(1) after Remove+Add: %v", err)
	}
	if !bytes.Equal(ln1.EncryptionKey, []byte{0x07}) {
		t.Errorf("leaf 1 enc key: got %x, want 07 (new leaf in reclaimed slot)", ln1.EncryptionKey)
	}
}
