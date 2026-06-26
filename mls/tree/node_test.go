package tree

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
)

func testLeaf(id byte) *LeafNode {
	return &LeafNode{
		EncryptionKey:  []byte{id, 'e'},
		SignatureKey:   []byte{id, 's'},
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte{id}},
		Capabilities:   sampleCapabilities(),
		LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime:       &Lifetime{NotBefore: 0, NotAfter: 1},
		Extensions:     []Extension{},
		Signature:      []byte{id, 'g'},
	}
}

func TestRatchetTreeRoundTripAndExtend(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	// Two leaves, one parent => compact width 3. Serialize with a trailing
	// blank that MUST be dropped, then reparse.
	tr := &RatchetTree{
		suite: suite,
		nodes: []*Node{
			{Leaf: testLeaf('a')},
			{Parent: &ParentNode{EncryptionKey: []byte("p"), UnmergedLeaves: []uint32{1}}},
			{Leaf: testLeaf('b')},
		},
	}
	enc, err := tr.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRatchetTree(suite, enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Width() != 3 {
		t.Fatalf("width=%d want 3", got.Width())
	}
	re, _ := got.MarshalMLS()
	if !bytes.Equal(re, enc) {
		t.Fatalf("re-serialize mismatch")
	}
}

func TestParseRejectsTrailingBlank(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	// optional<Node><V> body: [present + leaf-node][absent]. The trailing
	// absent node makes this malformed per RFC 9420 §12.4.3.1. Build the body
	// with the real codec so the varint length prefix is correct for any size.
	inner := syntax.NewBuilder()
	inner.WriteUint8(0x01) // optional present
	if err := (Node{Leaf: testLeaf('a')}).marshal(inner); err != nil {
		t.Fatal(err)
	}
	inner.WriteUint8(0x00) // optional absent (trailing blank)
	outer := syntax.NewBuilder()
	if err := outer.WriteOpaqueV(inner.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRatchetTree(suite, outer.Bytes()); err == nil {
		t.Fatal("expected error for trailing blank node")
	}
}

func TestFullWidth(t *testing.T) {
	cases := map[uint32]uint32{1: 1, 2: 3, 3: 3, 4: 7, 5: 7, 7: 7, 8: 15, 11: 15}
	for in, want := range cases {
		if got := fullWidth(in); got != want {
			t.Fatalf("fullWidth(%d)=%d want %d", in, got, want)
		}
	}
}
