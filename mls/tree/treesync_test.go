package tree

import (
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

func eqU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Tree from RFC 9420 §4.1.1 Figure 10 (8 leaves, width 15). Node X = index 1
// (parent of leaves 0,1) is non-blank with unmerged leaf B (leaf index 1 ->
// node 2). Node Y = index 9 non-blank. Several blanks. We assert the documented
// resolutions: res(1)=[1,2], res(4)=[], res(12)=[], res(7)=[1,2,9,14].
func TestResolutionFigure10(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	blank := func(n int) []*Node { return make([]*Node, n) }
	nodes := blank(15)
	// Leaves present: A(0), B(2), D(6), E(8), F(10), H(14). Mark only what the
	// resolution depends on: X(1) and Y(9) non-blank parents; the rest blank.
	nodes[1] = &Node{Parent: &ParentNode{EncryptionKey: []byte("X"), UnmergedLeaves: []uint32{1}}} // unmerged leaf 1 -> node 2
	nodes[9] = &Node{Parent: &ParentNode{EncryptionKey: []byte("Y")}}
	nodes[14] = &Node{Leaf: testLeaf('H')}
	tr := &RatchetTree{suite: suite, nodes: nodes}

	if got := tr.Resolution(1); !eqU32(got, []uint32{1, 2}) {
		t.Fatalf("res(1)=%v want [1 2]", got)
	}
	if got := tr.Resolution(4); !eqU32(got, []uint32{}) {
		t.Fatalf("res(4)=%v want []", got)
	}
	if got := tr.Resolution(7); !eqU32(got, []uint32{1, 2, 9, 14}) {
		t.Fatalf("res(7)=%v want [1 2 9 14]", got)
	}
}
