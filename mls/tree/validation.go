package tree

import (
	"bytes"
	"fmt"
	"maps"

	"github.com/trevex/mls-go/mls/syntax"
)

// leafSet builds a set of leaf indices.
func leafSet(leaves []uint32) map[uint32]bool {
	m := make(map[uint32]bool, len(leaves))
	for _, l := range leaves {
		m[l] = true
	}
	return m
}

// parentHashOf computes the parent hash that a child of parent node pi should
// carry, given si is the copath sibling (RFC 9420 §7.9). The parent_hash field
// is read directly from P; original_sibling_tree_hash is the tree hash of S in
// the tree with P's unmerged leaves blanked.
func (t *RatchetTree) parentHashOf(pi, si uint32) ([]byte, error) {
	p := t.nodes[pi].Parent
	excluded := leafSet(p.UnmergedLeaves)
	origSibHash, err := t.treeHashExcept(si, excluded)
	if err != nil {
		return nil, err
	}
	b := syntax.NewBuilder()
	if err := b.WriteOpaqueV(p.EncryptionKey); err != nil {
		return nil, err
	}
	if err := b.WriteOpaqueV(p.ParentHash); err != nil {
		return nil, err
	}
	if err := b.WriteOpaqueV(origSibHash); err != nil {
		return nil, err
	}
	return t.suite.Hash(b.Bytes()), nil
}

// nodeParentHash returns the parent_hash stored in node i, and whether the node
// carries one (parent nodes always; leaf nodes only when source==commit).
func (t *RatchetTree) nodeParentHash(i uint32) ([]byte, bool) {
	n := t.nodes[i]
	if n == nil {
		return nil, false
	}
	if n.Leaf != nil {
		if n.Leaf.LeafNodeSource == LeafNodeSourceCommit {
			return n.Leaf.ParentHash, true
		}
		return nil, false
	}
	return n.Parent.ParentHash, true
}

// subtreeContains reports whether node is in the subtree rooted at root.
func subtreeContains(root, node uint32) bool {
	half := uint32(1)<<level(root) - 1
	return node >= root-half && node <= root+half
}

// hasParentHashMatch reports whether, treating ci as the direct-path child and
// si as the copath sibling of parent pi, some node D in resolution(ci) has a
// stored parent_hash equal to parentHashOf(pi, si) and satisfies the
// unmerged-leaves condition of RFC 9420 §7.9.2.
func (t *RatchetTree) hasParentHashMatch(pi, ci, si uint32) (bool, error) {
	want, err := t.parentHashOf(pi, si)
	if err != nil {
		return false, err
	}
	res := t.Resolution(ci)
	excluded := leafSet(t.nodes[pi].Parent.UnmergedLeaves)
	for _, d := range res {
		ph, ok := t.nodeParentHash(d)
		if !ok || !bytes.Equal(ph, want) {
			continue
		}
		// resolution(ci) with d removed must equal { 2*L : L in excluded, leaf
		// 2*L under subtree ci }.
		expected := make(map[uint32]bool)
		for l := range excluded {
			ni := 2 * l
			if subtreeContains(ci, ni) {
				expected[ni] = true
			}
		}
		actual := make(map[uint32]bool)
		for _, x := range res {
			if x != d {
				actual[x] = true
			}
		}
		if maps.Equal(actual, expected) {
			return true, nil
		}
	}
	return false, nil
}

// VerifyParentHashes checks that every non-blank parent node is parent-hash
// valid (RFC 9420 §7.9.2, top-down): exactly one orientation of its children
// must yield a matching descendant.
func (t *RatchetTree) VerifyParentHashes() (bool, error) {
	leaves := t.leafCount()
	for i := uint32(0); i < t.Width(); i++ {
		n := t.nodes[i]
		if n == nil || n.Parent == nil {
			continue
		}
		l, _ := Left(i)
		r, _ := Right(i, leaves)
		okL, err := t.hasParentHashMatch(i, l, r)
		if err != nil {
			return false, err
		}
		okR, err := t.hasParentHashMatch(i, r, l)
		if err != nil {
			return false, err
		}
		if okL == okR { // need exactly one orientation to match
			return false, nil
		}
	}
	return true, nil
}

// VerifyLeafSignatures verifies the signature on every non-blank leaf using
// groupID as context for update/commit leaves (RFC 9420 §7.3), and checks that
// signature_key and encryption_key are unique across all leaves.
func (t *RatchetTree) VerifyLeafSignatures(groupID []byte) error {
	sigKeys := make(map[string]bool)
	encKeys := make(map[string]bool)
	for i := uint32(0); i < t.Width(); i += 2 {
		n := t.nodes[i]
		if n == nil || n.Leaf == nil {
			continue
		}
		leafIndex := i / 2
		ok, err := n.Leaf.verifySignature(t.suite, groupID, leafIndex)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("tree: invalid signature on leaf %d", leafIndex)
		}
		sk := string(n.Leaf.SignatureKey)
		if sigKeys[sk] {
			return fmt.Errorf("tree: duplicate signature_key at leaf %d", leafIndex)
		}
		sigKeys[sk] = true
		ek := string(n.Leaf.EncryptionKey)
		if encKeys[ek] {
			return fmt.Errorf("tree: duplicate encryption_key at leaf %d", leafIndex)
		}
		encKeys[ek] = true
	}
	return nil
}
