package tree

import (
	"bytes"
	"fmt"
)

// LeafCount returns the number of leaves: (width + 1) / 2.
func (t *RatchetTree) LeafCount() uint32 { return t.leafCount() }

// NodeAt returns the node at array index i (nil if blank or out of range).
func (t *RatchetTree) NodeAt(i uint32) *Node {
	if i >= uint32(len(t.nodes)) {
		return nil
	}
	return t.nodes[i]
}

// LeafNodeAt returns the LeafNode at leaf index L (node 2L), or an error if blank.
func (t *RatchetTree) LeafNodeAt(leaf uint32) (LeafNode, error) {
	n := t.NodeAt(2 * leaf)
	if n == nil || n.Leaf == nil {
		return LeafNode{}, fmt.Errorf("tree: leaf %d is blank", leaf)
	}
	return *n.Leaf, nil
}

// FindLeafByEncryptionKey returns the leaf index whose LeafNode.EncryptionKey
// matches key, and ok=false if none.
func (t *RatchetTree) FindLeafByEncryptionKey(key []byte) (uint32, bool) {
	for i := uint32(0); i < t.Width(); i += 2 {
		n := t.nodes[i]
		if n != nil && n.Leaf != nil && bytes.Equal(n.Leaf.EncryptionKey, key) {
			return i / 2, true
		}
	}
	return 0, false
}

// Clone returns a deep copy via marshal/parse round-trip (used to compute the
// provisional tree hash without mutating the live tree).
func (t *RatchetTree) Clone() (*RatchetTree, error) {
	data, err := t.MarshalMLS()
	if err != nil {
		return nil, err
	}
	return ParseRatchetTree(t.suite, data)
}

// UpdateLeaf replaces the LeafNode at leaf index L and blanks L's direct path
// (RFC 9420 §12.3 — Update). The new leaf's encryption/signature keys come from ln.
func (t *RatchetTree) UpdateLeaf(leaf uint32, ln LeafNode) error {
	if 2*leaf >= t.Width() {
		return fmt.Errorf("tree: UpdateLeaf: leaf %d out of range", leaf)
	}
	lnCopy := ln
	t.nodes[2*leaf] = &Node{Leaf: &lnCopy}
	// Blank the direct path.
	leaves := t.leafCount()
	root := Root(leaves)
	x := 2 * leaf
	for x != root {
		p, ok := Parent(x, leaves)
		if !ok {
			break
		}
		t.nodes[p] = nil
		x = p
	}
	return nil
}

// RemoveLeaf blanks leaf index L and its direct path, then truncates trailing
// blank nodes so the array ends on a non-blank node (RFC 9420 §12.3 — Remove).
func (t *RatchetTree) RemoveLeaf(leaf uint32) error {
	if 2*leaf >= t.Width() {
		return fmt.Errorf("tree: RemoveLeaf: leaf %d out of range", leaf)
	}
	t.nodes[2*leaf] = nil
	// Blank the direct path.
	leaves := t.leafCount()
	root := Root(leaves)
	x := 2 * leaf
	for x != root {
		p, ok := Parent(x, leaves)
		if !ok {
			break
		}
		t.nodes[p] = nil
		x = p
	}
	// Truncate trailing blank nodes so the array ends on a non-blank node.
	for len(t.nodes) > 1 && t.nodes[len(t.nodes)-1] == nil {
		t.nodes = t.nodes[:len(t.nodes)-1]
	}
	// Re-pad to fullWidth so the array width stays a valid complete-tree width.
	w := fullWidth(uint32(len(t.nodes)))
	if uint32(len(t.nodes)) < w {
		t.nodes = append(t.nodes, make([]*Node, w-uint32(len(t.nodes)))...)
	}
	return nil
}

// AddLeaf inserts ln at the leftmost blank leaf (extending the tree by one leaf
// and a parent if full), adds the new leaf to each populated ancestor's
// unmerged_leaves, and returns the new leaf index (RFC 9420 §12.3 — Add / §7.x).
func (t *RatchetTree) AddLeaf(ln LeafNode) (uint32, error) {
	// Find the first blank leaf slot.
	var newNode uint32
	found := false
	for i := uint32(0); i < t.Width(); i += 2 {
		if t.nodes[i] == nil {
			newNode = i
			found = true
			break
		}
	}
	if !found {
		// Tree is full: grow by 2 (new parent slot + new leaf slot) and re-pad.
		t.nodes = append(t.nodes, make([]*Node, 2)...)
		w := fullWidth(uint32(len(t.nodes)))
		if uint32(len(t.nodes)) < w {
			t.nodes = append(t.nodes, make([]*Node, w-uint32(len(t.nodes)))...)
		}
		// Re-scan for the first blank leaf after growing.
		for i := uint32(0); i < t.Width(); i += 2 {
			if t.nodes[i] == nil {
				newNode = i
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("tree: AddLeaf: no blank slot after growing")
		}
	}

	leafIndex := newNode / 2
	lnCopy := ln
	t.nodes[newNode] = &Node{Leaf: &lnCopy}

	// Walk the new leaf's direct path and add leafIndex to every populated
	// ancestor's unmerged_leaves (kept sorted ascending).
	leaves := t.leafCount()
	root := Root(leaves)
	x := newNode
	for x != root {
		p, ok := Parent(x, leaves)
		if !ok {
			break
		}
		if t.nodes[p] != nil && t.nodes[p].Parent != nil {
			ul := t.nodes[p].Parent.UnmergedLeaves
			// Binary-search insertion point.
			lo := 0
			for lo < len(ul) && ul[lo] < leafIndex {
				lo++
			}
			newUL := make([]uint32, len(ul)+1)
			copy(newUL[:lo], ul[:lo])
			newUL[lo] = leafIndex
			copy(newUL[lo+1:], ul[lo:])
			t.nodes[p].Parent.UnmergedLeaves = newUL
		}
		x = p
	}

	return leafIndex, nil
}
