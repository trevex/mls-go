package tree

import "github.com/trevex/mls-mlkem-go/mls/syntax"

// Resolution returns the resolution of node index i as a list of node indices
// (RFC 9420 §4.1.1).
func (t *RatchetTree) Resolution(i uint32) []uint32 {
	n := t.nodes[i]
	if n != nil {
		// Non-blank: the node itself, then its unmerged leaves as node indices.
		res := []uint32{i}
		if n.Parent != nil {
			for _, leaf := range n.Parent.UnmergedLeaves {
				res = append(res, 2*leaf)
			}
		}
		return res
	}
	// Blank node.
	left, ok := Left(i)
	if !ok {
		return []uint32{} // blank leaf
	}
	right, _ := Right(i, t.leafCount())
	res := append([]uint32{}, t.Resolution(left)...)
	return append(res, t.Resolution(right)...)
}

// TreeHash returns the tree hash of the subtree rooted at node index i
// (RFC 9420 §7.8).
func (t *RatchetTree) TreeHash(i uint32) ([]byte, error) {
	return t.treeHashExcept(i, nil)
}

// RootTreeHash returns the tree hash of the whole tree (its root).
func (t *RatchetTree) RootTreeHash() ([]byte, error) {
	return t.TreeHash(Root(t.leafCount()))
}

// treeHashExcept computes the tree hash of the subtree rooted at i (RFC 9420
// §7.8). Every leaf whose index is in excluded is treated as blank, and every
// ParentNode.unmerged_leaves is filtered to drop entries in excluded — this is
// the "original tree hash" of §7.9. With excluded nil/empty it is the ordinary
// tree hash.
func (t *RatchetTree) treeHashExcept(i uint32, excluded map[uint32]bool) ([]byte, error) {
	b := syntax.NewBuilder()
	left, isParent := Left(i)
	if !isParent {
		// Leaf node.
		leafIndex := i / 2
		var leaf *LeafNode
		if n := t.nodes[i]; n != nil && n.Leaf != nil && !excluded[leafIndex] {
			leaf = n.Leaf
		}
		b.WriteUint8(uint8(NodeTypeLeaf))
		b.WriteUint32(leafIndex)
		if err := syntax.WriteOptional(b, leaf, func(b *syntax.Builder, l LeafNode) error {
			return l.marshal(b)
		}); err != nil {
			return nil, err
		}
		return t.suite.Hash(b.Bytes()), nil
	}
	// Parent node.
	right, _ := Right(i, t.leafCount())
	leftHash, err := t.treeHashExcept(left, excluded)
	if err != nil {
		return nil, err
	}
	rightHash, err := t.treeHashExcept(right, excluded)
	if err != nil {
		return nil, err
	}
	var parent *ParentNode
	if n := t.nodes[i]; n != nil && n.Parent != nil {
		p := *n.Parent
		if len(excluded) > 0 {
			p.UnmergedLeaves = filterLeaves(p.UnmergedLeaves, excluded)
		}
		parent = &p
	}
	b.WriteUint8(uint8(NodeTypeParent))
	if err := syntax.WriteOptional(b, parent, func(b *syntax.Builder, pn ParentNode) error {
		return pn.marshal(b)
	}); err != nil {
		return nil, err
	}
	if err := b.WriteOpaqueV(leftHash); err != nil {
		return nil, err
	}
	if err := b.WriteOpaqueV(rightHash); err != nil {
		return nil, err
	}
	return t.suite.Hash(b.Bytes()), nil
}

// filterLeaves returns leaves with every entry in excluded removed.
func filterLeaves(leaves []uint32, excluded map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(leaves))
	for _, l := range leaves {
		if !excluded[l] {
			out = append(out, l)
		}
	}
	return out
}
