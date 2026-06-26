package tree

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
