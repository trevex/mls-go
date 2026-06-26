// Package tree implements the node-index math for the RFC 9420 §4.1.2
// left-balanced binary tree used by TreeKEM. Indices are array positions:
// leaves at even indices, intermediate nodes at odd indices.
package tree

import "math/bits"

// NodeWidth returns the number of nodes for a tree with nLeaves leaves.
func NodeWidth(nLeaves uint32) uint32 {
	if nLeaves == 0 {
		return 0
	}
	return 2*(nLeaves-1) + 1
}

// log2 returns floor(log2(x)) for x > 0; log2(0) == 0.
func log2(x uint32) uint32 {
	if x == 0 {
		return 0
	}
	return uint32(bits.Len32(x)) - 1
}

// level returns the level of node x: the number of trailing 1-bits in its
// index (its height in the complete binary tree). Leaves (even indices) are
// level 0.
func level(x uint32) uint32 {
	if x&1 == 0 {
		return 0
	}
	k := uint32(0)
	for (x>>k)&1 == 1 {
		k++
	}
	return k
}

// Root returns the root node index for a tree of nLeaves leaves.
func Root(nLeaves uint32) uint32 {
	w := NodeWidth(nLeaves)
	return (1 << log2(w)) - 1
}

// Left returns the left child of x; ok is false if x is a leaf.
func Left(x uint32) (uint32, bool) {
	k := level(x)
	if k == 0 {
		return 0, false
	}
	return x ^ (1 << (k - 1)), true
}

// Right returns the right child of x; ok is false if x is a leaf.
func Right(x uint32) (uint32, bool) {
	k := level(x)
	if k == 0 {
		return 0, false
	}
	return x ^ (3 << (k - 1)), true
}

// parentStep climbs one edge in the complete (infinite) binary tree, ignoring
// the actual tree width. It sets the level bit k and toggles bit k+1 according
// to whether x is a left or right child.
func parentStep(x uint32) uint32 {
	k := level(x)
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1))
}

// Parent returns the parent of x within a tree of nLeaves; ok is false if x is
// the root. Parents that fall outside the (possibly non-full) tree are walked
// up until they land in range.
// x must be a valid node index: 0 <= x < NodeWidth(nLeaves).
func Parent(x, nLeaves uint32) (uint32, bool) {
	if x == Root(nLeaves) {
		return 0, false
	}
	w := NodeWidth(nLeaves)
	p := parentStep(x)
	for p >= w {
		p = parentStep(p)
	}
	return p, true
}

// Sibling returns the sibling of x within a tree of nLeaves; ok is false if x
// is the root.
// x must be a valid node index: 0 <= x < NodeWidth(nLeaves).
func Sibling(x, nLeaves uint32) (uint32, bool) {
	p, ok := Parent(x, nLeaves)
	if !ok {
		return 0, false
	}
	l, _ := Left(p)
	r, _ := Right(p) // p is always internal, so both children exist
	if l == x {
		return r, true
	}
	return l, true
}
