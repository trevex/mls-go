package tree

import (
	"crypto"

	"github.com/trevex/mls-go/mls/cipher"
)

// NewRatchetTree builds a single-leaf tree holding leaf at index 0 (group
// creation, RFC 9420 §11). The returned tree has Width()==1.
func NewRatchetTree(suite cipher.Suite, leaf LeafNode) *RatchetTree {
	l := leaf
	return &RatchetTree{suite: suite, nodes: []*Node{{Leaf: &l}}}
}

// SignLeafNode signs ln in place under "LeafNodeTBS" (RFC 9420 §7.2/§7.3).
// For key_package source, groupID/leafIndex are ignored; for update/commit
// sources they are appended to the TBS.
func SignLeafNode(suite cipher.Suite, signer crypto.Signer, ln *LeafNode, groupID []byte, leafIndex uint32) error {
	tbs, err := ln.tbs(groupID, leafIndex)
	if err != nil {
		return err
	}
	sig, err := suite.SignWithLabel(signer, "LeafNodeTBS", tbs)
	if err != nil {
		return err
	}
	ln.Signature = sig
	return nil
}
