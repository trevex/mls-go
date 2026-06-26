package tree

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

// CommitSecret derives the commit secret from the topmost path secret of an
// UpdatePath: commit_secret = DeriveSecret(path_secret[n], "path") (RFC 9420
// §12.4 — the path secret one step past the root).
func CommitSecret(suite cipher.Suite, lastPathSecret []byte) ([]byte, error) {
	return suite.DeriveSecret(lastPathSecret, "path")
}

// nodeKeyPair derives the HPKE key pair for a tree node from its path secret
// (RFC 9420 §7.4): node_secret = DeriveSecret(path_secret, "node"); then
// DeriveKeyPair(node_secret).
func nodeKeyPair(suite cipher.Suite, pathSecret []byte) (priv, pub []byte, err error) {
	nodeSecret, err := suite.DeriveSecret(pathSecret, "node")
	if err != nil {
		return nil, nil, err
	}
	return suite.DeriveKeyPair(nodeSecret)
}

// pathChild returns the child of parent node p whose subtree contains target.
func (t *RatchetTree) pathChild(p, target uint32) uint32 {
	l, _ := Left(p)
	if subtreeContains(l, target) {
		return l
	}
	r, _ := Right(p, t.leafCount())
	return r
}

// copathChild returns the child of parent node p that is NOT on the direct path
// of senderNode (the node whose resolution the path secret is encrypted to).
func (t *RatchetTree) copathChild(p, senderNode uint32) uint32 {
	pc := t.pathChild(p, senderNode)
	s, _ := Sibling(pc, t.leafCount())
	return s
}

// filteredDirectPath returns the sender leaf's filtered direct path as a list of
// parent node indices, bottom-up (RFC 9420 §4.1.2): direct-path ancestors whose
// copath child has a non-empty resolution.
func (t *RatchetTree) filteredDirectPath(leafIndex uint32) []uint32 {
	leaves := t.leafCount()
	x := 2 * leafIndex
	root := Root(leaves)
	var path []uint32
	for x != root {
		p, _ := Parent(x, leaves)
		s, _ := Sibling(x, leaves)
		if len(t.Resolution(s)) > 0 {
			path = append(path, p)
		}
		x = p
	}
	return path
}

// nodePublicKey returns the HPKE public key stored at node index d.
func (t *RatchetTree) nodePublicKey(d uint32) ([]byte, error) {
	n := t.nodes[d]
	if n == nil {
		return nil, fmt.Errorf("tree: node %d is blank", d)
	}
	if n.Leaf != nil {
		return n.Leaf.EncryptionKey, nil
	}
	return n.Parent.EncryptionKey, nil
}

// TreeKEMPrivate is a member's private TreeKEM state: the HPKE private keys it
// holds, keyed by array node index. The leaf's own key sits at node 2*LeafIndex;
// ancestor keys are derived from path secrets via AddPathSecret.
type TreeKEMPrivate struct {
	LeafIndex uint32
	privs     map[uint32][]byte
}

// NewTreeKEMPrivate creates a private state holding only the leaf's own HPKE
// private key (RFC 9420 §7.6 receiver state).
func NewTreeKEMPrivate(leafIndex uint32, leafPriv []byte) *TreeKEMPrivate {
	return &TreeKEMPrivate{
		LeafIndex: leafIndex,
		privs:     map[uint32][]byte{2 * leafIndex: leafPriv},
	}
}

// AddPathSecret derives and stores the HPKE private key for the given node index
// from a path secret (RFC 9420 §7.4).
func (p *TreeKEMPrivate) AddPathSecret(suite cipher.Suite, nodeIndex uint32, pathSecret []byte) error {
	priv, _, err := nodeKeyPair(suite, pathSecret)
	if err != nil {
		return err
	}
	p.privs[nodeIndex] = priv
	return nil
}

func (p *TreeKEMPrivate) privateKey(node uint32) ([]byte, bool) {
	k, ok := p.privs[node]
	return k, ok
}

// ensure bytes/crypto are referenced (used by Process/Generate added later).
var _ = bytes.Equal
var _ crypto.Signer
