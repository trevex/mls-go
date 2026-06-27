package tree

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

// CommitSecret derives the commit secret from the topmost path secret of an
// UpdatePath: commit_secret = DeriveSecret(path_secret[n], "path") (RFC 9420
// §7.4 — the path secret one step past the root).
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

// PrivateKeyAt returns the HPKE private key held for the given array node index.
func (p *TreeKEMPrivate) PrivateKeyAt(node uint32) ([]byte, bool) {
	k, ok := p.privs[node]
	return k, ok
}

// installPath blanks the sender's full direct path, installs the new public keys
// for its filtered direct path (with empty unmerged_leaves), and assigns parent
// hashes top-down (RFC 9420 §7.5 step 1-2 + §7.9.1). nodePubs[k] is the new
// public key for filtered-direct-path node fdp[k]. It returns fdp.
func (t *RatchetTree) installPath(senderLeaf uint32, nodePubs [][]byte) ([]uint32, error) {
	leaves := t.leafCount()
	senderNode := 2 * senderLeaf
	fdp := t.filteredDirectPath(senderLeaf)
	if len(fdp) != len(nodePubs) {
		return nil, fmt.Errorf("tree: %d public keys for filtered direct path of length %d", len(nodePubs), len(fdp))
	}
	// Blank the full direct path.
	root := Root(leaves)
	for x := senderNode; x != root; {
		p, _ := Parent(x, leaves)
		t.nodes[p] = nil
		x = p
	}
	// Install new public keys.
	for k, p := range fdp {
		t.nodes[p] = &Node{Parent: &ParentNode{EncryptionKey: nodePubs[k]}}
	}
	// Assign parent hashes top-down (root first).
	for k := len(fdp) - 1; k >= 0; k-- {
		p := fdp[k]
		if k == len(fdp)-1 {
			t.nodes[p].Parent.ParentHash = nil // root: empty parent hash
			continue
		}
		parent := fdp[k+1]
		pc := t.pathChild(parent, p)
		s, _ := Sibling(pc, leaves)
		ph, err := t.parentHashOf(parent, s)
		if err != nil {
			return nil, err
		}
		t.nodes[p].Parent.ParentHash = ph
	}
	return fdp, nil
}

// leafParentHash returns the parent hash the sender's leaf should carry, i.e.
// the parent hash of the lowest filtered-direct-path node with the leaf's copath
// sibling (RFC 9420 §7.9.1). Returns nil when the filtered direct path is empty.
func (t *RatchetTree) leafParentHash(senderLeaf uint32, fdp []uint32) ([]byte, error) {
	if len(fdp) == 0 {
		return nil, nil
	}
	leaves := t.leafCount()
	senderNode := 2 * senderLeaf
	parent := fdp[0]
	pc := t.pathChild(parent, senderNode)
	s, _ := Sibling(pc, leaves)
	return t.parentHashOf(parent, s)
}

// Merge applies a received UpdatePath to the tree in place (RFC 9420 §7.5):
// blank the sender's direct path, install the UpdatePath public keys and parent
// hashes, and install the sender's (already-signed) leaf node verbatim. Parent-
// hash validity is verified separately by the caller via VerifyParentHashes.
func (t *RatchetTree) Merge(senderLeaf uint32, up *UpdatePath) error {
	pubs := make([][]byte, len(up.Nodes))
	for k, n := range up.Nodes {
		pubs[k] = n.EncryptionKey
	}
	if _, err := t.installPath(senderLeaf, pubs); err != nil {
		return err
	}
	leaf := up.LeafNode
	t.nodes[2*senderLeaf] = &Node{Leaf: &leaf}
	return nil
}

// ProcessUpdatePath decrypts the path secret addressed to priv, derives the
// remaining path secrets up to the root (verifying each derived public key
// against the UpdatePath), and returns the decrypted path secret (i.e. the
// vector's path_secrets[priv.LeafIndex]) and the commit secret (RFC 9420
// §7.5/§7.6). It does not mutate the tree; groupContext is the serialized
// provisional GroupContext for the new epoch.
func (t *RatchetTree) ProcessUpdatePath(senderLeaf uint32, up *UpdatePath, priv *TreeKEMPrivate, groupContext []byte) (pathSecret, commitSecret []byte, err error) {
	senderNode := 2 * senderLeaf
	fdp := t.filteredDirectPath(senderLeaf)
	if len(fdp) != len(up.Nodes) {
		return nil, nil, fmt.Errorf("tree: UpdatePath has %d nodes, filtered direct path has %d", len(up.Nodes), len(fdp))
	}
	// Find the lowest filtered-direct-path node whose copath child resolution
	// contains a node we hold a private key for, and decrypt at that index.
	foundK := -1
	var decrypted []byte
	for k, p := range fdp {
		cc := t.copathChild(p, senderNode)
		res := t.Resolution(cc)
		for idx, d := range res {
			sk, ok := priv.privateKey(d)
			if !ok {
				continue
			}
			if idx >= len(up.Nodes[k].EncryptedPathSecret) {
				return nil, nil, fmt.Errorf("tree: resolution index %d out of range for node %d", idx, p)
			}
			ct := up.Nodes[k].EncryptedPathSecret[idx]
			ps, derr := t.suite.DecryptWithLabel(sk, "UpdatePathNode", groupContext, ct.KemOutput, ct.Ciphertext)
			if derr != nil {
				return nil, nil, derr
			}
			decrypted, foundK = ps, k
			break
		}
		if foundK >= 0 {
			break
		}
	}
	if foundK < 0 {
		return nil, nil, fmt.Errorf("tree: leaf %d holds no key in any copath resolution", priv.LeafIndex)
	}
	// Derive up to the root, verifying public keys.
	cur := decrypted
	for k := foundK; k < len(fdp); k++ {
		_, pub, derr := nodeKeyPair(t.suite, cur)
		if derr != nil {
			return nil, nil, derr
		}
		if !bytes.Equal(pub, up.Nodes[k].EncryptionKey) {
			return nil, nil, fmt.Errorf("tree: derived public key mismatch at node %d", fdp[k])
		}
		if k < len(fdp)-1 {
			cur, derr = t.suite.DeriveSecret(cur, "path")
			if derr != nil {
				return nil, nil, derr
			}
		}
	}
	commitSecret, err = CommitSecret(t.suite, cur)
	if err != nil {
		return nil, nil, err
	}
	return decrypted, commitSecret, nil
}

// GenerateUpdatePath creates a fresh UpdatePath for senderLeaf and applies it to
// t in place (RFC 9420 §7.5 committer side). It samples new key material from
// leafSecret, blanks+rekeys the sender's direct path, builds and signs a new
// commit leaf, and encrypts each path secret to the resolution of the
// corresponding copath child. mkGroupContext builds the serialized provisional
// GroupContext from the post-update root tree hash (the HPKE context); groupID
// is the group identifier used in the leaf's signature context. Returns the
// UpdatePath and the commit secret.
func (t *RatchetTree) GenerateUpdatePath(senderLeaf uint32, leafSecret []byte, signer crypto.Signer, groupID []byte, mkGroupContext func(treeHash []byte) ([]byte, error)) (*UpdatePath, []byte, error) {
	suite := t.suite
	senderNode := 2 * senderLeaf
	origNode := t.nodes[senderNode]
	if origNode == nil || origNode.Leaf == nil {
		return nil, nil, fmt.Errorf("tree: sender leaf %d is blank", senderLeaf)
	}
	orig := *origNode.Leaf
	fdp := t.filteredDirectPath(senderLeaf)

	// Path secrets (Figure 14 model): path_secret[0] = DeriveSecret(leafSecret,"path").
	pathSecrets := make([][]byte, len(fdp))
	for k := range fdp {
		var src []byte
		if k == 0 {
			src = leafSecret
		} else {
			src = pathSecrets[k-1]
		}
		ps, err := suite.DeriveSecret(src, "path")
		if err != nil {
			return nil, nil, err
		}
		pathSecrets[k] = ps
	}
	last := leafSecret
	if len(fdp) > 0 {
		last = pathSecrets[len(fdp)-1]
	}
	commitSecret, err := CommitSecret(suite, last)
	if err != nil {
		return nil, nil, err
	}

	// Leaf key pair and node key pairs.
	leafNodeSecret, err := suite.DeriveSecret(leafSecret, "node")
	if err != nil {
		return nil, nil, err
	}
	_, leafPub, err := suite.DeriveKeyPair(leafNodeSecret)
	if err != nil {
		return nil, nil, err
	}
	nodePubs := make([][]byte, len(fdp))
	for k := range fdp {
		_, pub, err := nodeKeyPair(suite, pathSecrets[k])
		if err != nil {
			return nil, nil, err
		}
		nodePubs[k] = pub
	}

	// Snapshot each copath child's resolution public keys BEFORE mutating the tree.
	resPubs := make([][][]byte, len(fdp))
	for k, p := range fdp {
		res := t.Resolution(t.copathChild(p, senderNode))
		pubs := make([][]byte, len(res))
		for i, d := range res {
			pk, err := t.nodePublicKey(d)
			if err != nil {
				return nil, nil, err
			}
			pubs[i] = pk
		}
		resPubs[k] = pubs
	}

	// Blank + install public keys + parent hashes.
	if _, err := t.installPath(senderLeaf, nodePubs); err != nil {
		return nil, nil, err
	}

	// Build and sign the new commit leaf.
	ph, err := t.leafParentHash(senderLeaf, fdp)
	if err != nil {
		return nil, nil, err
	}
	leaf := LeafNode{
		EncryptionKey:  leafPub,
		SignatureKey:   orig.SignatureKey,
		Credential:     orig.Credential,
		Capabilities:   orig.Capabilities,
		LeafNodeSource: LeafNodeSourceCommit,
		ParentHash:     ph,
		Extensions:     orig.Extensions,
	}
	tbs, err := leaf.tbs(groupID, senderLeaf)
	if err != nil {
		return nil, nil, err
	}
	sig, err := suite.SignWithLabel(signer, "LeafNodeTBS", tbs)
	if err != nil {
		return nil, nil, err
	}
	leaf.Signature = sig
	leafCopy := leaf
	t.nodes[senderNode] = &Node{Leaf: &leafCopy}

	// Provisional group context from the post-update root tree hash.
	treeHash, err := t.RootTreeHash()
	if err != nil {
		return nil, nil, err
	}
	groupContext, err := mkGroupContext(treeHash)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt path secrets to the copath resolutions.
	nodes := make([]UpdatePathNode, len(fdp))
	for k := range fdp {
		cts := make([]HPKECiphertext, len(resPubs[k]))
		for i, pub := range resPubs[k] {
			kem, ct, err := suite.EncryptWithLabel(pub, "UpdatePathNode", groupContext, pathSecrets[k])
			if err != nil {
				return nil, nil, err
			}
			cts[i] = HPKECiphertext{KemOutput: kem, Ciphertext: ct}
		}
		nodes[k] = UpdatePathNode{EncryptionKey: nodePubs[k], EncryptedPathSecret: cts}
	}
	return &UpdatePath{LeafNode: leaf, Nodes: nodes}, commitSecret, nil
}
