package group

import "github.com/trevex/mls-mlkem-go/mls/tree"

// ActiveLeaves returns the ascending list of non-blank leaf indices in the
// current ratchet tree. The first element (if any) is the lowest active leaf —
// the designated committer (design spec §10.3). Read-only; the slice is freshly
// allocated and safe for the caller to mutate.
func (g *Group) ActiveLeaves() []uint32 {
	var out []uint32
	for i := uint32(0); i < g.tree.LeafCount(); i++ {
		if _, err := g.tree.LeafNodeAt(i); err == nil { // err ⇒ blank leaf, skip
			out = append(out, i)
		}
	}
	return out
}

// LeafCredential returns the Credential and signature public key of the member
// at the given non-blank leaf, for mapping verified identity → leaf in the
// membership controller's reconcile diff (design spec §10.3). It returns an
// error for a blank or out-of-range leaf. Read-only; exposes only public leaf
// material (no group secrets).
func (g *Group) LeafCredential(leaf uint32) (tree.Credential, []byte, error) {
	ln, err := g.tree.LeafNodeAt(leaf)
	if err != nil {
		return tree.Credential{}, nil, err
	}
	return ln.Credential, ln.SignatureKey, nil
}
