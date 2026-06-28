package group

import (
	"crypto"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/tree"
)

// Group is a member's view of one MLS group at the current epoch (RFC 9420 §8/§11).
// signer may be nil for a pure passive receiver.
//
// Group is NOT safe for concurrent use; serialize all method calls on a Group
// (callers needing concurrency must add their own locking).
type Group struct {
	suite        cipher.Suite
	groupContext keyschedule.GroupContext
	tree         *tree.RatchetTree
	priv         *tree.TreeKEMPrivate
	epoch        keyschedule.EpochSecrets
	secretTree   *keyschedule.SecretTree
	interim      []byte // interim_transcript_hash[current epoch]
	initSecret   []byte // init_secret for the NEXT epoch's key schedule
	ownLeaf      uint32
	signer       crypto.Signer     // own signing key (for generating; nil for pure receiver)
	externalPSKs map[string][]byte // psk_id (string) -> psk secret for external PSKs
	// resumptionPSKHistory holds the resumption_psk for each epoch the group has
	// been in. Keyed by epoch number. Populated at join and after each commit so
	// that PSK proposals in future commits can be resolved (RFC 9420 §8.4).
	resumptionPSKHistory map[uint64][]byte
	// appGeneration is the per-epoch, per-sender monotonic counter for application
	// messages (RFC 9420 §9.1). It is reset to 0 on every epoch change.
	appGeneration uint32
	// handshakeGeneration is the per-epoch monotonic counter for the handshake
	// ratchet (separate from appGeneration). Reset to 0 on every epoch change.
	handshakeGeneration uint32
	// encryptHandshakes makes this member frame its OWN Commit/Proposal/Update as
	// a PrivateMessage (RFC 9420 encrypt_handshake). Receive is always wire-format
	// agnostic; this only affects outbound member handshakes. Default false.
	encryptHandshakes bool
	// pendingUpdates maps new-leaf-pubkey (string) → new-leaf-priv for Update
	// proposals authored by this member but not yet committed.  ProcessCommit
	// swaps the key into g.priv atomically, only after confirmation_tag verifies,
	// so a superseded update leaves the old key intact (RFC 9420 §12.1.2).
	// Cleared on every epoch change.
	pendingUpdates map[string][]byte
}

// Epoch returns the current epoch number.
func (g *Group) Epoch() uint64 { return g.groupContext.Epoch }

// EpochAuthenticator returns the epoch_authenticator for the current epoch
// (RFC 9420 §8.7).
func (g *Group) EpochAuthenticator() []byte { return g.epoch.EpochAuthenticator }

// GroupContext returns the current GroupContext (RFC 9420 §8.1).
func (g *Group) GroupContext() keyschedule.GroupContext { return g.groupContext }

// OwnLeaf returns the group member's own leaf index.
func (g *Group) OwnLeaf() uint32 { return g.ownLeaf }

// SetEncryptHandshakes selects whether this member frames its own outbound
// handshakes (Commit/Proposal/Update) as encrypted PrivateMessages. Call it at
// create/join time. It never affects the receive path (which dispatches on the
// inbound wire format) nor external commits (always PublicMessage).
func (g *Group) SetEncryptHandshakes(v bool) { g.encryptHandshakes = v }

// sigPubByLeaf resolves a leaf index to its signature public key from the
// ratchet tree (the verifier callback for UnprotectPrivate).
//
//nolint:unused // used by the receive path added in a later task
func (g *Group) sigPubByLeaf(leaf uint32) ([]byte, error) {
	ln, err := g.tree.LeafNodeAt(leaf)
	if err != nil {
		return nil, err
	}
	return ln.SignatureKey, nil
}

// Exporter derives an application secret (RFC 9420 §8.5) — feeds IronCore ESP SAs.
func (g *Group) Exporter(label string, context []byte, length int) ([]byte, error) {
	return keyschedule.MLSExporter(g.suite, g.epoch.ExporterSecret, label, context, length)
}

// ─── private helpers ─────────────────────────────────────────────────────────

// levelOf returns the level of node x: the number of trailing 1-bits (leaves=0).
func levelOf(x uint32) uint32 {
	if x&1 == 0 {
		return 0
	}
	k := uint32(0)
	for (x>>k)&1 == 1 {
		k++
	}
	return k
}

// commonAncestor returns the lowest common ancestor of x and y in a tree of
// nLeaves leaves.
func commonAncestor(x, y, nLeaves uint32) uint32 {
	for levelOf(x) < levelOf(y) {
		x, _ = tree.Parent(x, nLeaves)
	}
	for levelOf(y) < levelOf(x) {
		y, _ = tree.Parent(y, nLeaves)
	}
	for x != y {
		x, _ = tree.Parent(x, nLeaves)
		y, _ = tree.Parent(y, nLeaves)
	}
	return x
}

// installJoinerPriv installs pathSecret and its ratcheted ancestors into priv,
// starting at the common ancestor of 2*ownLeaf and 2*senderLeaf (RFC 9420 §12.4.3.1).
func installJoinerPriv(suite cipher.Suite, priv *tree.TreeKEMPrivate, pathSecret []byte, ownLeaf, senderLeaf, nLeaves uint32) error {
	node := commonAncestor(2*ownLeaf, 2*senderLeaf, nLeaves)
	root := tree.Root(nLeaves)
	sec := pathSecret
	for {
		if err := priv.AddPathSecret(suite, node, sec); err != nil {
			return err
		}
		if node == root {
			break
		}
		var err error
		sec, err = suite.DeriveSecret(sec, "path")
		if err != nil {
			return err
		}
		node, _ = tree.Parent(node, nLeaves)
	}
	return nil
}
