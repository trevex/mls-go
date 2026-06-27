package group

import (
	"github.com/trevex/mls-mlkem-go/mls/framing"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// ProposeAdd builds a bare Add proposal from a received KeyPackage
// (RFC 9420 §12.1.1).
func ProposeAdd(kp KeyPackage) Proposal {
	return Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: kp}}
}

// ProposeRemove builds a bare Remove proposal targeting the given leaf index
// (RFC 9420 §12.1.3).
func ProposeRemove(leaf uint32) Proposal {
	return Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: leaf}}
}

// ProposeGroupContextExtensions builds a bare GroupContextExtensions proposal
// (RFC 9420 §12.1.7).
func ProposeGroupContextExtensions(ext []tree.Extension) Proposal {
	return Proposal{Type: ProposalTypeGroupContextExtensions, GroupContextExtensions: &GroupContextExtensions{Extensions: ext}}
}

// ProposeUpdate generates a fresh leaf HPKE key and an update-source LeafNode
// for g's own leaf, returning the proposal and the new leafPriv that the
// proposer must install when this proposal is committed (RFC 9420 §12.1.2).
//
// NOTE: The proposer's new leaf_priv is not automatically installed when a
// separate committer commits this Update by reference. Production callers must
// track the returned leafPriv and call a future InstallUpdateKey helper once
// ProcessCommit confirms the proposal (tracked as a TODO).
func (g *Group) ProposeUpdate() (Proposal, []byte, error) {
	leafPriv, leafPub, err := g.suite.GenerateHPKEKeyPair()
	if err != nil {
		return Proposal{}, nil, err
	}
	cur, err := g.tree.LeafNodeAt(g.ownLeaf)
	if err != nil {
		return Proposal{}, nil, err
	}
	ln := cur
	ln.EncryptionKey = leafPub
	ln.LeafNodeSource = tree.LeafNodeSourceUpdate
	ln.Lifetime = nil
	ln.ParentHash = nil
	if err := tree.SignLeafNode(g.suite, g.signer, &ln, g.groupContext.GroupID, g.ownLeaf); err != nil {
		return Proposal{}, nil, err
	}
	return Proposal{Type: ProposalTypeUpdate, Update: &Update{LeafNode: ln}}, leafPriv, nil
}

// InstallPendingUpdateKey installs a new leaf private key that was returned by
// a previous ProposeUpdate call, so that ProcessCommit can correctly decrypt
// the UpdatePath path secrets (which are encrypted to the NEW leaf public key
// after the Update proposal is applied to the tree). Must be called before
// ProcessCommit when the caller's own pending Update is included in the commit.
//
// The ancestor keys in g.priv are discarded here; ProcessCommit will reinstall
// them from the decrypted path secret via installJoinerPriv.
func (g *Group) InstallPendingUpdateKey(newLeafPriv []byte) {
	g.priv = tree.NewTreeKEMPrivate(g.ownLeaf, newLeafPriv)
}

// FrameProposal frames a bare Proposal as a member PublicMessage
// (RFC 9420 §6.2), returning the MLSMessage bytes for by-reference delivery.
func (g *Group) FrameProposal(p Proposal) ([]byte, error) {
	body, err := p.MarshalMLS()
	if err != nil {
		return nil, err
	}
	fc := framing.FramedContent{
		GroupID:     g.groupContext.GroupID,
		Epoch:       g.groupContext.Epoch,
		Sender:      framing.Sender{Type: framing.SenderTypeMember, LeafIndex: g.ownLeaf},
		ContentType: framing.ContentTypeProposal,
		Content:     body,
	}
	gc := g.groupContext
	pm, err := framing.ProtectPublic(g.suite, g.signer, &gc, g.epoch.MembershipKey, fc, nil)
	if err != nil {
		return nil, err
	}
	msg := framing.MLSMessage{
		Version:    tree.ProtocolVersionMLS10,
		WireFormat: framing.WireFormatPublicMessage,
		Public:     &pm,
	}
	return msg.MarshalMLS()
}
