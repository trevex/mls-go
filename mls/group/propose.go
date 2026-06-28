package group

import (
	"crypto/rand"

	"github.com/trevex/mls-go/mls/framing"
	"github.com/trevex/mls-go/mls/tree"
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
// for g's own leaf (RFC 9420 §12.1.2). The new leaf private key is stored
// atomically in g.pendingUpdates keyed by the new leaf public key. g.priv is
// NOT mutated here — ProcessCommit will swap the pending key in only after the
// confirmation_tag verifies, so a superseded update leaves the old key intact.
func (g *Group) ProposeUpdate() (Proposal, error) {
	leafPriv, leafPub, err := g.suite.GenerateHPKEKeyPair()
	if err != nil {
		return Proposal{}, err
	}
	cur, err := g.tree.LeafNodeAt(g.ownLeaf)
	if err != nil {
		return Proposal{}, err
	}
	ln := cur
	ln.EncryptionKey = leafPub
	ln.LeafNodeSource = tree.LeafNodeSourceUpdate
	ln.Lifetime = nil
	ln.ParentHash = nil
	if err := tree.SignLeafNode(g.suite, g.signer, &ln, g.groupContext.GroupID, g.ownLeaf); err != nil {
		return Proposal{}, err
	}
	// Store pending key by new leaf pubkey — atomic: ProcessCommit resolves this
	// and swaps it into g.priv only after confirmation_tag verifies.
	g.pendingUpdates[string(leafPub)] = leafPriv
	return Proposal{Type: ProposalTypeUpdate, Update: &Update{LeafNode: ln}}, nil
}

// FrameProposal frames a bare Proposal as a member PublicMessage or, when
// encryptHandshakes is true, a member PrivateMessage (RFC 9420 §6.2/§6.3),
// returning the MLSMessage bytes for by-reference delivery.
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
	if g.encryptHandshakes {
		var guard [4]byte
		if _, err := rand.Read(guard[:]); err != nil {
			return nil, err
		}
		pm, err := framing.ProtectPrivate(g.suite, g.signer, &gc, g.secretTree, g.epoch.SenderDataSecret, fc, g.handshakeGeneration, guard, 0, nil)
		if err != nil {
			return nil, err
		}
		g.handshakeGeneration++
		msg := framing.MLSMessage{
			Version:    tree.ProtocolVersionMLS10,
			WireFormat: framing.WireFormatPrivateMessage,
			Private:    &pm,
		}
		return msg.MarshalMLS()
	}
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
