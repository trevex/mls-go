package group

import (
	"crypto/rand"
	"errors"

	"github.com/trevex/mls-go/mls/framing"
	"github.com/trevex/mls-go/mls/tree"
)

// ProtectApplication encrypts plaintext as an application PrivateMessage from
// g's own leaf, advancing g's per-epoch sender ratchet (RFC 9420 §6.3/§9).
//
// authenticatedData is included in the encrypted message's AAD and recovered
// by UnprotectApplication. paddingSize is 0 for tests.
//
// Note: SecretTree.KeyNonce re-derives from generation 0 on each call
// (O(generation)); forward-secrecy deletion of consumed ratchet keys is a
// production follow-up (same caveat as keyschedule/secrettree.go).
func (g *Group) ProtectApplication(plaintext, authenticatedData []byte) ([]byte, error) {
	fc := framing.FramedContent{
		GroupID:           g.groupContext.GroupID,
		Epoch:             g.groupContext.Epoch,
		Sender:            framing.Sender{Type: framing.SenderTypeMember, LeafIndex: g.ownLeaf},
		AuthenticatedData: authenticatedData,
		ContentType:       framing.ContentTypeApplication,
		Content:           plaintext,
	}
	var guard [4]byte
	if _, err := rand.Read(guard[:]); err != nil {
		return nil, err
	}
	gc := g.groupContext
	pm, err := framing.ProtectPrivate(g.suite, g.signer, &gc, g.secretTree, g.epoch.SenderDataSecret, fc, g.appGeneration, guard, 0, nil)
	if err != nil {
		return nil, err
	}
	g.appGeneration++
	msg := framing.MLSMessage{
		Version:    tree.ProtocolVersionMLS10,
		WireFormat: framing.WireFormatPrivateMessage,
		Private:    &pm,
	}
	return msg.MarshalMLS()
}

// UnprotectApplication decrypts an application PrivateMessage and returns the
// plaintext and authenticated_data (RFC 9420 §6.3). The generation is read
// from the encrypted sender_data, so no receiver ratchet state is needed.
func (g *Group) UnprotectApplication(msg []byte) (plaintext, authenticatedData []byte, err error) {
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(msg); err != nil {
		return nil, nil, err
	}
	if m.WireFormat != framing.WireFormatPrivateMessage || m.Private == nil {
		return nil, nil, errors.New("group: not a PrivateMessage")
	}
	if m.Private.ContentType != framing.ContentTypeApplication {
		return nil, nil, errors.New("group: not an application message")
	}
	gc := g.groupContext
	sigPub := func(leaf uint32) ([]byte, error) {
		ln, err := g.tree.LeafNodeAt(leaf)
		if err != nil {
			return nil, err
		}
		return ln.SignatureKey, nil
	}
	ac, err := framing.UnprotectPrivate(g.suite, sigPub, &gc, g.secretTree, g.epoch.SenderDataSecret, *m.Private)
	if err != nil {
		return nil, nil, err
	}
	return ac.Content.Content, ac.Content.AuthenticatedData, nil
}
