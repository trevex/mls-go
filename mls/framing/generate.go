package framing

import (
	"crypto"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/syntax"
)

// SignCommit signs FramedContentTBS for a PublicMessage commit and returns the
// ConfirmedTranscriptHashInput (wire_format ‖ FramedContent ‖ signature<V>)
// plus the signature (RFC 9420 §6.1 / §8.2).
//
// The confirmedInput is byte-identical to the input that
// keyschedule.SplitAuthenticatedContent produces for the same commit: both are
// the AuthenticatedContent bytes with the trailing confirmation_tag<V> field
// removed.
func SignCommit(suite cipher.Suite, signer crypto.Signer, gc *keyschedule.GroupContext, fc FramedContent) (confirmedInput, signature []byte, err error) {
	ac := AuthenticatedContent{WireFormat: WireFormatPublicMessage, Content: fc}
	if err := ac.sign(suite, signer, gc); err != nil {
		return nil, nil, err
	}
	b := syntax.NewBuilder()
	b.WriteUint16(uint16(WireFormatPublicMessage))
	if err := fc.marshal(b); err != nil {
		return nil, nil, err
	}
	if err := b.WriteOpaqueV(ac.Auth.Signature); err != nil {
		return nil, nil, err
	}
	return b.Bytes(), ac.Auth.Signature, nil
}

// AssembleCommitPublic builds the PublicMessage from a precomputed signature +
// confirmation_tag, adding the membership_tag (RFC 9420 §6.2). The
// membership_tag uses the current epoch's gc + membershipKey.
func AssembleCommitPublic(suite cipher.Suite, gc *keyschedule.GroupContext, membershipKey []byte, fc FramedContent, signature, confTag []byte) (PublicMessage, error) {
	auth := FramedContentAuthData{Signature: signature, ConfirmationTag: confTag}
	m := PublicMessage{Content: fc, Auth: auth}
	tbm, err := authenticatedContentTBM(WireFormatPublicMessage, fc, auth, gc)
	if err != nil {
		return PublicMessage{}, err
	}
	m.MembershipTag = suite.MAC(membershipKey, tbm)
	return m, nil
}
