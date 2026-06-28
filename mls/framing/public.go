package framing

import (
	"crypto"
	"crypto/hmac"
	"errors"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/syntax"
)

// PublicMessage is an integrity-protected (signed, MAC'd) framed message
// (RFC 9420 §6.2).
type PublicMessage struct {
	Content       FramedContent
	Auth          FramedContentAuthData
	MembershipTag []byte // present iff Content.Sender.Type == member
}

func (m PublicMessage) marshal(b *syntax.Builder) error {
	if err := m.Content.marshal(b); err != nil {
		return err
	}
	if err := m.Auth.marshal(b, m.Content.ContentType); err != nil {
		return err
	}
	if m.Content.Sender.Type == SenderTypeMember {
		if err := b.WriteOpaqueV(m.MembershipTag); err != nil {
			return err
		}
	}
	return nil
}

func decodePublicMessage(c *syntax.Cursor) (PublicMessage, error) {
	var m PublicMessage
	var err error
	if m.Content, err = decodeFramedContent(c); err != nil {
		return m, err
	}
	if m.Auth, err = decodeFramedContentAuthData(c, m.Content.ContentType); err != nil {
		return m, err
	}
	if m.Content.Sender.Type == SenderTypeMember {
		if m.MembershipTag, err = c.ReadOpaqueV(); err != nil {
			return m, err
		}
	}
	return m, nil
}

// authenticatedContentTBM builds the membership-tag input
// (RFC 9420 §6.2): FramedContentTBS || FramedContentAuthData.
func authenticatedContentTBM(wf WireFormat, fc FramedContent, auth FramedContentAuthData, gc *keyschedule.GroupContext) ([]byte, error) {
	tbs, err := framedContentTBS(wf, fc, gc)
	if err != nil {
		return nil, err
	}
	b := syntax.NewBuilder()
	b.WriteRaw(tbs)
	if err := auth.marshal(b, fc.ContentType); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ProtectPublic frames fc as a signed PublicMessage (RFC 9420 §6.2). gc is
// required for member / new_member_commit senders; membershipKey is required
// for member senders (the membership_tag is then emitted). confirmationTag is
// used only for commit content.
func ProtectPublic(suite cipher.Suite, signer crypto.Signer, gc *keyschedule.GroupContext, membershipKey []byte, fc FramedContent, confirmationTag []byte) (PublicMessage, error) {
	ac := AuthenticatedContent{WireFormat: WireFormatPublicMessage, Content: fc}
	if fc.ContentType == ContentTypeCommit {
		ac.Auth.ConfirmationTag = confirmationTag
	}
	if err := ac.sign(suite, signer, gc); err != nil {
		return PublicMessage{}, err
	}
	m := PublicMessage{Content: ac.Content, Auth: ac.Auth}
	if fc.Sender.Type == SenderTypeMember {
		tbm, err := authenticatedContentTBM(WireFormatPublicMessage, fc, ac.Auth, gc)
		if err != nil {
			return PublicMessage{}, err
		}
		m.MembershipTag = suite.MAC(membershipKey, tbm)
	}
	return m, nil
}

// UnprotectPublic verifies a PublicMessage's membership tag (member senders)
// and signature, returning the authenticated content (RFC 9420 §6.2).
func UnprotectPublic(suite cipher.Suite, signaturePub []byte, gc *keyschedule.GroupContext, membershipKey []byte, m PublicMessage) (AuthenticatedContent, error) {
	if m.Content.Sender.Type == SenderTypeMember {
		tbm, err := authenticatedContentTBM(WireFormatPublicMessage, m.Content, m.Auth, gc)
		if err != nil {
			return AuthenticatedContent{}, err
		}
		if !hmac.Equal(suite.MAC(membershipKey, tbm), m.MembershipTag) {
			return AuthenticatedContent{}, errors.New("framing: membership_tag verification failed")
		}
	}
	ac := AuthenticatedContent{WireFormat: WireFormatPublicMessage, Content: m.Content, Auth: m.Auth}
	if !ac.verify(suite, signaturePub, gc) {
		return AuthenticatedContent{}, errors.New("framing: signature verification failed")
	}
	return ac, nil
}
