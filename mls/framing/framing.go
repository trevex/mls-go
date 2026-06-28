// Package framing implements RFC 9420 §6 message framing and protection:
// the framing value types, content authentication (§6.1), the PublicMessage
// membership tag (§6.2), and PrivateMessage AEAD protection (§6.3).
package framing

import (
	"crypto"
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/syntax"
	"github.com/trevex/mls-go/mls/tree"
)

// WireFormat selects the body of an MLSMessage (RFC 9420 §6).
type WireFormat uint16

const (
	WireFormatReserved       WireFormat = 0x0000
	WireFormatPublicMessage  WireFormat = 0x0001
	WireFormatPrivateMessage WireFormat = 0x0002
	WireFormatWelcome        WireFormat = 0x0003
	WireFormatGroupInfo      WireFormat = 0x0004
	WireFormatKeyPackage     WireFormat = 0x0005
)

// ContentType tags the inner content of a FramedContent (RFC 9420 §6).
type ContentType uint8

const (
	ContentTypeReserved    ContentType = 0
	ContentTypeApplication ContentType = 1
	ContentTypeProposal    ContentType = 2
	ContentTypeCommit      ContentType = 3
)

// SenderType identifies who produced a FramedContent (RFC 9420 §6).
type SenderType uint8

const (
	SenderTypeReserved          SenderType = 0
	SenderTypeMember            SenderType = 1
	SenderTypeExternal          SenderType = 2
	SenderTypeNewMemberProposal SenderType = 3
	SenderTypeNewMemberCommit   SenderType = 4
)

// proposal type ids (RFC 9420 §12.1) used only by the content skimmer.
const (
	proposalTypeAdd                    = 1
	proposalTypeUpdate                 = 2
	proposalTypeRemove                 = 3
	proposalTypePreSharedKey           = 4
	proposalTypeReInit                 = 5
	proposalTypeExternalInit           = 6
	proposalTypeGroupContextExtensions = 7
)

// Sender identifies the producer of a FramedContent (RFC 9420 §6).
type Sender struct {
	Type      SenderType
	LeafIndex uint32 // member
	Index     uint32 // external sender_index
}

func (s Sender) marshal(b *syntax.Builder) error {
	b.WriteUint8(uint8(s.Type))
	switch s.Type {
	case SenderTypeMember:
		b.WriteUint32(s.LeafIndex)
	case SenderTypeExternal:
		b.WriteUint32(s.Index)
	case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
		// no additional fields
	default:
		return fmt.Errorf("framing: invalid sender type %d", s.Type)
	}
	return nil
}

func decodeSender(c *syntax.Cursor) (Sender, error) {
	var s Sender
	t, err := c.ReadUint8()
	if err != nil {
		return s, err
	}
	s.Type = SenderType(t)
	switch s.Type {
	case SenderTypeMember:
		if s.LeafIndex, err = c.ReadUint32(); err != nil {
			return s, err
		}
	case SenderTypeExternal:
		if s.Index, err = c.ReadUint32(); err != nil {
			return s, err
		}
	case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
		// no additional fields
	default:
		return s, fmt.Errorf("framing: invalid sender type %d", s.Type)
	}
	return s, nil
}

// FramedContent is the signed payload of a framed message (RFC 9420 §6).
// Content holds the raw inner serialization: the unwrapped application_data
// bytes for application content, or the verbatim Proposal/Commit bytes for
// proposal/commit content (the wire form prefixes application_data with a
// length but inlines Proposal/Commit, see RFC 9420 §6).
type FramedContent struct {
	GroupID           []byte
	Epoch             uint64
	Sender            Sender
	AuthenticatedData []byte
	ContentType       ContentType
	Content           []byte
}

func (fc FramedContent) marshal(b *syntax.Builder) error {
	if err := b.WriteOpaqueV(fc.GroupID); err != nil {
		return err
	}
	b.WriteUint64(fc.Epoch)
	if err := fc.Sender.marshal(b); err != nil {
		return err
	}
	if err := b.WriteOpaqueV(fc.AuthenticatedData); err != nil {
		return err
	}
	b.WriteUint8(uint8(fc.ContentType))
	return marshalContent(b, fc.ContentType, fc.Content)
}

func decodeFramedContent(c *syntax.Cursor) (FramedContent, error) {
	var fc FramedContent
	var err error
	if fc.GroupID, err = c.ReadOpaqueV(); err != nil {
		return fc, err
	}
	if fc.Epoch, err = c.ReadUint64(); err != nil {
		return fc, err
	}
	if fc.Sender, err = decodeSender(c); err != nil {
		return fc, err
	}
	if fc.AuthenticatedData, err = c.ReadOpaqueV(); err != nil {
		return fc, err
	}
	ct, err := c.ReadUint8()
	if err != nil {
		return fc, err
	}
	fc.ContentType = ContentType(ct)
	if fc.Content, err = decodeContent(c, fc.ContentType); err != nil {
		return fc, err
	}
	return fc, nil
}

// marshalContent writes the inner content: application_data is length-prefixed
// (opaque<V>); Proposal/Commit are written verbatim/inline (RFC 9420 §6).
func marshalContent(b *syntax.Builder, ct ContentType, content []byte) error {
	switch ct {
	case ContentTypeApplication:
		return b.WriteOpaqueV(content)
	case ContentTypeProposal, ContentTypeCommit:
		b.WriteRaw(content)
		return nil
	default:
		return fmt.Errorf("framing: invalid content type %d", ct)
	}
}

// decodeContent reads the inner content, returning the raw inner serialization.
// For proposal/commit (no length prefix) it skims the structure to find the
// boundary, capturing exactly the consumed bytes via Cursor.Rest.
func decodeContent(c *syntax.Cursor, ct ContentType) ([]byte, error) {
	switch ct {
	case ContentTypeApplication:
		return c.ReadOpaqueV()
	case ContentTypeProposal:
		return skim(c, skimProposal)
	case ContentTypeCommit:
		return skim(c, skimCommit)
	default:
		return nil, fmt.Errorf("framing: invalid content type %d", ct)
	}
}

// skim runs f to advance c over an inline structure and returns the consumed
// bytes.
func skim(c *syntax.Cursor, f func(*syntax.Cursor) error) ([]byte, error) {
	rest := c.Rest()
	before := len(rest)
	if err := f(c); err != nil {
		return nil, err
	}
	return rest[:before-c.Remaining()], nil
}

// skimCommit advances over Commit = { ProposalOrRef proposals<V>;
// optional<UpdatePath> path; } (RFC 9420 §12.4).
func skimCommit(c *syntax.Cursor) error {
	if _, err := c.ReadOpaqueV(); err != nil { // proposals<V>
		return err
	}
	present, err := c.ReadUint8()
	if err != nil {
		return err
	}
	switch present {
	case 0:
		return nil
	case 1:
		_, err := tree.DecodeUpdatePath(c)
		return err
	default:
		return fmt.Errorf("framing: invalid optional<UpdatePath> presence %d", present)
	}
}

// skimProposal advances over Proposal = { ProposalType msg_type; select body }
// (RFC 9420 §6/§12.1), skimming each proposal-type body so the cursor lands on
// the next field. Add embeds a KeyPackage (skimKeyPackage), Update a LeafNode.
func skimProposal(c *syntax.Cursor) error {
	pt, err := c.ReadUint16()
	if err != nil {
		return err
	}
	switch int(pt) {
	case proposalTypeAdd:
		return skimKeyPackage(c)
	case proposalTypeUpdate:
		_, err := tree.DecodeLeafNode(c)
		return err
	case proposalTypeRemove:
		_, err := c.ReadUint32()
		return err
	case proposalTypePreSharedKey:
		return skimPreSharedKeyID(c)
	case proposalTypeReInit:
		if _, err := c.ReadOpaqueV(); err != nil { // group_id<V>
			return err
		}
		if _, err := c.ReadUint16(); err != nil { // version
			return err
		}
		if _, err := c.ReadUint16(); err != nil { // cipher_suite
			return err
		}
		_, err := c.ReadOpaqueV() // extensions<V>
		return err
	case proposalTypeExternalInit:
		_, err := c.ReadOpaqueV() // kem_output<V>
		return err
	case proposalTypeGroupContextExtensions:
		_, err := c.ReadOpaqueV() // extensions<V>
		return err
	default:
		return fmt.Errorf("framing: unknown proposal type %d", pt)
	}
}

// skimKeyPackage advances over a KeyPackage (RFC 9420 §10), delimiting an
// Add proposal's inline KeyPackage without importing the group package.
func skimKeyPackage(c *syntax.Cursor) error {
	if _, err := c.ReadUint16(); err != nil { // version
		return err
	}
	if _, err := c.ReadUint16(); err != nil { // cipher_suite
		return err
	}
	if _, err := c.ReadOpaqueV(); err != nil { // init_key<V>
		return err
	}
	if _, err := tree.DecodeLeafNode(c); err != nil { // leaf_node (inline)
		return err
	}
	if _, err := syntax.ReadVectorV(c, tree.DecodeExtension); err != nil { // extensions<V>
		return err
	}
	_, err := c.ReadOpaqueV() // signature<V>
	return err
}

// skimPreSharedKeyID advances over PreSharedKeyID (RFC 9420 §8.4).
func skimPreSharedKeyID(c *syntax.Cursor) error {
	t, err := c.ReadUint8()
	if err != nil {
		return err
	}
	switch t {
	case 1: // external
		if _, err := c.ReadOpaqueV(); err != nil { // psk_id<V>
			return err
		}
	case 2: // resumption
		if _, err := c.ReadUint8(); err != nil { // usage
			return err
		}
		if _, err := c.ReadOpaqueV(); err != nil { // psk_group_id<V>
			return err
		}
		if _, err := c.ReadUint64(); err != nil { // psk_epoch
			return err
		}
	default:
		return fmt.Errorf("framing: unknown PSKType %d", t)
	}
	_, err = c.ReadOpaqueV() // psk_nonce<V>
	return err
}

// FramedContentAuthData carries the content signature and, for commits, the
// confirmation tag (RFC 9420 §6.1).
type FramedContentAuthData struct {
	Signature       []byte
	ConfirmationTag []byte // present iff content_type == commit
}

func (a FramedContentAuthData) marshal(b *syntax.Builder, ct ContentType) error {
	if err := b.WriteOpaqueV(a.Signature); err != nil {
		return err
	}
	if ct == ContentTypeCommit {
		if err := b.WriteOpaqueV(a.ConfirmationTag); err != nil {
			return err
		}
	}
	return nil
}

func decodeFramedContentAuthData(c *syntax.Cursor, ct ContentType) (FramedContentAuthData, error) {
	var a FramedContentAuthData
	var err error
	if a.Signature, err = c.ReadOpaqueV(); err != nil {
		return a, err
	}
	if ct == ContentTypeCommit {
		if a.ConfirmationTag, err = c.ReadOpaqueV(); err != nil {
			return a, err
		}
	}
	return a, nil
}

// AuthenticatedContent is a FramedContent plus its signature/confirmation tag,
// bound to the wire format that framed it (RFC 9420 §6.1).
type AuthenticatedContent struct {
	WireFormat WireFormat
	Content    FramedContent
	Auth       FramedContentAuthData
}

// MarshalMLS serializes the AuthenticatedContent as wire_format || FramedContent
// || FramedContentAuthData (RFC 9420 §6 — the form keyschedule.SplitAuthenticatedContent
// consumes to derive the confirmed transcript hash).
func (ac AuthenticatedContent) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	b.WriteUint16(uint16(ac.WireFormat))
	if err := ac.Content.marshal(b); err != nil {
		return nil, err
	}
	if err := ac.Auth.marshal(b, ac.Content.ContentType); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// framedContentTBS builds the to-be-signed bytes (RFC 9420 §6.1). gc is
// required for member / new_member_commit senders and ignored otherwise.
func framedContentTBS(wf WireFormat, fc FramedContent, gc *keyschedule.GroupContext) ([]byte, error) {
	b := syntax.NewBuilder()
	b.WriteUint16(uint16(tree.ProtocolVersionMLS10))
	b.WriteUint16(uint16(wf))
	if err := fc.marshal(b); err != nil {
		return nil, err
	}
	switch fc.Sender.Type {
	case SenderTypeMember, SenderTypeNewMemberCommit:
		if gc == nil {
			return nil, fmt.Errorf("framing: %v sender requires a GroupContext for the signature", fc.Sender.Type)
		}
		gcb, err := gc.MarshalMLS()
		if err != nil {
			return nil, err
		}
		b.WriteRaw(gcb)
	}
	return b.Bytes(), nil
}

// sign computes ac.Auth.Signature over FramedContentTBS (RFC 9420 §6.1).
func (ac *AuthenticatedContent) sign(suite cipher.Suite, signer crypto.Signer, gc *keyschedule.GroupContext) error {
	tbs, err := framedContentTBS(ac.WireFormat, ac.Content, gc)
	if err != nil {
		return err
	}
	sig, err := suite.SignWithLabel(signer, "FramedContentTBS", tbs)
	if err != nil {
		return err
	}
	ac.Auth.Signature = sig
	return nil
}

// verify checks ac.Auth.Signature against signaturePub (RFC 9420 §6.1).
func (ac AuthenticatedContent) verify(suite cipher.Suite, signaturePub []byte, gc *keyschedule.GroupContext) bool {
	tbs, err := framedContentTBS(ac.WireFormat, ac.Content, gc)
	if err != nil {
		return false
	}
	return suite.VerifyWithLabel(signaturePub, "FramedContentTBS", tbs, ac.Auth.Signature)
}
