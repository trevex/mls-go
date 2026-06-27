package group

import (
	"crypto"
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// ExtensionTypeRatchetTree is the extension_type for the ratchet_tree extension
// (RFC 9420 §17.3).
const ExtensionTypeRatchetTree = 0x0002

// ExtensionTypeExternalPub is the extension_type for the external_pub extension
// (RFC 9420 §17.3). It carries the group's external HPKE public key so a
// non-member can compute the external-init secret for an external Commit.
const ExtensionTypeExternalPub tree.ExtensionType = 0x0004

// GroupInfo is the §12.4.3.1 GroupInfo message: a GroupContext, extensions
// (typically carrying the ratchet_tree), a confirmation_tag, the signer leaf
// index, and a GroupInfoTBS signature.
type GroupInfo struct {
	GroupContext    keyschedule.GroupContext
	Extensions      []tree.Extension
	ConfirmationTag []byte // MAC opaque<V>
	Signer          uint32
	Signature       []byte // opaque<V>
}

// marshalTBS writes the GroupInfoTBS serialization (GroupInfo minus signature).
func (gi GroupInfo) marshalTBS(b *syntax.Builder) error {
	gcb, err := gi.GroupContext.MarshalMLS()
	if err != nil {
		return err
	}
	b.WriteRaw(gcb)
	if err := syntax.WriteVectorV(b, gi.Extensions, func(b *syntax.Builder, e tree.Extension) error {
		return e.MarshalTo(b)
	}); err != nil {
		return err
	}
	if err := b.WriteOpaqueV(gi.ConfirmationTag); err != nil {
		return err
	}
	b.WriteUint32(gi.Signer)
	return nil
}

func (gi GroupInfo) marshal(b *syntax.Builder) error {
	if err := gi.marshalTBS(b); err != nil {
		return err
	}
	return b.WriteOpaqueV(gi.Signature)
}

func decodeGroupInfo(c *syntax.Cursor) (GroupInfo, error) {
	var gi GroupInfo
	var err error
	if gi.GroupContext, err = keyschedule.DecodeGroupContext(c); err != nil {
		return gi, err
	}
	if gi.Extensions, err = syntax.ReadVectorV(c, tree.DecodeExtension); err != nil {
		return gi, err
	}
	if gi.ConfirmationTag, err = c.ReadOpaqueV(); err != nil {
		return gi, err
	}
	signer, err := c.ReadUint32()
	if err != nil {
		return gi, err
	}
	gi.Signer = signer
	if gi.Signature, err = c.ReadOpaqueV(); err != nil {
		return gi, err
	}
	return gi, nil
}

// tbsBytes returns the serialized GroupInfoTBS for signing/verification.
func (gi GroupInfo) tbsBytes() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := gi.marshalTBS(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Sign sets gi.Signature = SignWithLabel(signer, "GroupInfoTBS", GroupInfoTBS)
// (RFC 9420 §12.4.3.1).
func (gi *GroupInfo) Sign(suite cipher.Suite, signer crypto.Signer) error {
	tbs, err := gi.tbsBytes()
	if err != nil {
		return err
	}
	sig, err := suite.SignWithLabel(signer, "GroupInfoTBS", tbs)
	if err != nil {
		return err
	}
	gi.Signature = sig
	return nil
}

// VerifySignature checks the GroupInfo signature under label "GroupInfoTBS"
// with signerPub (the signer leaf's signature key).
func (gi GroupInfo) VerifySignature(suite cipher.Suite, signerPub []byte) (bool, error) {
	tbs, err := gi.tbsBytes()
	if err != nil {
		return false, err
	}
	return suite.VerifyWithLabel(signerPub, "GroupInfoTBS", tbs, gi.Signature), nil
}

// RatchetTreeExtension returns the data of the ratchet_tree (0x0002) extension,
// or nil if absent.
func (gi GroupInfo) RatchetTreeExtension() []byte {
	for _, ext := range gi.Extensions {
		if ext.ExtensionType == ExtensionTypeRatchetTree {
			return ext.ExtensionData
		}
	}
	return nil
}

// ExternalPubExtension returns the data of the external_pub (0x0004) extension,
// or nil if absent. The bytes are the serialized HPKEPublicKey used by a
// non-member to compute the external-init secret for an external Commit
// (RFC 9420 §12.4.3.2).
func (gi GroupInfo) ExternalPubExtension() []byte {
	for _, ext := range gi.Extensions {
		if ext.ExtensionType == ExtensionTypeExternalPub {
			return ext.ExtensionData
		}
	}
	return nil
}

// MarshalMLS encodes the GroupInfo to its MLS wire form.
func (gi GroupInfo) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := gi.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a GroupInfo, rejecting trailing bytes.
func (gi *GroupInfo) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeGroupInfo(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("group: trailing bytes after GroupInfo")
	}
	*gi = v
	return nil
}
