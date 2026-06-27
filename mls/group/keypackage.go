// Package group implements the RFC 9420 §10/§12 protocol objects (KeyPackage,
// Proposal, Commit, GroupInfo, Welcome) and (Plan 8b) the group state machine.
package group

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// KeyPackage advertises a client's init key + leaf node for being added to a
// group (RFC 9420 §10).
type KeyPackage struct {
	Version     tree.ProtocolVersion
	CipherSuite cipher.CipherSuite
	InitKey     []byte // HPKEPublicKey opaque<V>
	LeafNode    tree.LeafNode
	Extensions  []tree.Extension
	Signature   []byte // opaque<V>
}

// marshalTBS writes KeyPackageTBS (everything above the signature).
func (kp KeyPackage) marshalTBS(b *syntax.Builder) error {
	b.WriteUint16(uint16(kp.Version))
	b.WriteUint16(uint16(kp.CipherSuite))
	if err := b.WriteOpaqueV(kp.InitKey); err != nil {
		return err
	}
	lnb, err := kp.LeafNode.MarshalMLS()
	if err != nil {
		return err
	}
	b.WriteRaw(lnb) // inline, no length prefix
	return syntax.WriteVectorV(b, kp.Extensions, func(b *syntax.Builder, e tree.Extension) error {
		return e.MarshalTo(b)
	})
}

func (kp KeyPackage) marshal(b *syntax.Builder) error {
	if err := kp.marshalTBS(b); err != nil {
		return err
	}
	return b.WriteOpaqueV(kp.Signature)
}

func decodeKeyPackage(c *syntax.Cursor) (KeyPackage, error) {
	var kp KeyPackage
	v, err := c.ReadUint16()
	if err != nil {
		return kp, err
	}
	kp.Version = tree.ProtocolVersion(v)
	cs, err := c.ReadUint16()
	if err != nil {
		return kp, err
	}
	kp.CipherSuite = cipher.CipherSuite(cs)
	if kp.InitKey, err = c.ReadOpaqueV(); err != nil {
		return kp, err
	}
	if kp.LeafNode, err = tree.DecodeLeafNode(c); err != nil {
		return kp, err
	}
	if kp.Extensions, err = syntax.ReadVectorV(c, tree.DecodeExtension); err != nil {
		return kp, err
	}
	if kp.Signature, err = c.ReadOpaqueV(); err != nil {
		return kp, err
	}
	return kp, nil
}

// tbsBytes returns the serialized KeyPackageTBS for signing/verification.
func (kp KeyPackage) tbsBytes() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := kp.marshalTBS(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// VerifySignature checks the KeyPackage signature under label "KeyPackageTBS"
// using the leaf node's signature key (RFC 9420 §10).
func (kp KeyPackage) VerifySignature(suite cipher.Suite) (bool, error) {
	tbs, err := kp.tbsBytes()
	if err != nil {
		return false, err
	}
	return suite.VerifyWithLabel(kp.LeafNode.SignatureKey, "KeyPackageTBS", tbs, kp.Signature), nil
}

// Ref computes the KeyPackageRef = RefHash("MLS 1.0 KeyPackage Reference",
// KeyPackage) (RFC 9420 §5.2). The value hashed is the full KeyPackage struct
// serialization (NOT the MLSMessage envelope).
func (kp KeyPackage) Ref(suite cipher.Suite) ([]byte, error) {
	raw, err := kp.MarshalMLS()
	if err != nil {
		return nil, err
	}
	return suite.RefHash("MLS 1.0 KeyPackage Reference", raw)
}

// MarshalMLS encodes the KeyPackage to its MLS wire form.
func (kp KeyPackage) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := kp.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a KeyPackage, rejecting trailing bytes.
func (kp *KeyPackage) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeKeyPackage(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("group: trailing bytes after KeyPackage")
	}
	*kp = v
	return nil
}
