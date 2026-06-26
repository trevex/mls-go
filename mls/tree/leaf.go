package tree

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
)

// ProtocolVersion is the 2-byte MLS protocol version (RFC 9420 §6).
type ProtocolVersion uint16

// ProtocolVersionMLS10 is mls10 (RFC 9420 §6).
const ProtocolVersionMLS10 ProtocolVersion = 1

// ExtensionType is the 2-byte MLS extension type (RFC 9420 §7.2).
type ExtensionType uint16

// ProposalType is the 2-byte MLS proposal type (RFC 9420 §12.1).
type ProposalType uint16

// LeafNodeSource indicates how a LeafNode entered the tree (RFC 9420 §7.2).
type LeafNodeSource uint8

const (
	LeafNodeSourceReserved   LeafNodeSource = 0
	LeafNodeSourceKeyPackage LeafNodeSource = 1
	LeafNodeSourceUpdate     LeafNodeSource = 2
	LeafNodeSourceCommit     LeafNodeSource = 3
)

// Capabilities advertises the features a client supports (RFC 9420 §7.2).
type Capabilities struct {
	Versions     []ProtocolVersion
	CipherSuites []cipher.CipherSuite
	Extensions   []ExtensionType
	Proposals    []ProposalType
	Credentials  []CredentialType
}

func (c Capabilities) marshal(b *syntax.Builder) error {
	if err := syntax.WriteVectorV(b, c.Versions, func(b *syntax.Builder, v ProtocolVersion) error {
		b.WriteUint16(uint16(v))
		return nil
	}); err != nil {
		return err
	}
	if err := syntax.WriteVectorV(b, c.CipherSuites, func(b *syntax.Builder, v cipher.CipherSuite) error {
		b.WriteUint16(uint16(v))
		return nil
	}); err != nil {
		return err
	}
	if err := syntax.WriteVectorV(b, c.Extensions, func(b *syntax.Builder, v ExtensionType) error {
		b.WriteUint16(uint16(v))
		return nil
	}); err != nil {
		return err
	}
	if err := syntax.WriteVectorV(b, c.Proposals, func(b *syntax.Builder, v ProposalType) error {
		b.WriteUint16(uint16(v))
		return nil
	}); err != nil {
		return err
	}
	return syntax.WriteVectorV(b, c.Credentials, func(b *syntax.Builder, v CredentialType) error {
		b.WriteUint16(uint16(v))
		return nil
	})
}

func decodeCapabilities(c *syntax.Cursor) (Capabilities, error) {
	var caps Capabilities
	var err error
	if caps.Versions, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (ProtocolVersion, error) {
		v, err := c.ReadUint16()
		return ProtocolVersion(v), err
	}); err != nil {
		return caps, err
	}
	if caps.CipherSuites, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (cipher.CipherSuite, error) {
		v, err := c.ReadUint16()
		return cipher.CipherSuite(v), err
	}); err != nil {
		return caps, err
	}
	if caps.Extensions, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (ExtensionType, error) {
		v, err := c.ReadUint16()
		return ExtensionType(v), err
	}); err != nil {
		return caps, err
	}
	if caps.Proposals, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (ProposalType, error) {
		v, err := c.ReadUint16()
		return ProposalType(v), err
	}); err != nil {
		return caps, err
	}
	if caps.Credentials, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (CredentialType, error) {
		v, err := c.ReadUint16()
		return CredentialType(v), err
	}); err != nil {
		return caps, err
	}
	return caps, nil
}

// Lifetime is the validity window for a key_package LeafNode (RFC 9420 §7.2).
type Lifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

func (l Lifetime) marshal(b *syntax.Builder) {
	b.WriteUint64(l.NotBefore)
	b.WriteUint64(l.NotAfter)
}

func decodeLifetime(c *syntax.Cursor) (Lifetime, error) {
	var l Lifetime
	var err error
	if l.NotBefore, err = c.ReadUint64(); err != nil {
		return l, err
	}
	if l.NotAfter, err = c.ReadUint64(); err != nil {
		return l, err
	}
	return l, nil
}

// Extension is a single MLS extension (RFC 9420 §7.2).
type Extension struct {
	ExtensionType ExtensionType
	ExtensionData []byte
}

func (e Extension) marshal(b *syntax.Builder) error {
	b.WriteUint16(uint16(e.ExtensionType))
	return b.WriteOpaqueV(e.ExtensionData)
}

func decodeExtension(c *syntax.Cursor) (Extension, error) {
	et, err := c.ReadUint16()
	if err != nil {
		return Extension{}, err
	}
	data, err := c.ReadOpaqueV()
	if err != nil {
		return Extension{}, err
	}
	return Extension{ExtensionType: ExtensionType(et), ExtensionData: data}, nil
}

// LeafNode describes a member's appearance in the ratchet tree (RFC 9420 §7.2).
type LeafNode struct {
	EncryptionKey  []byte // HPKEPublicKey opaque<V>
	SignatureKey   []byte // SignaturePublicKey opaque<V>
	Credential     Credential
	Capabilities   Capabilities
	LeafNodeSource LeafNodeSource
	Lifetime       *Lifetime // present iff source==key_package
	ParentHash     []byte    // present iff source==commit
	Extensions     []Extension
	Signature      []byte // opaque<V>
}

// marshalContents writes the fields above the signature — the body shared by
// LeafNode and the leading part of LeafNodeTBS (RFC 9420 §7.2).
func (l LeafNode) marshalContents(b *syntax.Builder) error {
	if err := b.WriteOpaqueV(l.EncryptionKey); err != nil {
		return err
	}
	if err := b.WriteOpaqueV(l.SignatureKey); err != nil {
		return err
	}
	if err := l.Credential.marshal(b); err != nil {
		return err
	}
	if err := l.Capabilities.marshal(b); err != nil {
		return err
	}
	b.WriteUint8(uint8(l.LeafNodeSource))
	switch l.LeafNodeSource {
	case LeafNodeSourceKeyPackage:
		if l.Lifetime == nil {
			return fmt.Errorf("tree: key_package leaf node missing lifetime")
		}
		l.Lifetime.marshal(b)
	case LeafNodeSourceUpdate:
		// empty struct{}
	case LeafNodeSourceCommit:
		if err := b.WriteOpaqueV(l.ParentHash); err != nil {
			return err
		}
	default:
		return fmt.Errorf("tree: invalid leaf_node_source %d", l.LeafNodeSource)
	}
	return syntax.WriteVectorV(b, l.Extensions, func(b *syntax.Builder, e Extension) error {
		return e.marshal(b)
	})
}

func (l LeafNode) marshal(b *syntax.Builder) error {
	if err := l.marshalContents(b); err != nil {
		return err
	}
	return b.WriteOpaqueV(l.Signature)
}

func decodeLeafNode(c *syntax.Cursor) (LeafNode, error) {
	var l LeafNode
	var err error
	if l.EncryptionKey, err = c.ReadOpaqueV(); err != nil {
		return l, err
	}
	if l.SignatureKey, err = c.ReadOpaqueV(); err != nil {
		return l, err
	}
	if l.Credential, err = decodeCredential(c); err != nil {
		return l, err
	}
	if l.Capabilities, err = decodeCapabilities(c); err != nil {
		return l, err
	}
	src, err := c.ReadUint8()
	if err != nil {
		return l, err
	}
	l.LeafNodeSource = LeafNodeSource(src)
	switch l.LeafNodeSource {
	case LeafNodeSourceKeyPackage:
		lt, err := decodeLifetime(c)
		if err != nil {
			return l, err
		}
		l.Lifetime = &lt
	case LeafNodeSourceUpdate:
		// empty struct{}
	case LeafNodeSourceCommit:
		if l.ParentHash, err = c.ReadOpaqueV(); err != nil {
			return l, err
		}
	default:
		return l, fmt.Errorf("tree: invalid leaf_node_source %d", l.LeafNodeSource)
	}
	if l.Extensions, err = syntax.ReadVectorV(c, decodeExtension); err != nil {
		return l, err
	}
	if l.Signature, err = c.ReadOpaqueV(); err != nil {
		return l, err
	}
	return l, nil
}

// tbs builds the LeafNodeTBS bytes for signing/verification (RFC 9420 §7.2/§7.3).
// groupID and leafIndex are appended only for update/commit sources.
func (l LeafNode) tbs(groupID []byte, leafIndex uint32) ([]byte, error) {
	b := syntax.NewBuilder()
	if err := l.marshalContents(b); err != nil {
		return nil, err
	}
	switch l.LeafNodeSource {
	case LeafNodeSourceUpdate, LeafNodeSourceCommit:
		if err := b.WriteOpaqueV(groupID); err != nil {
			return nil, err
		}
		b.WriteUint32(leafIndex)
	}
	return b.Bytes(), nil
}

// verifySignature checks the leaf's signature under label "LeafNodeTBS".
func (l LeafNode) verifySignature(suite cipher.Suite, groupID []byte, leafIndex uint32) (bool, error) {
	tbs, err := l.tbs(groupID, leafIndex)
	if err != nil {
		return false, err
	}
	return suite.VerifyWithLabel(l.SignatureKey, "LeafNodeTBS", tbs, l.Signature), nil
}

// MarshalMLS encodes the LeafNode to its MLS wire form.
func (l LeafNode) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := l.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a LeafNode, rejecting trailing bytes.
func (l *LeafNode) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeLeafNode(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("tree: trailing bytes after LeafNode")
	}
	*l = v
	return nil
}
