package tree

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/syntax"
)

// HPKECiphertext is an HPKE KEM output paired with an AEAD ciphertext
// (RFC 9420 §7.6).
type HPKECiphertext struct {
	KemOutput  []byte // opaque kem_output<V>
	Ciphertext []byte // opaque ciphertext<V>
}

func (h HPKECiphertext) marshal(b *syntax.Builder) error {
	if err := b.WriteOpaqueV(h.KemOutput); err != nil {
		return err
	}
	return b.WriteOpaqueV(h.Ciphertext)
}

func decodeHPKECiphertext(c *syntax.Cursor) (HPKECiphertext, error) {
	var h HPKECiphertext
	var err error
	if h.KemOutput, err = c.ReadOpaqueV(); err != nil {
		return h, err
	}
	if h.Ciphertext, err = c.ReadOpaqueV(); err != nil {
		return h, err
	}
	return h, nil
}

// MarshalTo writes the HPKECiphertext into b. Exported so group.EncryptedGroupSecrets
// can embed it.
func (h HPKECiphertext) MarshalTo(b *syntax.Builder) error { return h.marshal(b) }

// DecodeHPKECiphertext reads one HPKECiphertext from c.
func DecodeHPKECiphertext(c *syntax.Cursor) (HPKECiphertext, error) {
	return decodeHPKECiphertext(c)
}

// UpdatePathNode is one node of a sender's filtered direct path: a fresh public
// key plus the path secret encrypted to every member of the copath child's
// resolution (RFC 9420 §7.6).
type UpdatePathNode struct {
	EncryptionKey       []byte           // HPKEPublicKey opaque<V>
	EncryptedPathSecret []HPKECiphertext // encrypted_path_secret<V>
}

func (n UpdatePathNode) marshal(b *syntax.Builder) error {
	if err := b.WriteOpaqueV(n.EncryptionKey); err != nil {
		return err
	}
	return syntax.WriteVectorV(b, n.EncryptedPathSecret, func(b *syntax.Builder, h HPKECiphertext) error {
		return h.marshal(b)
	})
}

func decodeUpdatePathNode(c *syntax.Cursor) (UpdatePathNode, error) {
	var n UpdatePathNode
	var err error
	if n.EncryptionKey, err = c.ReadOpaqueV(); err != nil {
		return n, err
	}
	if n.EncryptedPathSecret, err = syntax.ReadVectorV(c, decodeHPKECiphertext); err != nil {
		return n, err
	}
	return n, nil
}

// UpdatePath carries a committer's new leaf node and the new public keys and
// encrypted path secrets for its filtered direct path (RFC 9420 §7.6).
type UpdatePath struct {
	LeafNode LeafNode
	Nodes    []UpdatePathNode
}

func (u UpdatePath) marshal(b *syntax.Builder) error {
	if err := u.LeafNode.marshal(b); err != nil {
		return err
	}
	return syntax.WriteVectorV(b, u.Nodes, func(b *syntax.Builder, n UpdatePathNode) error {
		return n.marshal(b)
	})
}

func decodeUpdatePath(c *syntax.Cursor) (UpdatePath, error) {
	var u UpdatePath
	var err error
	if u.LeafNode, err = decodeLeafNode(c); err != nil {
		return u, err
	}
	if u.Nodes, err = syntax.ReadVectorV(c, decodeUpdatePathNode); err != nil {
		return u, err
	}
	return u, nil
}

// DecodeUpdatePath decodes an UpdatePath from a cursor (used by framing to
// delimit a Commit's optional<UpdatePath>).
func DecodeUpdatePath(c *syntax.Cursor) (UpdatePath, error) { return decodeUpdatePath(c) }

// MarshalMLS encodes the UpdatePath to its MLS wire form.
func (u UpdatePath) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := u.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes an UpdatePath, rejecting trailing bytes.
func (u *UpdatePath) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeUpdatePath(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("tree: trailing bytes after UpdatePath")
	}
	*u = v
	return nil
}
