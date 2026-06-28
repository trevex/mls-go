package tree

import (
	"fmt"

	"github.com/trevex/mls-go/mls/syntax"
)

// ParentNode is an interior ratchet-tree node (RFC 9420 §7.1).
type ParentNode struct {
	EncryptionKey  []byte   // HPKEPublicKey opaque<V>
	ParentHash     []byte   // opaque<V>
	UnmergedLeaves []uint32 // uint32 unmerged_leaves<V>, sorted increasing
}

func (p ParentNode) marshal(b *syntax.Builder) error {
	if err := b.WriteOpaqueV(p.EncryptionKey); err != nil {
		return err
	}
	if err := b.WriteOpaqueV(p.ParentHash); err != nil {
		return err
	}
	return syntax.WriteVectorV(b, p.UnmergedLeaves, func(b *syntax.Builder, v uint32) error {
		b.WriteUint32(v)
		return nil
	})
}

func decodeParentNode(c *syntax.Cursor) (ParentNode, error) {
	var p ParentNode
	var err error
	if p.EncryptionKey, err = c.ReadOpaqueV(); err != nil {
		return p, err
	}
	if p.ParentHash, err = c.ReadOpaqueV(); err != nil {
		return p, err
	}
	if p.UnmergedLeaves, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (uint32, error) {
		return c.ReadUint32()
	}); err != nil {
		return p, err
	}
	return p, nil
}

// MarshalMLS encodes the ParentNode to its MLS wire form.
func (p ParentNode) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := p.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a ParentNode, rejecting trailing bytes.
func (p *ParentNode) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeParentNode(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("tree: trailing bytes after ParentNode")
	}
	*p = v
	return nil
}
