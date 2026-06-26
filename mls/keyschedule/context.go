// Package keyschedule implements the RFC 9420 §8 key schedule, the §9 secret
// tree, the §8.2/§6.1 transcript hashes, and the §8.4 pre-shared-key
// aggregation.
package keyschedule

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// GroupContext summarizes the group state hashed into the key schedule
// (RFC 9420 §8.1):
//
//	struct {
//	    ProtocolVersion version = mls10;
//	    CipherSuite cipher_suite;
//	    opaque group_id<V>;
//	    uint64 epoch;
//	    opaque tree_hash<V>;
//	    opaque confirmed_transcript_hash<V>;
//	    Extension extensions<V>;
//	} GroupContext;
type GroupContext struct {
	Version                 tree.ProtocolVersion
	CipherSuite             cipher.CipherSuite
	GroupID                 []byte
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
	Extensions              []tree.Extension
}

func (gc GroupContext) marshal(b *syntax.Builder) error {
	b.WriteUint16(uint16(gc.Version))
	b.WriteUint16(uint16(gc.CipherSuite))
	if err := b.WriteOpaqueV(gc.GroupID); err != nil {
		return err
	}
	b.WriteUint64(gc.Epoch)
	if err := b.WriteOpaqueV(gc.TreeHash); err != nil {
		return err
	}
	if err := b.WriteOpaqueV(gc.ConfirmedTranscriptHash); err != nil {
		return err
	}
	return syntax.WriteVectorV(b, gc.Extensions, func(b *syntax.Builder, e tree.Extension) error {
		return e.MarshalTo(b)
	})
}

func decodeGroupContext(c *syntax.Cursor) (GroupContext, error) {
	var gc GroupContext
	v, err := c.ReadUint16()
	if err != nil {
		return gc, err
	}
	gc.Version = tree.ProtocolVersion(v)
	cs, err := c.ReadUint16()
	if err != nil {
		return gc, err
	}
	gc.CipherSuite = cipher.CipherSuite(cs)
	if gc.GroupID, err = c.ReadOpaqueV(); err != nil {
		return gc, err
	}
	if gc.Epoch, err = c.ReadUint64(); err != nil {
		return gc, err
	}
	if gc.TreeHash, err = c.ReadOpaqueV(); err != nil {
		return gc, err
	}
	if gc.ConfirmedTranscriptHash, err = c.ReadOpaqueV(); err != nil {
		return gc, err
	}
	if gc.Extensions, err = syntax.ReadVectorV(c, tree.DecodeExtension); err != nil {
		return gc, err
	}
	return gc, nil
}

// MarshalMLS encodes the GroupContext to its MLS wire form.
func (gc GroupContext) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := gc.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a GroupContext, rejecting trailing bytes.
func (gc *GroupContext) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeGroupContext(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("keyschedule: trailing bytes after GroupContext")
	}
	*gc = v
	return nil
}
