package group

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// ProposalType is the 2-byte proposal type id (RFC 9420 §12.1).
type ProposalType uint16

const (
	ProposalTypeAdd                    ProposalType = 1
	ProposalTypeUpdate                 ProposalType = 2
	ProposalTypeRemove                 ProposalType = 3
	ProposalTypePreSharedKey           ProposalType = 4
	ProposalTypeReInit                 ProposalType = 5
	ProposalTypeExternalInit           ProposalType = 6
	ProposalTypeGroupContextExtensions ProposalType = 7
)

// Add carries a KeyPackage for a new member (RFC 9420 §12.1.1).
type Add struct{ KeyPackage KeyPackage }

// Update carries a new LeafNode for an existing member (RFC 9420 §12.1.2).
type Update struct{ LeafNode tree.LeafNode }

// Remove removes a member by leaf index (RFC 9420 §12.1.3).
type Remove struct{ Removed uint32 }

// PreSharedKey injects a pre-shared key into the key schedule (RFC 9420 §12.1.4).
type PreSharedKey struct{ PSK keyschedule.PreSharedKeyID }

// ReInit reinitializes the group with new parameters (RFC 9420 §12.1.5).
type ReInit struct {
	GroupID     []byte
	Version     tree.ProtocolVersion
	CipherSuite cipher.CipherSuite
	Extensions  []tree.Extension
}

// ExternalInit is used by an external joiner to add itself (RFC 9420 §12.1.6).
type ExternalInit struct{ KemOutput []byte }

// GroupContextExtensions updates the group context extensions (RFC 9420 §12.1.7).
type GroupContextExtensions struct{ Extensions []tree.Extension }

// Proposal is the §12.1 enum. Exactly one body pointer is set, selected by Type.
type Proposal struct {
	Type                   ProposalType
	Add                    *Add
	Update                 *Update
	Remove                 *Remove
	PreSharedKey           *PreSharedKey
	ReInit                 *ReInit
	ExternalInit           *ExternalInit
	GroupContextExtensions *GroupContextExtensions
}

func (p Proposal) marshal(b *syntax.Builder) error {
	b.WriteUint16(uint16(p.Type))
	switch p.Type {
	case ProposalTypeAdd:
		if p.Add == nil {
			return fmt.Errorf("group: Proposal.Add is nil")
		}
		return p.Add.KeyPackage.marshal(b)
	case ProposalTypeUpdate:
		if p.Update == nil {
			return fmt.Errorf("group: Proposal.Update is nil")
		}
		lnb, err := p.Update.LeafNode.MarshalMLS()
		if err != nil {
			return err
		}
		b.WriteRaw(lnb)
		return nil
	case ProposalTypeRemove:
		if p.Remove == nil {
			return fmt.Errorf("group: Proposal.Remove is nil")
		}
		b.WriteUint32(p.Remove.Removed)
		return nil
	case ProposalTypePreSharedKey:
		if p.PreSharedKey == nil {
			return fmt.Errorf("group: Proposal.PreSharedKey is nil")
		}
		return p.PreSharedKey.PSK.MarshalTo(b)
	case ProposalTypeReInit:
		if p.ReInit == nil {
			return fmt.Errorf("group: Proposal.ReInit is nil")
		}
		if err := b.WriteOpaqueV(p.ReInit.GroupID); err != nil {
			return err
		}
		b.WriteUint16(uint16(p.ReInit.Version))
		b.WriteUint16(uint16(p.ReInit.CipherSuite))
		return syntax.WriteVectorV(b, p.ReInit.Extensions, func(b *syntax.Builder, e tree.Extension) error {
			return e.MarshalTo(b)
		})
	case ProposalTypeExternalInit:
		if p.ExternalInit == nil {
			return fmt.Errorf("group: Proposal.ExternalInit is nil")
		}
		return b.WriteOpaqueV(p.ExternalInit.KemOutput)
	case ProposalTypeGroupContextExtensions:
		if p.GroupContextExtensions == nil {
			return fmt.Errorf("group: Proposal.GroupContextExtensions is nil")
		}
		return syntax.WriteVectorV(b, p.GroupContextExtensions.Extensions, func(b *syntax.Builder, e tree.Extension) error {
			return e.MarshalTo(b)
		})
	default:
		return fmt.Errorf("group: unknown proposal type %d", p.Type)
	}
}

func decodeProposal(c *syntax.Cursor) (Proposal, error) {
	var p Proposal
	pt, err := c.ReadUint16()
	if err != nil {
		return p, err
	}
	p.Type = ProposalType(pt)
	switch p.Type {
	case ProposalTypeAdd:
		kp, err := decodeKeyPackage(c)
		if err != nil {
			return p, err
		}
		p.Add = &Add{KeyPackage: kp}
	case ProposalTypeUpdate:
		ln, err := tree.DecodeLeafNode(c)
		if err != nil {
			return p, err
		}
		p.Update = &Update{LeafNode: ln}
	case ProposalTypeRemove:
		removed, err := c.ReadUint32()
		if err != nil {
			return p, err
		}
		p.Remove = &Remove{Removed: removed}
	case ProposalTypePreSharedKey:
		psk, err := keyschedule.DecodePreSharedKeyID(c)
		if err != nil {
			return p, err
		}
		p.PreSharedKey = &PreSharedKey{PSK: psk}
	case ProposalTypeReInit:
		var ri ReInit
		if ri.GroupID, err = c.ReadOpaqueV(); err != nil {
			return p, err
		}
		v, err := c.ReadUint16()
		if err != nil {
			return p, err
		}
		ri.Version = tree.ProtocolVersion(v)
		cs, err := c.ReadUint16()
		if err != nil {
			return p, err
		}
		ri.CipherSuite = cipher.CipherSuite(cs)
		if ri.Extensions, err = syntax.ReadVectorV(c, tree.DecodeExtension); err != nil {
			return p, err
		}
		p.ReInit = &ri
	case ProposalTypeExternalInit:
		kemOutput, err := c.ReadOpaqueV()
		if err != nil {
			return p, err
		}
		p.ExternalInit = &ExternalInit{KemOutput: kemOutput}
	case ProposalTypeGroupContextExtensions:
		exts, err := syntax.ReadVectorV(c, tree.DecodeExtension)
		if err != nil {
			return p, err
		}
		p.GroupContextExtensions = &GroupContextExtensions{Extensions: exts}
	default:
		return p, fmt.Errorf("group: unknown proposal type %d", p.Type)
	}
	return p, nil
}

// Ref computes ProposalRef = RefHash("MLS 1.0 Proposal Reference", Proposal)
// (RFC 9420 §5.2 / §12.4).
func (p Proposal) Ref(suite cipher.Suite) ([]byte, error) {
	raw, err := p.MarshalMLS()
	if err != nil {
		return nil, err
	}
	return suite.RefHash("MLS 1.0 Proposal Reference", raw)
}

// MarshalMLS encodes the Proposal to its MLS wire form.
func (p Proposal) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := p.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a Proposal, rejecting trailing bytes.
func (p *Proposal) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeProposal(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("group: trailing bytes after Proposal")
	}
	*p = v
	return nil
}

// ProposalOrRefType discriminates a ProposalOrRef (RFC 9420 §12.4).
type ProposalOrRefType uint8

const (
	ProposalOrRefTypeProposal  ProposalOrRefType = 1
	ProposalOrRefTypeReference ProposalOrRefType = 2
)

// ProposalOrRef is either an inline Proposal or a ProposalRef (RFC 9420 §12.4).
type ProposalOrRef struct {
	Type      ProposalOrRefType
	Proposal  *Proposal // type==proposal
	Reference []byte    // type==reference, opaque<V>
}

func (por ProposalOrRef) marshal(b *syntax.Builder) error {
	b.WriteUint8(uint8(por.Type))
	switch por.Type {
	case ProposalOrRefTypeProposal:
		if por.Proposal == nil {
			return fmt.Errorf("group: ProposalOrRef.Proposal is nil")
		}
		return por.Proposal.marshal(b)
	case ProposalOrRefTypeReference:
		return b.WriteOpaqueV(por.Reference)
	default:
		return fmt.Errorf("group: unknown ProposalOrRefType %d", por.Type)
	}
}

func decodeProposalOrRef(c *syntax.Cursor) (ProposalOrRef, error) {
	var por ProposalOrRef
	t, err := c.ReadUint8()
	if err != nil {
		return por, err
	}
	por.Type = ProposalOrRefType(t)
	switch por.Type {
	case ProposalOrRefTypeProposal:
		p, err := decodeProposal(c)
		if err != nil {
			return por, err
		}
		por.Proposal = &p
	case ProposalOrRefTypeReference:
		if por.Reference, err = c.ReadOpaqueV(); err != nil {
			return por, err
		}
	default:
		return por, fmt.Errorf("group: unknown ProposalOrRefType %d", por.Type)
	}
	return por, nil
}

// MarshalMLS encodes the ProposalOrRef to its MLS wire form.
func (por ProposalOrRef) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := por.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a ProposalOrRef, rejecting trailing bytes.
func (por *ProposalOrRef) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeProposalOrRef(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("group: trailing bytes after ProposalOrRef")
	}
	*por = v
	return nil
}
