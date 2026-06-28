package group

import (
	"fmt"

	"github.com/trevex/mls-go/mls/syntax"
	"github.com/trevex/mls-go/mls/tree"
)

// Commit is the §12.4 Commit message body: a vector of ProposalOrRef and an
// optional UpdatePath.
type Commit struct {
	Proposals []ProposalOrRef
	Path      *tree.UpdatePath // optional<UpdatePath>
}

func (cm Commit) marshal(b *syntax.Builder) error {
	if err := syntax.WriteVectorV(b, cm.Proposals, func(b *syntax.Builder, p ProposalOrRef) error {
		return p.marshal(b)
	}); err != nil {
		return err
	}
	if cm.Path == nil {
		b.WriteUint8(0)
		return nil
	}
	b.WriteUint8(1)
	up, err := cm.Path.MarshalMLS()
	if err != nil {
		return err
	}
	b.WriteRaw(up)
	return nil
}

func decodeCommit(c *syntax.Cursor) (Commit, error) {
	var cm Commit
	var err error
	if cm.Proposals, err = syntax.ReadVectorV(c, decodeProposalOrRef); err != nil {
		return cm, err
	}
	present, err := c.ReadUint8()
	if err != nil {
		return cm, err
	}
	switch present {
	case 0:
		// absent
	case 1:
		up, err := tree.DecodeUpdatePath(c)
		if err != nil {
			return cm, err
		}
		cm.Path = &up
	default:
		return cm, fmt.Errorf("group: invalid optional<UpdatePath> presence %d", present)
	}
	return cm, nil
}

// MarshalMLS encodes the Commit to its MLS wire form.
func (cm Commit) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := cm.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a Commit, rejecting trailing bytes.
func (cm *Commit) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeCommit(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("group: trailing bytes after Commit")
	}
	*cm = v
	return nil
}
