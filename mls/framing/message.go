package framing

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/syntax"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// MLSMessage is the top-level wire envelope (RFC 9420 §6). Exactly one body
// pointer is set, selected by WireFormat. Welcome/GroupInfo/KeyPackage bodies
// arrive in a later plan.
type MLSMessage struct {
	Version    tree.ProtocolVersion
	WireFormat WireFormat
	Public     *PublicMessage
	Private    *PrivateMessage
}

func (m MLSMessage) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	b.WriteUint16(uint16(m.Version))
	b.WriteUint16(uint16(m.WireFormat))
	switch m.WireFormat {
	case WireFormatPublicMessage:
		if m.Public == nil {
			return nil, fmt.Errorf("framing: MLSMessage public body missing")
		}
		if err := m.Public.marshal(b); err != nil {
			return nil, err
		}
	case WireFormatPrivateMessage:
		if m.Private == nil {
			return nil, fmt.Errorf("framing: MLSMessage private body missing")
		}
		if err := m.Private.marshal(b); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("framing: unsupported wire format %#x", m.WireFormat)
	}
	return b.Bytes(), nil
}

func (m *MLSMessage) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := c.ReadUint16()
	if err != nil {
		return err
	}
	m.Version = tree.ProtocolVersion(v)
	wf, err := c.ReadUint16()
	if err != nil {
		return err
	}
	m.WireFormat = WireFormat(wf)
	switch m.WireFormat {
	case WireFormatPublicMessage:
		pm, err := decodePublicMessage(c)
		if err != nil {
			return err
		}
		m.Public = &pm
	case WireFormatPrivateMessage:
		pm, err := decodePrivateMessage(c)
		if err != nil {
			return err
		}
		m.Private = &pm
	default:
		return fmt.Errorf("framing: unsupported wire format %#x", m.WireFormat)
	}
	if !c.Empty() {
		return fmt.Errorf("framing: trailing bytes after MLSMessage")
	}
	return nil
}
