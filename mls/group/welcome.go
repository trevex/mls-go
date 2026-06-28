package group

import (
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/syntax"
	"github.com/trevex/mls-go/mls/tree"
)

// wireVersion is the MLS protocol version sent in MLSMessage envelopes (mls10).
const wireVersion uint16 = 0x0001

// wireFormatWelcome / wireFormatGroupInfo / wireFormatKeyPackage are the
// WireFormat constants for the three non-framing envelope types.
const (
	wireFormatWelcome    uint16 = 0x0003
	wireFormatGroupInfo  uint16 = 0x0004
	wireFormatKeyPackage uint16 = 0x0005
)

// PathSecret is a single path secret wrapped in an optional (RFC 9420 §12.4.3.1).
type PathSecret struct {
	PathSecret []byte // opaque<V>
}

func (ps PathSecret) marshal(b *syntax.Builder) error {
	return b.WriteOpaqueV(ps.PathSecret)
}

func decodePathSecret(c *syntax.Cursor) (PathSecret, error) {
	var ps PathSecret
	var err error
	if ps.PathSecret, err = c.ReadOpaqueV(); err != nil {
		return ps, err
	}
	return ps, nil
}

// MarshalMLS encodes the PathSecret.
func (ps PathSecret) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := ps.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a PathSecret, rejecting trailing bytes.
func (ps *PathSecret) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodePathSecret(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("group: trailing bytes after PathSecret")
	}
	*ps = v
	return nil
}

// GroupSecrets is the plaintext recovered by HPKE decryption of an
// EncryptedGroupSecrets entry (RFC 9420 §12.4.3.1).
type GroupSecrets struct {
	JoinerSecret []byte                       // opaque<V>
	PathSecret   *PathSecret                  // optional<PathSecret>
	PSKs         []keyschedule.PreSharedKeyID // psks<V>
}

func (gs GroupSecrets) marshal(b *syntax.Builder) error {
	if err := b.WriteOpaqueV(gs.JoinerSecret); err != nil {
		return err
	}
	// optional<PathSecret>: 0x00 absent / 0x01 present
	if gs.PathSecret == nil {
		b.WriteUint8(0)
	} else {
		b.WriteUint8(1)
		if err := gs.PathSecret.marshal(b); err != nil {
			return err
		}
	}
	return syntax.WriteVectorV(b, gs.PSKs, func(b *syntax.Builder, p keyschedule.PreSharedKeyID) error {
		return p.MarshalTo(b)
	})
}

func decodeGroupSecrets(c *syntax.Cursor) (GroupSecrets, error) {
	var gs GroupSecrets
	var err error
	if gs.JoinerSecret, err = c.ReadOpaqueV(); err != nil {
		return gs, err
	}
	present, err := c.ReadUint8()
	if err != nil {
		return gs, err
	}
	switch present {
	case 0:
		// absent
	case 1:
		ps, err := decodePathSecret(c)
		if err != nil {
			return gs, err
		}
		gs.PathSecret = &ps
	default:
		return gs, fmt.Errorf("group: invalid optional<PathSecret> presence %d", present)
	}
	if gs.PSKs, err = syntax.ReadVectorV(c, keyschedule.DecodePreSharedKeyID); err != nil {
		return gs, err
	}
	return gs, nil
}

// MarshalMLS encodes the GroupSecrets.
func (gs GroupSecrets) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := gs.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a GroupSecrets, rejecting trailing bytes.
func (gs *GroupSecrets) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeGroupSecrets(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("group: trailing bytes after GroupSecrets")
	}
	*gs = v
	return nil
}

// EncryptedGroupSecrets pairs a KeyPackageRef with its HPKE-encrypted GroupSecrets
// (RFC 9420 §12.4.3.1).
type EncryptedGroupSecrets struct {
	NewMember             []byte              // KeyPackageRef opaque<V>
	EncryptedGroupSecrets tree.HPKECiphertext // { kem_output<V>; ciphertext<V> }
}

func (egs EncryptedGroupSecrets) marshal(b *syntax.Builder) error {
	if err := b.WriteOpaqueV(egs.NewMember); err != nil {
		return err
	}
	return egs.EncryptedGroupSecrets.MarshalTo(b)
}

func decodeEncryptedGroupSecrets(c *syntax.Cursor) (EncryptedGroupSecrets, error) {
	var egs EncryptedGroupSecrets
	var err error
	if egs.NewMember, err = c.ReadOpaqueV(); err != nil {
		return egs, err
	}
	if egs.EncryptedGroupSecrets, err = tree.DecodeHPKECiphertext(c); err != nil {
		return egs, err
	}
	return egs, nil
}

// MarshalMLS encodes the EncryptedGroupSecrets.
func (egs EncryptedGroupSecrets) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := egs.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes an EncryptedGroupSecrets, rejecting trailing bytes.
func (egs *EncryptedGroupSecrets) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeEncryptedGroupSecrets(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("group: trailing bytes after EncryptedGroupSecrets")
	}
	*egs = v
	return nil
}

// Welcome is the §12.4.3.1 Welcome message: a cipher suite, encrypted group
// secrets for each new member, and the AEAD-encrypted GroupInfo.
type Welcome struct {
	CipherSuite        cipher.CipherSuite
	Secrets            []EncryptedGroupSecrets
	EncryptedGroupInfo []byte // opaque<V>
}

func (w Welcome) marshal(b *syntax.Builder) error {
	b.WriteUint16(uint16(w.CipherSuite))
	if err := syntax.WriteVectorV(b, w.Secrets, func(b *syntax.Builder, egs EncryptedGroupSecrets) error {
		return egs.marshal(b)
	}); err != nil {
		return err
	}
	return b.WriteOpaqueV(w.EncryptedGroupInfo)
}

func decodeWelcome(c *syntax.Cursor) (Welcome, error) {
	var w Welcome
	cs, err := c.ReadUint16()
	if err != nil {
		return w, err
	}
	w.CipherSuite = cipher.CipherSuite(cs)
	if w.Secrets, err = syntax.ReadVectorV(c, decodeEncryptedGroupSecrets); err != nil {
		return w, err
	}
	if w.EncryptedGroupInfo, err = c.ReadOpaqueV(); err != nil {
		return w, err
	}
	return w, nil
}

// MarshalMLS encodes the Welcome.
func (w Welcome) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := w.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a Welcome, rejecting trailing bytes.
func (w *Welcome) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeWelcome(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("group: trailing bytes after Welcome")
	}
	*w = v
	return nil
}

// ─── MLSMessage envelope helpers ────────────────────────────────────────────

// decodeEnvelopeHeader reads and validates the 4-byte MLSMessage header
// (uint16 version, uint16 wire_format), returning an error if they don't match.
func decodeEnvelopeHeader(c *syntax.Cursor, expectedWireFormat uint16) error {
	ver, err := c.ReadUint16()
	if err != nil {
		return err
	}
	if ver != wireVersion {
		return fmt.Errorf("group: MLSMessage version %#x, want %#x", ver, wireVersion)
	}
	wf, err := c.ReadUint16()
	if err != nil {
		return err
	}
	if wf != expectedWireFormat {
		return fmt.Errorf("group: MLSMessage wire_format %#x, want %#x", wf, expectedWireFormat)
	}
	return nil
}

// writeEnvelopeHeader writes the 4-byte MLSMessage header.
func writeEnvelopeHeader(b *syntax.Builder, wireFormat uint16) {
	b.WriteUint16(wireVersion)
	b.WriteUint16(wireFormat)
}

// DecodeWelcomeMessage parses an MLSMessage envelope (ver=1, wf=0x0003) and
// returns the body Welcome.
func DecodeWelcomeMessage(data []byte) (Welcome, error) {
	c := syntax.NewCursor(data)
	if err := decodeEnvelopeHeader(c, wireFormatWelcome); err != nil {
		return Welcome{}, err
	}
	w, err := decodeWelcome(c)
	if err != nil {
		return Welcome{}, err
	}
	if !c.Empty() {
		return Welcome{}, fmt.Errorf("group: trailing bytes after Welcome envelope body")
	}
	return w, nil
}

// EncodeWelcomeMessage encodes a Welcome inside an MLSMessage envelope.
func EncodeWelcomeMessage(w Welcome) ([]byte, error) {
	b := syntax.NewBuilder()
	writeEnvelopeHeader(b, wireFormatWelcome)
	if err := w.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// DecodeGroupInfoMessage parses an MLSMessage envelope (ver=1, wf=0x0004).
func DecodeGroupInfoMessage(data []byte) (GroupInfo, error) {
	c := syntax.NewCursor(data)
	if err := decodeEnvelopeHeader(c, wireFormatGroupInfo); err != nil {
		return GroupInfo{}, err
	}
	gi, err := decodeGroupInfo(c)
	if err != nil {
		return GroupInfo{}, err
	}
	if !c.Empty() {
		return GroupInfo{}, fmt.Errorf("group: trailing bytes after GroupInfo envelope body")
	}
	return gi, nil
}

// EncodeGroupInfoMessage encodes a GroupInfo inside an MLSMessage envelope.
func EncodeGroupInfoMessage(gi GroupInfo) ([]byte, error) {
	b := syntax.NewBuilder()
	writeEnvelopeHeader(b, wireFormatGroupInfo)
	if err := gi.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// DecodeKeyPackageMessage parses an MLSMessage envelope (ver=1, wf=0x0005).
func DecodeKeyPackageMessage(data []byte) (KeyPackage, error) {
	c := syntax.NewCursor(data)
	if err := decodeEnvelopeHeader(c, wireFormatKeyPackage); err != nil {
		return KeyPackage{}, err
	}
	kp, err := decodeKeyPackage(c)
	if err != nil {
		return KeyPackage{}, err
	}
	if !c.Empty() {
		return KeyPackage{}, fmt.Errorf("group: trailing bytes after KeyPackage envelope body")
	}
	return kp, nil
}

// EncodeKeyPackageMessage encodes a KeyPackage inside an MLSMessage envelope.
func EncodeKeyPackageMessage(kp KeyPackage) ([]byte, error) {
	b := syntax.NewBuilder()
	writeEnvelopeHeader(b, wireFormatKeyPackage)
	if err := kp.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
