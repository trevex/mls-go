package framing

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/syntax"
)

// PrivateMessage is an AEAD-protected framed message (RFC 9420 §6.3).
type PrivateMessage struct {
	GroupID             []byte
	Epoch               uint64
	ContentType         ContentType
	AuthenticatedData   []byte
	EncryptedSenderData []byte
	Ciphertext          []byte
}

func (m PrivateMessage) marshal(b *syntax.Builder) error {
	if err := b.WriteOpaqueV(m.GroupID); err != nil {
		return err
	}
	b.WriteUint64(m.Epoch)
	b.WriteUint8(uint8(m.ContentType))
	if err := b.WriteOpaqueV(m.AuthenticatedData); err != nil {
		return err
	}
	if err := b.WriteOpaqueV(m.EncryptedSenderData); err != nil {
		return err
	}
	return b.WriteOpaqueV(m.Ciphertext)
}

func decodePrivateMessage(c *syntax.Cursor) (PrivateMessage, error) {
	var m PrivateMessage
	var err error
	if m.GroupID, err = c.ReadOpaqueV(); err != nil {
		return m, err
	}
	if m.Epoch, err = c.ReadUint64(); err != nil {
		return m, err
	}
	ct, err := c.ReadUint8()
	if err != nil {
		return m, err
	}
	m.ContentType = ContentType(ct)
	if m.AuthenticatedData, err = c.ReadOpaqueV(); err != nil {
		return m, err
	}
	if m.EncryptedSenderData, err = c.ReadOpaqueV(); err != nil {
		return m, err
	}
	if m.Ciphertext, err = c.ReadOpaqueV(); err != nil {
		return m, err
	}
	return m, nil
}

// senderData is the per-message sender metadata encrypted into a PrivateMessage
// (RFC 9420 §6.3.2). reuse_guard is a fixed 4-byte array (no length prefix).
type senderData struct {
	LeafIndex  uint32
	Generation uint32
	ReuseGuard [4]byte
}

func (sd senderData) marshal(b *syntax.Builder) {
	b.WriteUint32(sd.LeafIndex)
	b.WriteUint32(sd.Generation)
	b.WriteRaw(sd.ReuseGuard[:])
}

func decodeSenderData(c *syntax.Cursor) (senderData, error) {
	var sd senderData
	var err error
	if sd.LeafIndex, err = c.ReadUint32(); err != nil {
		return sd, err
	}
	if sd.Generation, err = c.ReadUint32(); err != nil {
		return sd, err
	}
	g, err := c.ReadRaw(4)
	if err != nil {
		return sd, err
	}
	copy(sd.ReuseGuard[:], g)
	return sd, nil
}

func senderDataAAD(groupID []byte, epoch uint64, ct ContentType) ([]byte, error) {
	b := syntax.NewBuilder()
	if err := b.WriteOpaqueV(groupID); err != nil {
		return nil, err
	}
	b.WriteUint64(epoch)
	b.WriteUint8(uint8(ct))
	return b.Bytes(), nil
}

func privateContentAAD(groupID []byte, epoch uint64, ct ContentType, ad []byte) ([]byte, error) {
	b := syntax.NewBuilder()
	if err := b.WriteOpaqueV(groupID); err != nil {
		return nil, err
	}
	b.WriteUint64(epoch)
	b.WriteUint8(uint8(ct))
	if err := b.WriteOpaqueV(ad); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ratchetTypeFor selects the secret-tree ratchet for a content type
// (RFC 9420 §6.3.1/§9.1): application -> application ratchet; proposal/commit
// (handshake) -> handshake ratchet.
func ratchetTypeFor(ct ContentType) keyschedule.RatchetType {
	if ct == ContentTypeApplication {
		return keyschedule.ApplicationRatchet
	}
	return keyschedule.HandshakeRatchet
}

// applyReuseGuard XORs the 4-byte reuse_guard into the first 4 bytes of the
// ratchet nonce (RFC 9420 §6.3.1).
func applyReuseGuard(nonce []byte, guard [4]byte) []byte {
	n := append([]byte(nil), nonce...)
	for i := 0; i < 4; i++ {
		n[i] ^= guard[i]
	}
	return n
}

// privateMessageContent serializes content || auth || padding (RFC 9420 §6.3.1).
func privateMessageContent(fc FramedContent, auth FramedContentAuthData, paddingSize int) ([]byte, error) {
	b := syntax.NewBuilder()
	if err := marshalContent(b, fc.ContentType, fc.Content); err != nil {
		return nil, err
	}
	if err := auth.marshal(b, fc.ContentType); err != nil {
		return nil, err
	}
	if paddingSize > 0 {
		b.WriteRaw(make([]byte, paddingSize))
	}
	return b.Bytes(), nil
}

// decodePrivateMessageContent parses content || auth || zero-padding.
func decodePrivateMessageContent(pt []byte, ct ContentType) ([]byte, FramedContentAuthData, error) {
	c := syntax.NewCursor(pt)
	content, err := decodeContent(c, ct)
	if err != nil {
		return nil, FramedContentAuthData{}, err
	}
	auth, err := decodeFramedContentAuthData(c, ct)
	if err != nil {
		return nil, FramedContentAuthData{}, err
	}
	for _, x := range c.Rest() {
		if x != 0 {
			return nil, FramedContentAuthData{}, errors.New("framing: non-zero padding in PrivateMessageContent")
		}
	}
	return content, auth, nil
}

// sealPrivate performs the two AEAD steps of PrivateMessage construction
// (RFC 9420 §6.3.1–§6.3.2): content encryption with the ratchet key/nonce
// (guarded by reuse_guard), then sender-data encryption. The caller supplies
// the already-built auth so this helper can be shared by ProtectPrivate and
// AssembleCommitPrivate.
func sealPrivate(suite cipher.Suite, st *keyschedule.SecretTree, senderDataSecret []byte, fc FramedContent, auth FramedContentAuthData, generation uint32, reuseGuard [4]byte, paddingSize int) (PrivateMessage, error) {
	// 1. Content AEAD with the ratchet key/nonce (guarded by reuse_guard).
	key, nonce, err := st.KeyNonce(fc.Sender.LeafIndex, ratchetTypeFor(fc.ContentType), generation)
	if err != nil {
		return PrivateMessage{}, err
	}
	contentAAD, err := privateContentAAD(fc.GroupID, fc.Epoch, fc.ContentType, fc.AuthenticatedData)
	if err != nil {
		return PrivateMessage{}, err
	}
	pt, err := privateMessageContent(fc, auth, paddingSize)
	if err != nil {
		return PrivateMessage{}, err
	}
	ciphertext, err := suite.Seal(key, applyReuseGuard(nonce, reuseGuard), contentAAD, pt)
	if err != nil {
		return PrivateMessage{}, err
	}
	// 2. Sender-data AEAD (key/nonce sampled from the content ciphertext).
	sdKey, sdNonce, err := keyschedule.SenderDataKeyNonce(suite, senderDataSecret, ciphertext)
	if err != nil {
		return PrivateMessage{}, err
	}
	sdAAD, err := senderDataAAD(fc.GroupID, fc.Epoch, fc.ContentType)
	if err != nil {
		return PrivateMessage{}, err
	}
	sdb := syntax.NewBuilder()
	senderData{LeafIndex: fc.Sender.LeafIndex, Generation: generation, ReuseGuard: reuseGuard}.marshal(sdb)
	encSD, err := suite.Seal(sdKey, sdNonce, sdAAD, sdb.Bytes())
	if err != nil {
		return PrivateMessage{}, err
	}
	return PrivateMessage{
		GroupID:             fc.GroupID,
		Epoch:               fc.Epoch,
		ContentType:         fc.ContentType,
		AuthenticatedData:   fc.AuthenticatedData,
		EncryptedSenderData: encSD,
		Ciphertext:          ciphertext,
	}, nil
}

// ProtectPrivate encrypts fc as a PrivateMessage (RFC 9420 §6.3). The sender's
// leaf index is taken from fc.Sender (must be a member). st provides the
// content key/nonce at (leaf, ratchet, generation); senderDataSecret derives
// the sender-data key/nonce. confirmationTag is used only for commit content.
func ProtectPrivate(suite cipher.Suite, signer crypto.Signer, gc *keyschedule.GroupContext, st *keyschedule.SecretTree, senderDataSecret []byte, fc FramedContent, generation uint32, reuseGuard [4]byte, paddingSize int, confirmationTag []byte) (PrivateMessage, error) {
	if fc.Sender.Type != SenderTypeMember {
		return PrivateMessage{}, fmt.Errorf("framing: PrivateMessage requires a member sender, got %v", fc.Sender.Type)
	}
	// 1. Sign the content.
	ac := AuthenticatedContent{WireFormat: WireFormatPrivateMessage, Content: fc}
	if fc.ContentType == ContentTypeCommit {
		ac.Auth.ConfirmationTag = confirmationTag
	}
	if err := ac.sign(suite, signer, gc); err != nil {
		return PrivateMessage{}, err
	}
	// 2–3. AEAD encrypt the content and sender data.
	return sealPrivate(suite, st, senderDataSecret, fc, ac.Auth, generation, reuseGuard, paddingSize)
}

// AssembleCommitPrivate builds a PrivateMessage from a precomputed signature
// and confirmation_tag, bypassing the signing step. The signature must already
// be bound to WireFormatPrivateMessage (e.g. from SignCommit with that wire
// format). This mirrors AssembleCommitPublic for the private wire format
// (RFC 9420 §6.3).
// reuseGuard must be a fresh uniformly random [4]byte per message (RFC 9420 §6.3.1).
func AssembleCommitPrivate(suite cipher.Suite, st *keyschedule.SecretTree, senderDataSecret []byte, fc FramedContent, generation uint32, reuseGuard [4]byte, paddingSize int, signature, confTag []byte) (PrivateMessage, error) {
	if fc.Sender.Type != SenderTypeMember {
		return PrivateMessage{}, fmt.Errorf("framing: AssembleCommitPrivate requires a member sender, got %v", fc.Sender.Type)
	}
	auth := FramedContentAuthData{Signature: signature, ConfirmationTag: confTag}
	return sealPrivate(suite, st, senderDataSecret, fc, auth, generation, reuseGuard, paddingSize)
}

// UnprotectPrivate decrypts the sender data, then the content, reconstructs the
// FramedContent, and verifies its signature (RFC 9420 §6.3). signaturePub maps
// a sender leaf index to its signature public key (the verifier looks this up
// from the ratchet tree in a live group).
func UnprotectPrivate(suite cipher.Suite, signaturePub func(leafIndex uint32) ([]byte, error), gc *keyschedule.GroupContext, st *keyschedule.SecretTree, senderDataSecret []byte, m PrivateMessage) (AuthenticatedContent, error) {
	// 1. Sender data.
	sdKey, sdNonce, err := keyschedule.SenderDataKeyNonce(suite, senderDataSecret, m.Ciphertext)
	if err != nil {
		return AuthenticatedContent{}, err
	}
	sdAAD, err := senderDataAAD(m.GroupID, m.Epoch, m.ContentType)
	if err != nil {
		return AuthenticatedContent{}, err
	}
	sdPlain, err := suite.Open(sdKey, sdNonce, sdAAD, m.EncryptedSenderData)
	if err != nil {
		return AuthenticatedContent{}, fmt.Errorf("framing: sender data open: %w", err)
	}
	sdc := syntax.NewCursor(sdPlain)
	sd, err := decodeSenderData(sdc)
	if err != nil {
		return AuthenticatedContent{}, err
	}
	if !sdc.Empty() {
		return AuthenticatedContent{}, errors.New("framing: trailing bytes after SenderData")
	}
	// 2. Content.
	key, nonce, err := st.KeyNonce(sd.LeafIndex, ratchetTypeFor(m.ContentType), sd.Generation)
	if err != nil {
		return AuthenticatedContent{}, err
	}
	contentAAD, err := privateContentAAD(m.GroupID, m.Epoch, m.ContentType, m.AuthenticatedData)
	if err != nil {
		return AuthenticatedContent{}, err
	}
	pt, err := suite.Open(key, applyReuseGuard(nonce, sd.ReuseGuard), contentAAD, m.Ciphertext)
	if err != nil {
		return AuthenticatedContent{}, fmt.Errorf("framing: content open: %w", err)
	}
	content, auth, err := decodePrivateMessageContent(pt, m.ContentType)
	if err != nil {
		return AuthenticatedContent{}, err
	}
	// 3. Reconstruct + verify.
	fc := FramedContent{
		GroupID:           m.GroupID,
		Epoch:             m.Epoch,
		Sender:            Sender{Type: SenderTypeMember, LeafIndex: sd.LeafIndex},
		AuthenticatedData: m.AuthenticatedData,
		ContentType:       m.ContentType,
		Content:           content,
	}
	ac := AuthenticatedContent{WireFormat: WireFormatPrivateMessage, Content: fc, Auth: auth}
	pub, err := signaturePub(sd.LeafIndex)
	if err != nil {
		return AuthenticatedContent{}, err
	}
	if !ac.verify(suite, pub, gc) {
		return AuthenticatedContent{}, errors.New("framing: signature verification failed")
	}
	return ac, nil
}
