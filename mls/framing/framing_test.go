package framing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

func TestFramedContentRoundTripProposal(t *testing.T) {
	fc := FramedContent{
		GroupID:           []byte{0xaa, 0xbb},
		Epoch:             0x121212,
		Sender:            Sender{Type: SenderTypeMember, LeafIndex: 1},
		AuthenticatedData: nil,
		ContentType:       ContentTypeProposal,
		Content:           []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x02}, // Remove(2)
	}
	b := syntax.NewBuilder()
	if err := fc.marshal(b); err != nil {
		t.Fatal(err)
	}
	got, err := decodeFramedContent(syntax.NewCursor(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Content, fc.Content) || got.ContentType != fc.ContentType ||
		got.Sender.LeafIndex != 1 || got.Epoch != fc.Epoch {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestFramedContentRoundTripApplication(t *testing.T) {
	fc := FramedContent{
		GroupID:           []byte{0x01, 0x02},
		Epoch:             7,
		Sender:            Sender{Type: SenderTypeMember, LeafIndex: 0},
		AuthenticatedData: []byte("aad"),
		ContentType:       ContentTypeApplication,
		Content:           []byte("hello world"),
	}
	b := syntax.NewBuilder()
	if err := fc.marshal(b); err != nil {
		t.Fatal(err)
	}
	got, err := decodeFramedContent(syntax.NewCursor(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Content, fc.Content) || got.ContentType != fc.ContentType {
		t.Fatalf("application round-trip mismatch: %+v", got)
	}
}

func TestFramedContentRoundTripCommit(t *testing.T) {
	// Commit = proposals<V>(empty) + optional<UpdatePath>(absent=0x00)
	commitContent := []byte{
		0x00, // varint length=0 for proposals<V>
		0x00, // optional<UpdatePath> absent
	}
	fc := FramedContent{
		GroupID:     []byte{0x03},
		Epoch:       42,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 2},
		ContentType: ContentTypeCommit,
		Content:     commitContent,
	}
	b := syntax.NewBuilder()
	if err := fc.marshal(b); err != nil {
		t.Fatal(err)
	}
	got, err := decodeFramedContent(syntax.NewCursor(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Content, fc.Content) || got.ContentType != fc.ContentType {
		t.Fatalf("commit round-trip mismatch: got %x want %x", got.Content, fc.Content)
	}
}

func TestFramedContentAuthSignVerify(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	gc := &keyschedule.GroupContext{
		Version:     tree.ProtocolVersionMLS10,
		CipherSuite: cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:     []byte{0x01},
		Epoch:       1,
	}

	fc := FramedContent{
		GroupID:     []byte{0x01},
		Epoch:       1,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 0},
		ContentType: ContentTypeProposal,
		Content:     []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x02},
	}
	ac := AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content:    fc,
	}
	if err := ac.sign(suite, priv, gc); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ac.verify(suite, pub, gc) {
		t.Fatal("verify returned false for a valid signature")
	}

	// Tamper: flip a content byte and verify must fail.
	ac2 := ac
	content2 := append([]byte(nil), ac.Content.Content...)
	content2[0] ^= 0xff
	ac2.Content.Content = content2
	if ac2.verify(suite, pub, gc) {
		t.Fatal("verify returned true after content tamper")
	}
}
