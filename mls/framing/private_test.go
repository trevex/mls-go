package framing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// case 0 (suite 1) values from message-protection.json used for the
// PrivateMessage unit tests (Task 4).
const (
	c0EncryptionSecret   = "4db33574f514024e61e2a15e71527182f62561d84b4d8230501b623d848df998"
	c0SenderDataSecret   = "b21dfbbf69da2fec93299d8bd0795ad0aec22b42d83ff10a2e5e3f997672b8b3"
	c0ApplicationHex     = "a1ab266714fdb6d121f4c7f248271fb824a3e61dd3f91835e68fc8789f17f754a86233781fb59d23811b"
	c0ApplicationPrivHex = "000100022042e4c3a73738d838cb4f9dc550cb81406206943f9e6870ee150f2000ae8aa780000000000012121201001cf18ad2e0ad4462390d72714d68b2a845ba336c3e8d398d21334f8d0f407dab47ce77c5fff3107b2f4e4bf99936c0ec680364333403663b7a955708a73d91e921a4fb3ffd50292a51ec31d4ec684231eb6f765cfbd5cca5b78fbe42bbf1b04dd1682fc87678b3a4f1599770839b171caff15e5e264957f3d16c31ba3ca16416f4665115244291536ddb438528cdb8502de654be9ca093915d36b1ab"
)

// TestPrivateMessageUnprotectApplication decodes the vendor application_priv
// blob and verifies that UnprotectPrivate recovers the expected application
// bytes (RFC 9420 §6.3 — sender data decrypted, content AEAD opened, signature
// verified).
func TestPrivateMessageUnprotectApplication(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}
	gc := buildCase0GC(t)
	signaturePub := mustHex(t, c0SignaturePub)
	encryptionSecret := mustHex(t, c0EncryptionSecret)
	senderDataSecret := mustHex(t, c0SenderDataSecret)
	application := mustHex(t, c0ApplicationHex)
	applicationPriv := mustHex(t, c0ApplicationPrivHex)

	st, err := keyschedule.NewSecretTree(suite, 2, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}

	var m MLSMessage
	if err := m.UnmarshalMLS(applicationPriv); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	if m.WireFormat != WireFormatPrivateMessage || m.Private == nil {
		t.Fatalf("expected private message, got wire_format=%v", m.WireFormat)
	}
	pubOf := func(uint32) ([]byte, error) { return signaturePub, nil }
	ac, err := UnprotectPrivate(suite, pubOf, gc, st, senderDataSecret, *m.Private)
	if err != nil {
		t.Fatalf("UnprotectPrivate: %v", err)
	}
	if !bytes.Equal(ac.Content.Content, application) {
		t.Fatalf("recovered application mismatch: got %x want %x", ac.Content.Content, application)
	}
}

// TestPrivateMessageRoundTripApplication re-encrypts the recovered application
// content with a fresh Ed25519 key, marshals the PrivateMessage, parses it
// back, and verifies the round-trip (RFC 9420 §6.3).
func TestPrivateMessageRoundTripApplication(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}
	gc := buildCase0GC(t)
	encryptionSecret := mustHex(t, c0EncryptionSecret)
	senderDataSecret := mustHex(t, c0SenderDataSecret)
	application := mustHex(t, c0ApplicationHex)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	fc := FramedContent{
		GroupID:     mustHex(t, c0GroupID),
		Epoch:       c0Epoch,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 1},
		ContentType: ContentTypeApplication,
		Content:     application,
	}

	var reuseGuard [4]byte
	if _, err := rand.Read(reuseGuard[:]); err != nil {
		t.Fatal(err)
	}

	stProtect, err := keyschedule.NewSecretTree(suite, 2, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree (protect): %v", err)
	}
	pm, err := ProtectPrivate(suite, priv, gc, stProtect, senderDataSecret, fc, 0, reuseGuard, 0, nil)
	if err != nil {
		t.Fatalf("ProtectPrivate: %v", err)
	}
	out, err := MLSMessage{
		Version:    tree.ProtocolVersionMLS10,
		WireFormat: WireFormatPrivateMessage,
		Private:    &pm,
	}.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	var m2 MLSMessage
	if err := m2.UnmarshalMLS(out); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	stUnprotect, err := keyschedule.NewSecretTree(suite, 2, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree (unprotect): %v", err)
	}
	pubOf := func(uint32) ([]byte, error) { return pub, nil }
	ac2, err := UnprotectPrivate(suite, pubOf, gc, stUnprotect, senderDataSecret, *m2.Private)
	if err != nil {
		t.Fatalf("UnprotectPrivate round-trip: %v", err)
	}
	if !bytes.Equal(ac2.Content.Content, application) {
		t.Fatalf("round-trip content mismatch: got %x want %x", ac2.Content.Content, application)
	}
}
