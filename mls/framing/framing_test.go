package framing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/syntax"
	"github.com/trevex/mls-go/mls/tree"
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

func TestFramedContentRoundTripAddProposal(t *testing.T) {
	// Build a minimal KeyPackage serialization (version, cipher_suite, init_key<V>,
	// leaf_node (inline), extensions<V>, signature<V>) without importing group.
	ln := tree.LeafNode{
		EncryptionKey:  []byte{0x01, 0x02, 0x03},
		SignatureKey:   []byte{0x04, 0x05, 0x06},
		Credential:     tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte("test")},
		Capabilities:   tree.Capabilities{},
		LeafNodeSource: tree.LeafNodeSourceKeyPackage,
		Lifetime:       &tree.Lifetime{NotBefore: 0, NotAfter: 0xffffffffffffffff},
		Extensions:     nil,
		Signature:      []byte{0xde, 0xad},
	}
	lnBytes, err := ln.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	// Build KeyPackage bytes manually: version(2) + cipher_suite(2) + init_key<V> + leaf_node(inline) + extensions<V> + signature<V>
	kpBuilder := syntax.NewBuilder()
	kpBuilder.WriteUint16(1)                       // version mls10
	kpBuilder.WriteUint16(1)                       // cipher_suite 0x0001
	_ = kpBuilder.WriteOpaqueV([]byte{0xab, 0xcd}) // init_key
	kpBuilder.WriteRaw(lnBytes)                    // leaf_node inline
	_ = kpBuilder.WriteOpaqueV([]byte{})           // extensions<V> empty
	_ = kpBuilder.WriteOpaqueV([]byte{0xbe, 0xef}) // signature<V>
	kpBytes := kpBuilder.Bytes()

	// Build Add proposal: 0x0001 (ProposalType add) + KeyPackage inline
	addBuilder := syntax.NewBuilder()
	addBuilder.WriteUint16(0x0001) // proposalTypeAdd
	addBuilder.WriteRaw(kpBytes)
	addContent := addBuilder.Bytes()

	fc := FramedContent{
		GroupID:     []byte{0x01},
		Epoch:       1,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 0},
		ContentType: ContentTypeProposal,
		Content:     addContent,
	}
	b := syntax.NewBuilder()
	if err := fc.marshal(b); err != nil {
		t.Fatal(err)
	}
	got, err := decodeFramedContent(syntax.NewCursor(b.Bytes()))
	if err != nil {
		t.Fatalf("decodeFramedContent: %v", err)
	}
	if !bytes.Equal(got.Content, fc.Content) || got.ContentType != fc.ContentType {
		t.Fatalf("Add proposal round-trip mismatch: got %x want %x", got.Content, fc.Content)
	}
}

func TestAuthenticatedContentMarshalMLS(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	_ = pub
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
		Content:     []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x02}, // Remove(2)
	}
	ac := AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content:    fc,
	}
	if err := ac.sign(suite, priv, gc); err != nil {
		t.Fatalf("sign: %v", err)
	}
	marshaled, err := ac.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	// Re-marshal and check byte equality
	marshaled2, err := ac.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS2: %v", err)
	}
	if !bytes.Equal(marshaled, marshaled2) {
		t.Fatalf("MarshalMLS not deterministic: %x vs %x", marshaled, marshaled2)
	}
	// The marshaled form must at least contain the wire_format uint16
	if len(marshaled) < 2 {
		t.Fatalf("MarshalMLS too short: %d bytes", len(marshaled))
	}
	wf := uint16(marshaled[0])<<8 | uint16(marshaled[1])
	if wf != uint16(WireFormatPublicMessage) {
		t.Fatalf("wire_format %#x, want %#x", wf, WireFormatPublicMessage)
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
