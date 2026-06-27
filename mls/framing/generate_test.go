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

// minimalCommitContent is the wire form of an empty Commit:
// proposals<V>=0x00 (empty vector) + optional<UpdatePath>=0x00 (absent).
var minimalCommitContent = []byte{0x00, 0x00}

// TestSignCommitConfirmedInput verifies that SignCommit's confirmedInput is
// byte-equal to what SplitAuthenticatedContent returns for the same message
// (RFC 9420 §8.2 / N6 of the plan).
func TestSignCommitConfirmedInput(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite not registered")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	gc := &keyschedule.GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:                 []byte("test-group"),
		Epoch:                   3,
		TreeHash:                make([]byte, 32),
		ConfirmedTranscriptHash: make([]byte, 32),
	}
	fc := FramedContent{
		GroupID:     []byte("test-group"),
		Epoch:       3,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 0},
		ContentType: ContentTypeCommit,
		Content:     minimalCommitContent,
	}

	confirmedInput, sig, err := SignCommit(suite, priv, gc, fc)
	if err != nil {
		t.Fatalf("SignCommit: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("SignCommit returned empty signature")
	}

	// Build an AuthenticatedContent with a placeholder confirmation_tag of the
	// right length (it is not included in confirmedInput).
	ac := AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content:    fc,
		Auth: FramedContentAuthData{
			Signature:       sig,
			ConfirmationTag: make([]byte, suite.HashLen()),
		},
	}
	acBytes, err := ac.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	wantInput, _, err := keyschedule.SplitAuthenticatedContent(suite, acBytes)
	if err != nil {
		t.Fatalf("SplitAuthenticatedContent: %v", err)
	}
	if !bytes.Equal(confirmedInput, wantInput) {
		t.Fatalf("confirmedInput mismatch:\n got  %x\n want %x", confirmedInput, wantInput)
	}
}

// TestAssembleCommitPublicRoundTrip verifies that a PublicMessage assembled via
// AssembleCommitPublic can be unprotected by UnprotectPublic (RFC 9420 §6.2).
func TestAssembleCommitPublicRoundTrip(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite not registered")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	membershipKey := make([]byte, suite.HashLen())
	if _, err := rand.Read(membershipKey); err != nil {
		t.Fatal(err)
	}

	gc := &keyschedule.GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:                 []byte("test-group"),
		Epoch:                   3,
		TreeHash:                make([]byte, 32),
		ConfirmedTranscriptHash: make([]byte, 32),
	}
	fc := FramedContent{
		GroupID:     []byte("test-group"),
		Epoch:       3,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 0},
		ContentType: ContentTypeCommit,
		Content:     minimalCommitContent,
	}

	// Step 1: sign the commit, getting the signature.
	_, sig, err := SignCommit(suite, priv, gc, fc)
	if err != nil {
		t.Fatalf("SignCommit: %v", err)
	}

	// Step 2: assemble the PublicMessage with a fixed confirmation tag.
	confTag := make([]byte, suite.HashLen())
	if _, err := rand.Read(confTag); err != nil {
		t.Fatal(err)
	}
	pm, err := AssembleCommitPublic(suite, gc, membershipKey, fc, sig, confTag)
	if err != nil {
		t.Fatalf("AssembleCommitPublic: %v", err)
	}

	// Step 3: unprotect and verify.
	ac2, err := UnprotectPublic(suite, pub, gc, membershipKey, pm)
	if err != nil {
		t.Fatalf("UnprotectPublic: %v", err)
	}
	if !bytes.Equal(ac2.Auth.ConfirmationTag, confTag) {
		t.Fatalf("confirmation_tag mismatch:\n got  %x\n want %x", ac2.Auth.ConfirmationTag, confTag)
	}
	if !bytes.Equal(ac2.Content.Content, minimalCommitContent) {
		t.Fatalf("content mismatch: got %x want %x", ac2.Content.Content, minimalCommitContent)
	}
}
