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
// PublicMessage unit tests (Task 3).
const (
	c0GroupID               = "42e4c3a73738d838cb4f9dc550cb81406206943f9e6870ee150f2000ae8aa780"
	c0Epoch          uint64 = 1184274
	c0TreeHash              = "a257a326c7b632ce7ccdea8d3a3b5c3c2daa53a21029b3673ee05e9a3cea5934"
	c0CTHash                = "59b10f7a137e853c4ef7ce43d2fe0a481bb80652f648c5efab11c3141a1ba60c"
	c0SignaturePub          = "62087f5b047e5292d5d29ded0977442788633c196a607988238b8c4374b4b4be"
	c0MembershipKey         = "1f338b39337d019ab52c797bc836875998387e88fe711287df2258bc8f9967fb"
	c0ProposalHex           = "000300000002"
	c0ProposalPubHex        = "000100012042e4c3a73738d838cb4f9dc550cb81406206943f9e6870ee150f2000ae8aa7800000000000121212010000000100020003000000024040932e43773e992f7b0c8ec9d82f72c9395ad62120f19a764e50ec150ca48ba94dbb139a1f9c6901aab353d67f97f68210027818f634ac9cf8a738fe35b7404906201be6bf2e5e22e38a6f908d534a04ae231c3f6de72750d74bbf626a2c0bfcf1ec"
	c0CommitHex             = "404601000401205ff3e28b8183cba127d0b74459b5d8a81286c299ba02d68c7d62f6101c3782dc20e0fbf69e4e80c4b2b8d43ffac9c0863a25300d0a6880aa9287d3916c467ae3ab00"
	c0CommitPubHex          = "000100012042e4c3a73738d838cb4f9dc550cb81406206943f9e6870ee150f2000ae8aa780000000000012121201000000010003404601000401205ff3e28b8183cba127d0b74459b5d8a81286c299ba02d68c7d62f6101c3782dc20e0fbf69e4e80c4b2b8d43ffac9c0863a25300d0a6880aa9287d3916c467ae3ab0040403fe4fb435c134950173cf4244a899e3a3fedb6d77dde1279b8a1b03a507109661d82e6e08f9a476ebad8983ce83a1218dbf4df0b538e88d3d8ffb0cbc5fffb0120b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad2096f30e3de73f8f49037897e7e2ff6964857d7e662c6823cea2b5c4b78c3b03a2"
)

// buildCase0GC builds the GroupContext for case 0 (suite 1).
func buildCase0GC(t *testing.T) *keyschedule.GroupContext {
	t.Helper()
	return &keyschedule.GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:                 mustHex(t, c0GroupID),
		Epoch:                   c0Epoch,
		TreeHash:                mustHex(t, c0TreeHash),
		ConfirmedTranscriptHash: mustHex(t, c0CTHash),
	}
}

// TestPublicMessageUnprotectProposal decodes the vendor proposal_pub blob and
// verifies that UnprotectPublic recovers the expected proposal bytes (RFC 9420
// §6.2 — signature and membership_tag both check).
func TestPublicMessageUnprotectProposal(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}
	gc := buildCase0GC(t)
	signaturePub := mustHex(t, c0SignaturePub)
	membershipKey := mustHex(t, c0MembershipKey)
	proposal := mustHex(t, c0ProposalHex)
	proposalPub := mustHex(t, c0ProposalPubHex)

	var m MLSMessage
	if err := m.UnmarshalMLS(proposalPub); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	if m.WireFormat != WireFormatPublicMessage || m.Public == nil {
		t.Fatalf("expected public message, got wire_format=%v", m.WireFormat)
	}
	ac, err := UnprotectPublic(suite, signaturePub, gc, membershipKey, *m.Public)
	if err != nil {
		t.Fatalf("UnprotectPublic: %v", err)
	}
	if !bytes.Equal(ac.Content.Content, proposal) {
		t.Fatalf("recovered proposal mismatch: got %x want %x", ac.Content.Content, proposal)
	}
}

// TestPublicMessageUnprotectCommit decodes the vendor commit_pub blob and
// verifies that UnprotectPublic recovers the expected commit bytes (RFC 9420
// §6.2 — signature, membership_tag, and confirmation_tag all present).
func TestPublicMessageUnprotectCommit(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}
	gc := buildCase0GC(t)
	signaturePub := mustHex(t, c0SignaturePub)
	membershipKey := mustHex(t, c0MembershipKey)
	commit := mustHex(t, c0CommitHex)
	commitPub := mustHex(t, c0CommitPubHex)

	var m MLSMessage
	if err := m.UnmarshalMLS(commitPub); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	if m.WireFormat != WireFormatPublicMessage || m.Public == nil {
		t.Fatalf("expected public message")
	}
	ac, err := UnprotectPublic(suite, signaturePub, gc, membershipKey, *m.Public)
	if err != nil {
		t.Fatalf("UnprotectPublic: %v", err)
	}
	if !bytes.Equal(ac.Content.Content, commit) {
		t.Fatalf("recovered commit mismatch: got %x want %x", ac.Content.Content, commit)
	}
}

// TestPublicMessageRoundTripProposal protects a proposal FramedContent with a
// fresh Ed25519 key, marshals it to an MLSMessage, parses it back, and verifies
// the recovered content equals the original (RFC 9420 §6.2).
func TestPublicMessageRoundTripProposal(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}
	gc := buildCase0GC(t)
	membershipKey := mustHex(t, c0MembershipKey)
	proposal := mustHex(t, c0ProposalHex)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	fc := FramedContent{
		GroupID:     mustHex(t, c0GroupID),
		Epoch:       c0Epoch,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 1},
		ContentType: ContentTypeProposal,
		Content:     proposal,
	}
	pm, err := ProtectPublic(suite, priv, gc, membershipKey, fc, nil)
	if err != nil {
		t.Fatalf("ProtectPublic: %v", err)
	}
	out, err := MLSMessage{
		Version:    tree.ProtocolVersionMLS10,
		WireFormat: WireFormatPublicMessage,
		Public:     &pm,
	}.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	var m2 MLSMessage
	if err := m2.UnmarshalMLS(out); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	ac2, err := UnprotectPublic(suite, pub, gc, membershipKey, *m2.Public)
	if err != nil {
		t.Fatalf("UnprotectPublic round-trip: %v", err)
	}
	if !bytes.Equal(ac2.Content.Content, proposal) {
		t.Fatalf("round-trip content mismatch: got %x want %x", ac2.Content.Content, proposal)
	}
}
