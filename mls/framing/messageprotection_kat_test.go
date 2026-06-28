package framing_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/framing"
	"github.com/trevex/mls-go/mls/internal/katutil"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/tree"
)

type mpVector struct {
	CipherSuite             uint16           `json:"cipher_suite"`
	GroupID                 katutil.HexBytes `json:"group_id"`
	Epoch                   uint64           `json:"epoch"`
	TreeHash                katutil.HexBytes `json:"tree_hash"`
	ConfirmedTranscriptHash katutil.HexBytes `json:"confirmed_transcript_hash"`
	SignaturePriv           katutil.HexBytes `json:"signature_priv"`
	SignaturePub            katutil.HexBytes `json:"signature_pub"`
	EncryptionSecret        katutil.HexBytes `json:"encryption_secret"`
	SenderDataSecret        katutil.HexBytes `json:"sender_data_secret"`
	MembershipKey           katutil.HexBytes `json:"membership_key"`
	Proposal                katutil.HexBytes `json:"proposal"`
	ProposalPub             katutil.HexBytes `json:"proposal_pub"`
	ProposalPriv            katutil.HexBytes `json:"proposal_priv"`
	Commit                  katutil.HexBytes `json:"commit"`
	CommitPub               katutil.HexBytes `json:"commit_pub"`
	CommitPriv              katutil.HexBytes `json:"commit_priv"`
	Application             katutil.HexBytes `json:"application"`
	ApplicationPriv         katutil.HexBytes `json:"application_priv"`
}

// senderLeaf is the RFC message-protection KAT group: 2-member group with the
// sender at leaf index 1.
const senderLeaf uint32 = 1

// buildSigner constructs a crypto.Signer from the vector's raw private key
// bytes for the suite's signature scheme. Ed25519: 32-byte seed. P-256: big-
// endian scalar (parsed via ecdsa.ParseRawPrivateKey).
func buildSigner(t *testing.T, s cipher.Suite, priv []byte) crypto.Signer {
	t.Helper()
	switch s.Sig {
	case cipher.SigEd25519:
		return ed25519.NewKeyFromSeed(priv)
	case cipher.SigECDSAP256:
		sk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), priv)
		if err != nil {
			t.Fatalf("buildSigner P-256: %v", err)
		}
		return sk
	default:
		t.Fatalf("buildSigner: unsupported sig scheme %v", s.Sig)
		return nil
	}
}

// makeSecretTree builds a fresh SecretTree for the 2-leaf KAT group.
func makeSecretTree(t *testing.T, suite cipher.Suite, encryptionSecret []byte) *keyschedule.SecretTree {
	t.Helper()
	st, err := keyschedule.NewSecretTree(suite, 2, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	return st
}

// checkPublicUnprotect decodes a PublicMessage MLSMessage blob, calls
// UnprotectPublic, and asserts that the recovered content equals want.
// It returns the AuthenticatedContent so the caller can reuse the
// confirmation_tag for the round-trip.
func checkPublicUnprotect(t *testing.T, suite cipher.Suite, blob, want []byte,
	signaturePub, membershipKey []byte, gc *keyschedule.GroupContext) framing.AuthenticatedContent {
	t.Helper()
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(blob); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	if m.WireFormat != framing.WireFormatPublicMessage || m.Public == nil {
		t.Fatalf("expected public message, got wire_format=%v", m.WireFormat)
	}
	ac, err := framing.UnprotectPublic(suite, signaturePub, gc, membershipKey, *m.Public)
	if err != nil {
		t.Fatalf("UnprotectPublic: %v", err)
	}
	if !bytes.Equal(ac.Content.Content, want) {
		t.Fatalf("content mismatch: got %x want %x", ac.Content.Content, want)
	}
	return ac
}

// checkPublicRoundTrip protects fc as a PublicMessage, marshals it, parses it
// back, and asserts that UnprotectPublic recovers content equal to want.
func checkPublicRoundTrip(t *testing.T, suite cipher.Suite, signer crypto.Signer,
	want, signaturePub, membershipKey []byte, gc *keyschedule.GroupContext,
	fc framing.FramedContent, confirmationTag []byte) {
	t.Helper()
	pm, err := framing.ProtectPublic(suite, signer, gc, membershipKey, fc, confirmationTag)
	if err != nil {
		t.Fatalf("ProtectPublic: %v", err)
	}
	out, err := framing.MLSMessage{
		Version:    tree.ProtocolVersionMLS10,
		WireFormat: framing.WireFormatPublicMessage,
		Public:     &pm,
	}.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	var m2 framing.MLSMessage
	if err := m2.UnmarshalMLS(out); err != nil {
		t.Fatalf("UnmarshalMLS round-trip: %v", err)
	}
	ac2, err := framing.UnprotectPublic(suite, signaturePub, gc, membershipKey, *m2.Public)
	if err != nil {
		t.Fatalf("UnprotectPublic round-trip: %v", err)
	}
	if !bytes.Equal(ac2.Content.Content, want) {
		t.Fatalf("round-trip content mismatch: got %x want %x", ac2.Content.Content, want)
	}
}

// checkPrivateUnprotect decodes a PrivateMessage MLSMessage blob, calls
// UnprotectPrivate, and asserts that the recovered content equals want.
// It returns the AuthenticatedContent so the caller can reuse
// confirmation_tag for the round-trip.
func checkPrivateUnprotect(t *testing.T, suite cipher.Suite, blob, want []byte,
	pubOf func(uint32) ([]byte, error), gc *keyschedule.GroupContext,
	st *keyschedule.SecretTree, senderDataSecret []byte) framing.AuthenticatedContent {
	t.Helper()
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(blob); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	if m.WireFormat != framing.WireFormatPrivateMessage || m.Private == nil {
		t.Fatalf("expected private message, got wire_format=%v", m.WireFormat)
	}
	ac, err := framing.UnprotectPrivate(suite, pubOf, gc, st, senderDataSecret, *m.Private)
	if err != nil {
		t.Fatalf("UnprotectPrivate: %v", err)
	}
	if !bytes.Equal(ac.Content.Content, want) {
		t.Fatalf("content mismatch: got %x want %x", ac.Content.Content, want)
	}
	return ac
}

// checkPrivateRoundTrip protects fc as a PrivateMessage, marshals it, parses
// it back, and asserts that UnprotectPrivate recovers content equal to want.
func checkPrivateRoundTrip(t *testing.T, suite cipher.Suite, signer crypto.Signer,
	want []byte, pubOf func(uint32) ([]byte, error),
	gc *keyschedule.GroupContext, encryptionSecret, senderDataSecret []byte,
	fc framing.FramedContent, confirmationTag []byte) {
	t.Helper()
	var guard [4]byte
	if _, err := rand.Read(guard[:]); err != nil {
		t.Fatal(err)
	}
	pm, err := framing.ProtectPrivate(suite, signer, gc,
		makeSecretTree(t, suite, encryptionSecret),
		senderDataSecret, fc, 0, guard, 0, confirmationTag)
	if err != nil {
		t.Fatalf("ProtectPrivate: %v", err)
	}
	out, err := framing.MLSMessage{
		Version:    tree.ProtocolVersionMLS10,
		WireFormat: framing.WireFormatPrivateMessage,
		Private:    &pm,
	}.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	var m2 framing.MLSMessage
	if err := m2.UnmarshalMLS(out); err != nil {
		t.Fatalf("UnmarshalMLS round-trip: %v", err)
	}
	ac2, err := framing.UnprotectPrivate(suite, pubOf, gc,
		makeSecretTree(t, suite, encryptionSecret),
		senderDataSecret, *m2.Private)
	if err != nil {
		t.Fatalf("UnprotectPrivate round-trip: %v", err)
	}
	if !bytes.Equal(ac2.Content.Content, want) {
		t.Fatalf("round-trip content mismatch: got %x want %x", ac2.Content.Content, want)
	}
}

// TestMessageProtectionKAT is the authoritative acceptance test for RFC 9420
// §6 message framing. It loads the vendored message-protection.json vectors,
// skips unregistered suites (3–7), and for each registered suite (1 and 2):
//
//  1. Verifies UnprotectPublic on the vendor proposal_pub / commit_pub blobs.
//  2. Verifies UnprotectPrivate on the vendor application_priv / proposal_priv /
//     commit_priv blobs.
//  3. Round-trips ProtectPublic → serialize → parse → UnprotectPublic for
//     proposal and commit.
//  4. Round-trips ProtectPrivate → serialize → parse → UnprotectPrivate for
//     application, proposal, and commit.
func TestMessageProtectionKAT(t *testing.T) {
	var vectors []mpVector
	katutil.Load(t, "message-protection.json", &vectors)

	executed := 0
	for i, v := range vectors {
		suite, ok := cipher.Lookup(cipher.CipherSuite(v.CipherSuite))
		if !ok {
			continue // unregistered suite (3–7)
		}
		executed++

		gc := &keyschedule.GroupContext{
			Version:                 tree.ProtocolVersionMLS10,
			CipherSuite:             cipher.CipherSuite(v.CipherSuite),
			GroupID:                 v.GroupID,
			Epoch:                   v.Epoch,
			TreeHash:                v.TreeHash,
			ConfirmedTranscriptHash: v.ConfirmedTranscriptHash,
		}
		signer := buildSigner(t, suite, v.SignaturePriv)
		pubOf := func(uint32) ([]byte, error) { return v.SignaturePub, nil }

		// ── PublicMessage: proposal ──────────────────────────────────────────
		t.Run(fmt.Sprintf("case%d_suite%d_proposal_pub", i, v.CipherSuite), func(t *testing.T) {
			ac := checkPublicUnprotect(t, suite, v.ProposalPub, v.Proposal,
				v.SignaturePub, v.MembershipKey, gc)
			fc := framing.FramedContent{
				GroupID:     v.GroupID,
				Epoch:       v.Epoch,
				Sender:      framing.Sender{Type: framing.SenderTypeMember, LeafIndex: senderLeaf},
				ContentType: framing.ContentTypeProposal,
				Content:     v.Proposal,
			}
			checkPublicRoundTrip(t, suite, signer, v.Proposal,
				v.SignaturePub, v.MembershipKey, gc, fc, ac.Auth.ConfirmationTag)
		})

		// ── PublicMessage: commit ────────────────────────────────────────────
		t.Run(fmt.Sprintf("case%d_suite%d_commit_pub", i, v.CipherSuite), func(t *testing.T) {
			ac := checkPublicUnprotect(t, suite, v.CommitPub, v.Commit,
				v.SignaturePub, v.MembershipKey, gc)
			fc := framing.FramedContent{
				GroupID:     v.GroupID,
				Epoch:       v.Epoch,
				Sender:      framing.Sender{Type: framing.SenderTypeMember, LeafIndex: senderLeaf},
				ContentType: framing.ContentTypeCommit,
				Content:     v.Commit,
			}
			checkPublicRoundTrip(t, suite, signer, v.Commit,
				v.SignaturePub, v.MembershipKey, gc, fc, ac.Auth.ConfirmationTag)
		})

		// ── PrivateMessage: application ──────────────────────────────────────
		t.Run(fmt.Sprintf("case%d_suite%d_application_priv", i, v.CipherSuite), func(t *testing.T) {
			ac := checkPrivateUnprotect(t, suite, v.ApplicationPriv, v.Application,
				pubOf, gc, makeSecretTree(t, suite, v.EncryptionSecret), v.SenderDataSecret)
			fc := framing.FramedContent{
				GroupID:     v.GroupID,
				Epoch:       v.Epoch,
				Sender:      framing.Sender{Type: framing.SenderTypeMember, LeafIndex: senderLeaf},
				ContentType: framing.ContentTypeApplication,
				Content:     v.Application,
			}
			checkPrivateRoundTrip(t, suite, signer, v.Application, pubOf, gc,
				v.EncryptionSecret, v.SenderDataSecret, fc, ac.Auth.ConfirmationTag)
		})

		// ── PrivateMessage: proposal ─────────────────────────────────────────
		t.Run(fmt.Sprintf("case%d_suite%d_proposal_priv", i, v.CipherSuite), func(t *testing.T) {
			ac := checkPrivateUnprotect(t, suite, v.ProposalPriv, v.Proposal,
				pubOf, gc, makeSecretTree(t, suite, v.EncryptionSecret), v.SenderDataSecret)
			fc := framing.FramedContent{
				GroupID:     v.GroupID,
				Epoch:       v.Epoch,
				Sender:      framing.Sender{Type: framing.SenderTypeMember, LeafIndex: senderLeaf},
				ContentType: framing.ContentTypeProposal,
				Content:     v.Proposal,
			}
			checkPrivateRoundTrip(t, suite, signer, v.Proposal, pubOf, gc,
				v.EncryptionSecret, v.SenderDataSecret, fc, ac.Auth.ConfirmationTag)
		})

		// ── PrivateMessage: commit ───────────────────────────────────────────
		t.Run(fmt.Sprintf("case%d_suite%d_commit_priv", i, v.CipherSuite), func(t *testing.T) {
			ac := checkPrivateUnprotect(t, suite, v.CommitPriv, v.Commit,
				pubOf, gc, makeSecretTree(t, suite, v.EncryptionSecret), v.SenderDataSecret)
			fc := framing.FramedContent{
				GroupID:     v.GroupID,
				Epoch:       v.Epoch,
				Sender:      framing.Sender{Type: framing.SenderTypeMember, LeafIndex: senderLeaf},
				ContentType: framing.ContentTypeCommit,
				Content:     v.Commit,
			}
			checkPrivateRoundTrip(t, suite, signer, v.Commit, pubOf, gc,
				v.EncryptionSecret, v.SenderDataSecret, fc, ac.Auth.ConfirmationTag)
		})
	}

	if executed == 0 {
		t.Fatal("no registered cipher suites exercised")
	}
}
