package group_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/framing"
	"github.com/trevex/mls-go/mls/group"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/tree"
)

// twoMemberGroup returns a committer (leaf 0) and a joiner (leaf 1) both at
// epoch 1, using the same setup pattern as TestActiveRoundTrip T1.
func twoMemberGroup(t *testing.T) (committer, joiner *group.Group) {
	t.Helper()
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite 1 not registered")
	}

	groupID := []byte("encrypted-handshake-test-group")

	aliceSigner := makeSigner(t)
	alice, err := group.NewGroup(suite, groupID, makeCred("alice"), aliceSigner, makeLifetime())
	if err != nil {
		t.Fatalf("twoMemberGroup: NewGroup(alice): %v", err)
	}

	bobSigner := makeSigner(t)
	bobKP, bobInitPriv, bobLeafPriv, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
	if err != nil {
		t.Fatalf("twoMemberGroup: NewKeyPackage(bob): %v", err)
	}
	bobKPMsg, err := group.EncodeKeyPackageMessage(bobKP)
	if err != nil {
		t.Fatalf("twoMemberGroup: EncodeKeyPackageMessage: %v", err)
	}

	_, welcomeMsg, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
	})
	if err != nil {
		t.Fatalf("twoMemberGroup: alice.Commit(Add bob): %v", err)
	}
	if len(welcomeMsg) == 0 {
		t.Fatal("twoMemberGroup: expected welcome, got empty")
	}

	bob, err := group.JoinFromWelcome(suite, welcomeMsg, group.JoinOptions{
		KeyPackage:     bobKPMsg,
		InitPriv:       bobInitPriv,
		EncryptionPriv: bobLeafPriv,
		Signer:         bobSigner,
		ExternalPSKs:   map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("twoMemberGroup: JoinFromWelcome(bob): %v", err)
	}

	return alice, bob
}

// makeSuiteSignerForTest generates a signer of the type required by suite.
func makeSuiteSignerForTest(t *testing.T, suite cipher.Suite) crypto.Signer {
	t.Helper()
	switch suite.Sig {
	case cipher.SigEd25519:
		return makeSigner(t)
	case cipher.SigECDSAP256:
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("makeSuiteSignerForTest: ecdsa.GenerateKey: %v", err)
		}
		return sk
	default:
		t.Fatalf("makeSuiteSignerForTest: unsupported signature scheme %d", suite.Sig)
		return nil
	}
}

// twoMemberGroupSuite creates a 2-member group (committer=leaf 0, joiner=leaf 1)
// at epoch 1 for an arbitrary cipher suite.
func twoMemberGroupSuite(t *testing.T, suiteID cipher.CipherSuite) (committer, joiner *group.Group) {
	t.Helper()
	suite, ok := cipher.Lookup(suiteID)
	if !ok {
		t.Skipf("suite %#x not registered", suiteID)
	}

	groupID := []byte("encrypted-handshake-multisuite-group")

	aliceSigner := makeSuiteSignerForTest(t, suite)
	alice, err := group.NewGroup(suite, groupID, makeCred("alice"), aliceSigner, makeLifetime())
	if err != nil {
		t.Fatalf("twoMemberGroupSuite(%#x): NewGroup(alice): %v", suiteID, err)
	}

	bobSigner := makeSuiteSignerForTest(t, suite)
	bobKP, bobInitPriv, bobLeafPriv, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
	if err != nil {
		t.Fatalf("twoMemberGroupSuite(%#x): NewKeyPackage(bob): %v", suiteID, err)
	}
	bobKPMsg, err := group.EncodeKeyPackageMessage(bobKP)
	if err != nil {
		t.Fatalf("twoMemberGroupSuite(%#x): EncodeKeyPackageMessage: %v", suiteID, err)
	}

	_, welcomeMsg, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
	})
	if err != nil {
		t.Fatalf("twoMemberGroupSuite(%#x): alice.Commit(Add bob): %v", suiteID, err)
	}
	if len(welcomeMsg) == 0 {
		t.Fatalf("twoMemberGroupSuite(%#x): expected welcome, got empty", suiteID)
	}

	bob, err := group.JoinFromWelcome(suite, welcomeMsg, group.JoinOptions{
		KeyPackage:     bobKPMsg,
		InitPriv:       bobInitPriv,
		EncryptionPriv: bobLeafPriv,
		Signer:         bobSigner,
		ExternalPSKs:   map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("twoMemberGroupSuite(%#x): JoinFromWelcome(bob): %v", suiteID, err)
	}

	return alice, bob
}

// TestEncryptedCommitIsPrivateMessage asserts that a commit produced by a
// member with encryptHandshakes=true is framed as a PrivateMessage.
func TestEncryptedCommitIsPrivateMessage(t *testing.T) {
	committer, _ := twoMemberGroup(t)

	committer.SetEncryptHandshakes(true)

	commit, _, err := committer.Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	var m framing.MLSMessage
	if err := m.UnmarshalMLS(commit); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}

	if m.WireFormat != framing.WireFormatPrivateMessage {
		t.Errorf("WireFormat = %v, want WireFormatPrivateMessage", m.WireFormat)
	}
	if m.Private == nil {
		t.Error("Private == nil, want non-nil PrivateMessage")
	}
}

// TestEncryptedCommitRoundTripAllSuites verifies that a PrivateMessage commit
// can be produced by the committer and successfully processed by the receiver
// on all three supported cipher suites (0x0001, 0x0002, 0xF001). After processing
// both members must share the same epoch and epoch_authenticator.
func TestEncryptedCommitRoundTripAllSuites(t *testing.T) {
	suites := []cipher.CipherSuite{
		cipher.X25519_AES128GCM_SHA256_Ed25519,
		cipher.P256_AES128GCM_SHA256_P256,
		cipher.XWING_AES256GCM_SHA256_Ed25519,
	}
	executed := 0
	for _, csID := range suites {
		csID := csID
		t.Run(fmt.Sprintf("suite-%#x", csID), func(t *testing.T) {
			committer, member := twoMemberGroupSuite(t, csID)
			executed++

			committer.SetEncryptHandshakes(true)

			commit, _, err := committer.Commit(group.CommitOptions{})
			if err != nil {
				t.Fatalf("suite %#x: Commit: %v", csID, err)
			}

			if err := member.ProcessCommit(nil, commit); err != nil {
				t.Fatalf("suite %#x: ProcessCommit: %v", csID, err)
			}

			if !bytes.Equal(member.EpochAuthenticator(), committer.EpochAuthenticator()) {
				t.Fatalf("suite %#x: epoch_authenticator mismatch\n  member   %x\n  committer %x",
					csID, member.EpochAuthenticator(), committer.EpochAuthenticator())
			}
			if member.Epoch() != committer.Epoch() {
				t.Fatalf("suite %#x: epoch mismatch: member=%d committer=%d",
					csID, member.Epoch(), committer.Epoch())
			}
			t.Logf("suite %#x: PrivateMessage commit round-trip OK, EA=%x", csID, committer.EpochAuthenticator())
		})
	}
	if executed == 0 {
		t.Fatal("no suites executed (all skipped)")
	}
}

// TestWireFormatBindsTranscript proves that wire_format is bound into the
// confirmed_transcript_hash by construction: the ONLY variable between the two
// SignCommit calls is the wire_format (same commit content, same signer, same
// prior interim hash).  Because independent random entropy is deliberately
// absent, any equality would be a genuine failure of the binding property.
func TestWireFormatBindsTranscript(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite 1 not registered")
	}

	// Same signer for both calls — Ed25519 is deterministic, so the only source
	// of divergence between the two confirmedInputs is the wire_format itself.
	signer := makeSigner(t)

	gc := keyschedule.GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:                 []byte("wire-format-binding-test-group"),
		Epoch:                   1,
		TreeHash:                make([]byte, suite.HashLen()),
		ConfirmedTranscriptHash: make([]byte, suite.HashLen()),
	}
	// Minimal well-formed commit: empty proposals<V> (0x00) + absent UpdatePath (0x00).
	fc := framing.FramedContent{
		GroupID:     gc.GroupID,
		Epoch:       gc.Epoch,
		Sender:      framing.Sender{Type: framing.SenderTypeMember, LeafIndex: 0},
		ContentType: framing.ContentTypeCommit,
		Content:     []byte{0x00, 0x00},
	}

	pubInput, _, err := framing.SignCommit(suite, signer, &gc, fc, framing.WireFormatPublicMessage)
	if err != nil {
		t.Fatalf("SignCommit(public): %v", err)
	}
	privInput, _, err := framing.SignCommit(suite, signer, &gc, fc, framing.WireFormatPrivateMessage)
	if err != nil {
		t.Fatalf("SignCommit(private): %v", err)
	}

	// Same fixed interim hash for both — any difference in the resulting
	// confirmed_transcript_hash is solely due to the wire_format binding.
	interim := make([]byte, suite.HashLen())
	pubHash := keyschedule.ConfirmedTranscriptHash(suite, interim, pubInput)
	privHash := keyschedule.ConfirmedTranscriptHash(suite, interim, privInput)
	if bytes.Equal(pubHash, privHash) {
		t.Fatal("confirmed_transcript_hash identical across wire formats — wire_format not bound")
	}
	t.Logf("wire_format correctly bound in transcript: pubHash=%x privHash=%x", pubHash, privHash)
}

// TestEncryptedCommitTamperRejected verifies that a bit-flip in the commit
// ciphertext is detected and rejected by ProcessCommit.
func TestEncryptedCommitTamperRejected(t *testing.T) {
	committer, member := twoMemberGroup(t)

	committer.SetEncryptHandshakes(true)

	commit, _, err := committer.Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Flip the last byte to simulate tampering.
	tampered := make([]byte, len(commit))
	copy(tampered, commit)
	tampered[len(tampered)-1] ^= 0xFF

	if err := member.ProcessCommit(nil, tampered); err == nil {
		t.Fatal("ProcessCommit accepted a tampered PrivateMessage commit, expected error")
	} else {
		t.Logf("tampered commit correctly rejected: %v", err)
	}
}

// TestEncryptedByReferenceProposal verifies that when encryptHandshakes is true
// FrameProposal produces a PrivateMessage, and that Commit and ProcessCommit
// both handle by-reference private proposals correctly. After processing both
// members must share the same epoch_authenticator. Runs over suites 0x0001,
// 0x0002, and 0xF001.
func TestEncryptedByReferenceProposal(t *testing.T) {
	suites := []cipher.CipherSuite{
		cipher.X25519_AES128GCM_SHA256_Ed25519,
		cipher.P256_AES128GCM_SHA256_P256,
		cipher.XWING_AES256GCM_SHA256_Ed25519,
	}
	for _, id := range suites {
		id := id
		t.Run(fmt.Sprintf("suite-%#x", id), func(t *testing.T) {
			committer, member := twoMemberGroupSuite(t, id)
			committer.SetEncryptHandshakes(true)
			member.SetEncryptHandshakes(true)

			// Member (leaf 1) proposes an update.
			upd, err := member.ProposeUpdate()
			if err != nil {
				t.Fatalf("ProposeUpdate: %v", err)
			}
			propMsg, err := member.FrameProposal(upd)
			if err != nil {
				t.Fatalf("FrameProposal: %v", err)
			}

			// Assert propMsg is a PrivateMessage.
			var m framing.MLSMessage
			if err := m.UnmarshalMLS(propMsg); err != nil {
				t.Fatalf("UnmarshalMLS(propMsg): %v", err)
			}
			if m.WireFormat != framing.WireFormatPrivateMessage {
				t.Errorf("propMsg WireFormat = %v, want WireFormatPrivateMessage", m.WireFormat)
			}

			// Committer commits the by-reference private proposal.
			commit, _, err := committer.Commit(group.CommitOptions{ByReference: [][]byte{propMsg}})
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}

			// Member processes the commit.
			if err := member.ProcessCommit([][]byte{propMsg}, commit); err != nil {
				t.Fatalf("ProcessCommit: %v", err)
			}

			// Both must converge on the same epoch_authenticator.
			if !bytes.Equal(member.EpochAuthenticator(), committer.EpochAuthenticator()) {
				t.Fatalf("epoch_authenticator mismatch\n  member    %x\n  committer %x",
					member.EpochAuthenticator(), committer.EpochAuthenticator())
			}
			t.Logf("suite %#x: encrypted by-reference proposal round-trip OK, EA=%x", id, committer.EpochAuthenticator())
		})
	}
}

// TestEncryptedByReferenceProposalTamperRejected verifies that a tampered
// private by-reference proposal is rejected by Commit. A bit-flip in the last
// byte of the proposal ciphertext must produce a non-nil error.
func TestEncryptedByReferenceProposalTamperRejected(t *testing.T) {
	committer, member := twoMemberGroup(t)
	committer.SetEncryptHandshakes(true)
	member.SetEncryptHandshakes(true)

	// Member (leaf 1) frames a private Update proposal.
	upd, err := member.ProposeUpdate()
	if err != nil {
		t.Fatalf("ProposeUpdate: %v", err)
	}
	propMsg, err := member.FrameProposal(upd)
	if err != nil {
		t.Fatalf("FrameProposal: %v", err)
	}

	// Flip the last byte of a copy to simulate tampering.
	tampered := append([]byte(nil), propMsg...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, _, err := committer.Commit(group.CommitOptions{ByReference: [][]byte{tampered}}); err == nil {
		t.Fatal("Commit accepted a tampered private by-reference proposal, want error")
	} else {
		t.Logf("tampered private by-reference proposal correctly rejected: %v", err)
	}
}

// TestMixedPublicPrivateSequence exercises a mixed sequence of public and
// private commits: committer sends A (public), then B and C (private). Member
// processes all three. Final epoch_authenticators must converge.
func TestMixedPublicPrivateSequence(t *testing.T) {
	committer, member := twoMemberGroup(t)

	// Commit A: public (default).
	commitA, _, err := committer.Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("Commit A (public): %v", err)
	}
	if err := member.ProcessCommit(nil, commitA); err != nil {
		t.Fatalf("ProcessCommit A: %v", err)
	}
	if !bytes.Equal(member.EpochAuthenticator(), committer.EpochAuthenticator()) {
		t.Fatalf("after commit A: epoch_authenticator mismatch")
	}

	// Commit B: private.
	committer.SetEncryptHandshakes(true)
	commitB, _, err := committer.Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("Commit B (private): %v", err)
	}
	if err := member.ProcessCommit(nil, commitB); err != nil {
		t.Fatalf("ProcessCommit B: %v", err)
	}
	if !bytes.Equal(member.EpochAuthenticator(), committer.EpochAuthenticator()) {
		t.Fatalf("after commit B: epoch_authenticator mismatch")
	}

	// Commit C: private.
	commitC, _, err := committer.Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("Commit C (private): %v", err)
	}
	if err := member.ProcessCommit(nil, commitC); err != nil {
		t.Fatalf("ProcessCommit C: %v", err)
	}
	if !bytes.Equal(member.EpochAuthenticator(), committer.EpochAuthenticator()) {
		t.Fatalf("after commit C: epoch_authenticator mismatch\n  member    %x\n  committer %x",
			member.EpochAuthenticator(), committer.EpochAuthenticator())
	}
	t.Logf("mixed public→private sequence OK, final EA=%x", committer.EpochAuthenticator())
}
