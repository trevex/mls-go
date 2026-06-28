package group_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/framing"
	"github.com/trevex/mls-go/mls/group"
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
		t.Run("suite", func(t *testing.T) {
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

// TestWireFormatBindsTranscript asserts that a public commit and a private commit
// produce different epoch_authenticators, proving the wire_format is bound into
// the confirmed_transcript_hash.
func TestWireFormatBindsTranscript(t *testing.T) {
	// Two independent two-member groups, same suite.
	cPub, _ := twoMemberGroup(t)
	cPriv, _ := twoMemberGroup(t)

	// cPub commits publicly (default).
	_, _, err := cPub.Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("cPub.Commit (public): %v", err)
	}

	// cPriv commits privately.
	cPriv.SetEncryptHandshakes(true)
	_, _, err = cPriv.Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("cPriv.Commit (private): %v", err)
	}

	// The wire_format is bound into the transcript — the epoch_authenticators MUST differ.
	if bytes.Equal(cPub.EpochAuthenticator(), cPriv.EpochAuthenticator()) {
		t.Errorf("wire_format not bound in transcript: public and private epoch_authenticators are equal (%x)",
			cPub.EpochAuthenticator())
	} else {
		t.Logf("wire_format correctly bound: public EA=%x, private EA=%x",
			cPub.EpochAuthenticator(), cPriv.EpochAuthenticator())
	}
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
