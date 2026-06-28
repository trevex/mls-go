package group_test

import (
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
