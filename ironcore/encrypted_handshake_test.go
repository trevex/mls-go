package ironcore_test

import (
	"context"
	"testing"

	"github.com/trevex/mls-go/ironcore"
	"github.com/trevex/mls-go/ironcore/sequencer"
	"github.com/trevex/mls-go/mls/framing"
	"github.com/trevex/mls-go/mls/group"
)

// TestControllerDefaultEncryptsMemberCommit verifies that a VNI whose
// ControllerConfig carries the zero HandshakePrivacy (= HandshakeEncrypted)
// frames its outbound member commits as WireFormatPrivateMessage.
func TestControllerDefaultEncryptsMemberCommit(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctx := context.Background()

	// Build joiner material.
	joiner, kpMsg, initPriv, leafPriv := mkNode(t, suite, testVNI, "node-1", seq, nil)

	// Build founder with DEFAULT config (zero HandshakePrivacy = HandshakeEncrypted).
	resolver := ironcore.KeyPackageResolver(func(identity []byte) ([]byte, bool) {
		if string(identity) == "node-1" {
			return kpMsg, true
		}
		return nil, false
	})
	founder := founderNode(t, suite, testVNI, "node-0", seq, resolver)

	// Reconcile adds node-1.
	desired := [][]byte{[]byte("node-0"), []byte("node-1")}
	result, err := founder.Reconcile(ctx, desired)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !result.Committed || !result.Won {
		t.Fatalf("Reconcile: Committed=%v Won=%v, want both true", result.Committed, result.Won)
	}

	// Joiner joins via Welcome.
	if err := joiner.JoinViaWelcome(result.WelcomeMsg, kpMsg, initPriv, leafPriv); err != nil {
		t.Fatalf("JoinViaWelcome: %v", err)
	}

	// The commit produced by a default (HandshakeEncrypted) controller MUST be
	// WireFormatPrivateMessage so a reflector relaying it sees only ciphertext.
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(result.CommitMsg); err != nil {
		t.Fatalf("UnmarshalMLS(CommitMsg): %v", err)
	}
	if m.WireFormat != framing.WireFormatPrivateMessage {
		t.Fatalf("commit WireFormat = %v, want WireFormatPrivateMessage (HandshakeEncrypted default)",
			m.WireFormat)
	}
	t.Logf("TestControllerDefaultEncryptsMemberCommit: commit is WireFormatPrivateMessage as expected")
}

// TestRecoveryCommitStaysPublic verifies that AutoRecover always produces a
// PublicMessage external commit with SenderTypeNewMemberCommit — RFC 9420
// §12.4.3 — regardless of the VNI's HandshakePrivacy setting.
func TestRecoveryCommitStaysPublic(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	ctx := context.Background()

	// Build a 2-member group. Both nodes use the DEFAULT encrypted config.
	joiner, kpMsg, initPriv, leafPriv := mkNode(t, suite, testVNI, "node-1", seq, nil)
	resolver := ironcore.KeyPackageResolver(func(identity []byte) ([]byte, bool) {
		if string(identity) == "node-1" {
			return kpMsg, true
		}
		return nil, false
	})
	founder := founderNode(t, suite, testVNI, "node-0", seq, resolver)

	result, err := founder.Reconcile(ctx, [][]byte{[]byte("node-0"), []byte("node-1")})
	if err != nil || !result.Committed || !result.Won {
		t.Fatalf("Reconcile add: %+v err=%v", result, err)
	}
	if err := joiner.JoinViaWelcome(result.WelcomeMsg, kpMsg, initPriv, leafPriv); err != nil {
		t.Fatalf("JoinViaWelcome: %v", err)
	}
	assertControllerConverged(t, "pre-recovery", founder, joiner)

	// Force a fork: both commit from the same base epoch without seeing each
	// other's commit.
	baseEpoch := founder.Epoch()
	rekeyMsg, won, err := founder.Rekey(ctx)
	if err != nil || !won {
		t.Fatalf("founder.Rekey: won=%v err=%v", won, err)
	}
	_ = rekeyMsg // joiner has NOT processed it

	// joiner makes a competing fork commit at the same base epoch.
	forkCommit, _, forkErr := joiner.Group().Commit(group.CommitOptions{})
	if forkErr != nil {
		t.Fatalf("joiner fork commit: %v", forkErr)
	}
	forkRef := group.CommitRef(suite.Hash(forkCommit))

	gid := group.GroupID(ironcore.GroupID(testVNI))
	okFork, err := seq.AcceptCommit(ctx, gid, baseEpoch, forkRef)
	if err != nil {
		t.Fatalf("AcceptCommit(fork): %v", err)
	}
	if okFork {
		t.Fatal("fork should be rejected — founder already won the epoch slot")
	}

	// Retrieve the canonical ref and GroupInfo.
	canonRef, found := seq.Decided(gid, baseEpoch)
	if !found {
		t.Fatal("sequencer has no decided commit for baseEpoch")
	}
	gi, err := founder.PublishGroupInfo()
	if err != nil {
		t.Fatalf("founder.PublishGroupInfo: %v", err)
	}

	// joiner auto-recovers onto the canonical branch using the default
	// (HandshakeEncrypted) config.
	recoveryMsg, err := joiner.AutoRecover(ctx,
		[]group.CommitRef{canonRef},
		func(_ group.CommitRef) (*group.GroupInfo, error) { return gi, nil },
	)
	if err != nil {
		t.Fatalf("joiner.AutoRecover: %v", err)
	}

	// The recovery commit MUST be PublicMessage with SenderTypeNewMemberCommit
	// (RFC 9420 §12.4.3) regardless of HandshakePrivacy — external-commit
	// recovery is always public.
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(recoveryMsg); err != nil {
		t.Fatalf("UnmarshalMLS(recoveryMsg): %v", err)
	}
	if m.WireFormat != framing.WireFormatPublicMessage {
		t.Fatalf("recovery commit WireFormat = %v, want WireFormatPublicMessage", m.WireFormat)
	}
	if m.Public == nil {
		t.Fatal("recovery commit: Public body is nil")
	}
	if m.Public.Content.Sender.Type != framing.SenderTypeNewMemberCommit {
		t.Fatalf("recovery commit Sender.Type = %v, want SenderTypeNewMemberCommit",
			m.Public.Content.Sender.Type)
	}
	t.Logf("TestRecoveryCommitStaysPublic: recovery commit is PublicMessage/new_member_commit as expected")
}
