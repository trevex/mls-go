package sim

import (
	"testing"

	"github.com/trevex/mls-go/mls/framing"
	"github.com/trevex/mls-go/mls/tree"
)

// buildDSHarness creates a minimal harness with two reflectors (R0=replica 0,
// R1=replica 1), each with its own accept-once register.
func buildDSHarness() (s *Scheduler, f *faultState, b *Bus, m *Metrics, ds0, ds1 *DS) {
	s = NewScheduler(1)
	f = newFaultState(FaultConfig{Latency: 1})
	m = newMetrics()
	b = newBus(s, f, m)
	ds0 = newDS(ActorID(10), 0, b, f)
	ds1 = newDS(ActorID(11), 1, b, f)
	return
}

// TestDSSerializeAndFanout: a commit accepted by the register is logged + fanned
// out; a re-submitted identical commit is idempotent (no duplicate log entry).
func TestDSSerializeAndFanout(t *testing.T) {
	_, _, b, m, ds0, _ := buildDSHarness()
	b.Subscribe(42, ActorID(0))
	b.Subscribe(42, ActorID(1))

	commit := []byte("fake-commit-bytes")
	env := Envelope{VNI: 42, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Base: 0, Payload: commit, Hash: contentHash(commit)}
	ds0.handle(env, m)

	if m.Reflected != 1 {
		t.Fatalf("expected 1 reflection, got %d", m.Reflected)
	}
	if len(ds0.logs[42]) != 1 || ds0.logs[42][0].Hash != env.Hash {
		t.Fatalf("log not recorded correctly: %+v", ds0.logs[42])
	}

	// Idempotent resend: same hash → accepted again but log de-duped.
	ds0.handle(env, m)
	if len(ds0.logs[42]) != 1 {
		t.Fatalf("idempotent resend duplicated the log: %d entries", len(ds0.logs[42]))
	}
}

// TestDSRegisterRejectsCompetingCommit: a DIFFERENT commit for an already-decided
// (channel, epoch) is rejected by the local register — the total-order guarantee.
func TestDSRegisterRejectsCompetingCommit(t *testing.T) {
	_, _, b, m, ds0, _ := buildDSHarness()
	b.Subscribe(42, ActorID(0))

	a := []byte("commit-A")
	ds0.handle(Envelope{VNI: 42, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Base: 0, Payload: a, Hash: contentHash(a)}, m)

	bcommit := []byte("commit-B-different")
	rejBefore := m.CommitRejected
	ds0.handle(Envelope{VNI: 42, Type: MsgCommit, Src: ActorID(1), Dst: ActorID(10),
		Base: 0, Payload: bcommit, Hash: contentHash(bcommit)}, m)

	if m.CommitRejected != rejBefore+1 {
		t.Fatalf("competing commit not rejected by register")
	}
	if len(ds0.logs[42]) != 1 {
		t.Fatalf("rejected commit must not be logged: %d entries", len(ds0.logs[42]))
	}
}

// TestDSCatchupServesLog: logRequest{fromEpoch} returns records ≥ fromEpoch.
func TestDSCatchupServesLog(t *testing.T) {
	_, _, b, m, ds0, _ := buildDSHarness()
	b.Subscribe(55, ActorID(0))

	for base := uint64(0); base < 3; base++ {
		payload := []byte{byte(base), 0xAB}
		ds0.handle(Envelope{VNI: 55, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
			Base: base, Payload: payload, Hash: contentHash(payload)}, m)
	}

	before := m.LogRetransmits
	ds0.handle(Envelope{VNI: 55, Type: MsgLogRequest, Src: ActorID(0), Dst: ActorID(10), Base: 1}, m)
	if m.LogRetransmits != before+1 {
		t.Fatalf("LogRetransmits not incremented")
	}
}

// TestDSDownStopsFanout: a downed reflector neither serializes nor fans out; after
// restart it serves again.
func TestDSDownStopsFanout(t *testing.T) {
	_, f, b, m, ds0, _ := buildDSHarness()
	b.Subscribe(77, ActorID(0))

	f.applyFault(FaultOp{Kind: faultDSDown, On: true, DS: ActorID(10)})
	commit := []byte("commit-while-down")
	ds0.handle(Envelope{VNI: 77, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Base: 0, Payload: commit, Hash: contentHash(commit)}, m)
	if m.Reflected != 0 || len(ds0.logs[77]) != 0 {
		t.Fatalf("downed DS reflected/logged: reflected=%d log=%d", m.Reflected, len(ds0.logs[77]))
	}

	f.applyFault(FaultOp{Kind: faultDSDown, On: false, DS: ActorID(10)})
	ds0.handle(Envelope{VNI: 77, Type: MsgCommit, Src: ActorID(0), Dst: ActorID(10),
		Base: 0, Payload: commit, Hash: contentHash(commit)}, m)
	if m.Reflected != 1 {
		t.Fatalf("restarted DS should reflect, got %d", m.Reflected)
	}
}

// TestObserveHandshakePrivacyDetectsPlaintext directly exercises observeHandshakePrivacy
// without running a full simulation.
func TestObserveHandshakePrivacyDetectsPlaintext(t *testing.T) {
	d := &DS{encryptHandshakes: true}
	m := newMetrics()

	// Minimal commit content: empty proposals<V> (one zero varint) + absent UpdatePath (0x00).
	commitContent := []byte{0x00, 0x00}

	// buildPublic marshals a PublicMessage MLSMessage with the given sender type and
	// verifies it round-trips through UnmarshalMLS before returning the wire bytes.
	buildPublic := func(senderType framing.SenderType) []byte {
		t.Helper()
		sender := framing.Sender{Type: senderType}
		if senderType == framing.SenderTypeMember {
			sender.LeafIndex = 0
		}
		pub := &framing.PublicMessage{
			Content: framing.FramedContent{
				GroupID:     []byte{0x01},
				Epoch:       0,
				Sender:      sender,
				ContentType: framing.ContentTypeCommit,
				Content:     commitContent,
			},
			Auth: framing.FramedContentAuthData{
				Signature:       nil, // zero-length OpaqueV; observer only checks wire format + sender type
				ConfirmationTag: nil, // required field for commit; zero-length is valid wire
			},
		}
		if senderType == framing.SenderTypeMember {
			pub.MembershipTag = nil // required field for member sender; zero-length is valid wire
		}
		msg := framing.MLSMessage{
			Version:    tree.ProtocolVersionMLS10,
			WireFormat: framing.WireFormatPublicMessage,
			Public:     pub,
		}
		b, err := msg.MarshalMLS()
		if err != nil {
			t.Fatalf("buildPublic(%v) MarshalMLS: %v", senderType, err)
		}
		// Verify the bytes round-trip so the test setup is self-consistent.
		var got framing.MLSMessage
		if err := got.UnmarshalMLS(b); err != nil {
			t.Fatalf("buildPublic(%v) UnmarshalMLS: %v", senderType, err)
		}
		if got.WireFormat != framing.WireFormatPublicMessage || got.Public == nil {
			t.Fatalf("buildPublic(%v) round-trip: WireFormat=%v Public=%v", senderType, got.WireFormat, got.Public)
		}
		if got.Public.Content.Sender.Type != senderType {
			t.Fatalf("buildPublic(%v) round-trip: sender type = %v", senderType, got.Public.Content.Sender.Type)
		}
		return b
	}

	// Case 1: SenderTypeMember commit as PublicMessage in an encrypted VNI
	// → counter must increment (plaintext exposure detected).
	env1 := Envelope{Type: MsgCommit, Payload: buildPublic(framing.SenderTypeMember)}
	d.observeHandshakePrivacy(env1, m)
	if m.PlaintextHandshakeExposures != 1 {
		t.Fatalf("case 1: PlaintextHandshakeExposures = %d, want 1", m.PlaintextHandshakeExposures)
	}

	// Case 2: SenderTypeNewMemberCommit (external-join / recovery carve-out) is
	// always PublicMessage by RFC 9420 — the observer must NOT count it.
	env2 := Envelope{Type: MsgCommit, Payload: buildPublic(framing.SenderTypeNewMemberCommit)}
	before2 := m.PlaintextHandshakeExposures
	d.observeHandshakePrivacy(env2, m)
	if m.PlaintextHandshakeExposures != before2 {
		t.Fatalf("case 2: NewMemberCommit incremented counter: got %d, want %d",
			m.PlaintextHandshakeExposures, before2)
	}

	// Case 3: PrivateMessage commit → observer must not increment (handshake is encrypted).
	privMsg := framing.MLSMessage{
		Version:    tree.ProtocolVersionMLS10,
		WireFormat: framing.WireFormatPrivateMessage,
		Private: &framing.PrivateMessage{
			GroupID:             []byte{0x01},
			Epoch:               0,
			ContentType:         framing.ContentTypeCommit,
			AuthenticatedData:   nil,
			EncryptedSenderData: []byte{0x00},
			Ciphertext:          []byte{0x00},
		},
	}
	privBytes, err := privMsg.MarshalMLS()
	if err != nil {
		t.Fatalf("case 3 MarshalMLS: %v", err)
	}
	var gotPriv framing.MLSMessage
	if err := gotPriv.UnmarshalMLS(privBytes); err != nil {
		t.Fatalf("case 3 UnmarshalMLS: %v", err)
	}
	env3 := Envelope{Type: MsgCommit, Payload: privBytes}
	before3 := m.PlaintextHandshakeExposures
	d.observeHandshakePrivacy(env3, m)
	if m.PlaintextHandshakeExposures != before3 {
		t.Fatalf("case 3: PrivateMessage incremented counter: got %d, want %d",
			m.PlaintextHandshakeExposures, before3)
	}
}
