package sim

import (
	"context"
	"sort"

	"github.com/trevex/mls-go/ironcore"
	"github.com/trevex/mls-go/ironcore/sequencer"
	"github.com/trevex/mls-go/mls/framing"
	"github.com/trevex/mls-go/mls/group"
)

// DS is one MetalBond reflector R_r ordering replica r of every VNI (design spec
// rev 5 §0). It owns its OWN local accept-once register (sequencer.MemorySequencer,
// one per reflector, NEVER shared) plus a per-channel commit log + catch-up
// service. Because each replica is ordered by exactly one reflector and committed
// by a single designated committer, the register emits a true total order and the
// replica never forks. There is NO cross-reflector contact, NO lease, NO consensus.
type DS struct {
	id                ActorID
	replica           int
	bus               *Bus
	faults            *faultState
	seq               *sequencer.MemorySequencer // this reflector's local accept-once register
	logs              map[uint32][]CommitRecord  // channel(saVNI) -> serialized commit log
	encryptHandshakes bool                       // EncryptedChurn scenario: detect plaintext member handshakes
}

func newDS(id ActorID, replica int, bus *Bus, f *faultState) *DS {
	return &DS{
		id: id, replica: replica, bus: bus, faults: f,
		seq:  sequencer.NewMemorySequencer(),
		logs: map[uint32][]CommitRecord{},
	}
}

// handle dispatches an inbound envelope to this reflector. Channels are saVNI
// values; this reflector only ever receives traffic for its own replica because
// clients route replica-r control messages exclusively to R_r.
func (d *DS) handle(env Envelope, m *Metrics) {
	if d.faults.isDown(d.id) {
		return // a downed reflector ignores everything (replica r stalls; the other replica carries the data plane)
	}
	switch env.Type {
	case MsgCommit:
		d.onCommit(env, m)
	case MsgWelcome:
		d.reflect(env, m)
	case MsgLogRequest:
		d.serveCatchup(env, m)
	}
}

// observeHandshakePrivacy flags a member handshake that a reflector could read
// in cleartext while the VNI is configured to encrypt handshakes.
func (d *DS) observeHandshakePrivacy(env Envelope, m *Metrics) {
	if !d.encryptHandshakes {
		return
	}
	if env.Type != MsgCommit { // proposals ride inside by-value commits in this model
		return
	}
	var msg framing.MLSMessage
	if err := msg.UnmarshalMLS(env.Payload); err != nil {
		return // unparseable bytes are not a plaintext exposure
	}
	// new_member_commit (external join/recovery) is PublicMessage by RFC — ignore.
	// Counted per delivery, not per unique commit; resends may increment more than once (harmless for the >0 invariant).
	if msg.WireFormat == framing.WireFormatPublicMessage && msg.Public != nil &&
		msg.Public.Content.Sender.Type != framing.SenderTypeNewMemberCommit {
		m.PlaintextHandshakeExposures++
	}
}

// onCommit serializes a commit through this reflector's local register. The first
// commit to win (channel, epoch) is appended + fanned out; any different commit
// for an already-decided slot is dropped. A re-submitted identical commit (a
// resend after a drop) is idempotently accepted and re-fanned-out.
func (d *DS) onCommit(env Envelope, m *Metrics) {
	d.observeHandshakePrivacy(env, m)
	gid := group.GroupID(ironcore.GroupID(env.VNI))
	ref := group.CommitRef([]byte(env.Hash))
	ok, err := d.seq.AcceptCommit(context.Background(), gid, env.Base, ref)
	if err != nil || !ok {
		m.CommitRejected++
		return
	}
	d.appendLog(env)
	d.reflect(env, m)
}

// appendLog records the winning commit in serialized order (dedup by hash so an
// idempotent resend does not duplicate the log entry).
func (d *DS) appendLog(env Envelope) {
	for _, r := range d.logs[env.VNI] {
		if r.Hash == env.Hash {
			return
		}
	}
	d.logs[env.VNI] = append(d.logs[env.VNI], CommitRecord{
		Base: env.Base, Bytes: env.Payload, Hash: env.Hash,
	})
}

// reflect re-publishes to all channel subscribers (BGP-RR fan-out).
func (d *DS) reflect(env Envelope, m *Metrics) {
	out := env
	out.Src = d.id
	out.Dst = Broadcast
	d.bus.Publish(out)
	m.Reflected++
}

// serveCatchup answers a logRequest with the records this reflector holds ≥ fromEpoch.
func (d *DS) serveCatchup(env Envelope, m *Metrics) {
	var recs []CommitRecord
	for _, r := range d.logs[env.VNI] {
		if r.Base >= env.Base {
			recs = append(recs, r)
		}
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Base < recs[j].Base })
	d.bus.Publish(Envelope{VNI: env.VNI, Type: MsgLogReply, Src: d.id, Dst: env.Src, Records: recs})
	m.LogRetransmits++
}
