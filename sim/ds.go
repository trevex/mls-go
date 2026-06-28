package sim

import "sort"

// DS is one MetalBond reflector: a dumb, eventually-consistent AP fan-out with a
// per-VNI commit log + GroupInfo cache + catch-up service (design spec §3.2).
// NO register, NO lease, NO ownership, NO consensus.
type DS struct {
	id      ActorID
	bus     *Bus
	faults  *faultState
	logs    map[uint32][]CommitRecord    // vni -> received-order commit log
	giCache map[uint32]map[string][]byte // vni -> ref(hash) -> GroupInfo bytes
	latest  map[uint32][]byte            // vni -> latest GroupInfo bytes
}

func newDS(id ActorID, bus *Bus, f *faultState) *DS {
	return &DS{
		id: id, bus: bus, faults: f,
		logs:    map[uint32][]CommitRecord{},
		giCache: map[uint32]map[string][]byte{},
		latest:  map[uint32][]byte{},
	}
}

// handle dispatches an inbound envelope to this DS.
func (d *DS) handle(env Envelope, m *Metrics) {
	if d.faults.isDown(d.id) {
		return // a downed reflector ignores everything (design spec §3.2 failover)
	}
	switch env.Type {
	case MsgCommit:
		d.appendLog(env)
		d.reflect(env, m)
	case MsgGroupInfo:
		d.cacheGI(env)
		d.reflect(env, m)
	case MsgWelcome, MsgHeartbeat:
		d.reflect(env, m)
	case MsgLogRequest:
		d.serveCatchup(env, m)
	}
}

// appendLog records the commit in receive order (the two DS may diverge — AP).
func (d *DS) appendLog(env Envelope) {
	for _, r := range d.logs[env.VNI] {
		if r.Hash == env.Hash {
			return // dedup
		}
	}
	d.logs[env.VNI] = append(d.logs[env.VNI], CommitRecord{
		Base: env.Base, External: env.External, Bytes: env.Payload, Hash: env.Hash,
	})
}

func (d *DS) cacheGI(env Envelope) {
	if d.giCache[env.VNI] == nil {
		d.giCache[env.VNI] = map[string][]byte{}
	}
	d.giCache[env.VNI][env.Hash] = env.Payload
	d.latest[env.VNI] = env.Payload
}

// reflect best-effort re-publishes to all VNI subscribers (BGP-RR behaviour).
func (d *DS) reflect(env Envelope, m *Metrics) {
	out := env
	out.Src = d.id // reflected from this DS
	out.Dst = Broadcast
	d.bus.Publish(out)
	m.Reflected++
}

// serveCatchup answers a logRequest with the records this DS holds ≥ fromEpoch.
func (d *DS) serveCatchup(env Envelope, m *Metrics) {
	var recs []CommitRecord
	for _, r := range d.logs[env.VNI] {
		if r.Base >= env.Base {
			recs = append(recs, r)
		}
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Base < recs[j].Base })
	reply := Envelope{VNI: env.VNI, Type: MsgLogReply, Src: d.id, Dst: env.Src, Records: recs}
	d.bus.Publish(reply)
	// also serve the latest GroupInfo for the external-commit fallback
	if gi := d.latest[env.VNI]; gi != nil {
		d.bus.Publish(Envelope{VNI: env.VNI, Type: MsgGroupInfo, Src: d.id, Dst: env.Src,
			Payload: gi, Hash: contentHash(gi)})
	}
	m.LogRetransmits++
}

// restart re-enables a downed DS (state is re-learned via the bus over time).
func (d *DS) restart() { /* faultState.dsDown[d.id] cleared by the lifting FaultOp */ }
