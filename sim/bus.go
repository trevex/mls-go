package sim

import "sort"

// Bus is the in-memory transport: per-VNI subscriptions + fault application
// (design spec §3.1). It schedules deliver events; it never delivers
// synchronously (determinism).
type Bus struct {
	sched   *Scheduler
	faults  *faultState
	metrics *Metrics
	subs    map[uint32]map[ActorID]bool // vni -> subscriber set
}

func newBus(s *Scheduler, f *faultState, m *Metrics) *Bus {
	return &Bus{sched: s, faults: f, metrics: m, subs: map[uint32]map[ActorID]bool{}}
}

// Subscribe registers actor a as a member-side listener on vni.
func (b *Bus) Subscribe(vni uint32, a ActorID) {
	if b.subs[vni] == nil {
		b.subs[vni] = map[ActorID]bool{}
	}
	b.subs[vni][a] = true
}

// Unsubscribe removes actor a from vni (on Leave / self-remove).
func (b *Bus) Unsubscribe(vni uint32, a ActorID) {
	if b.subs[vni] != nil {
		delete(b.subs[vni], a)
	}
}

func (b *Bus) subscribers(vni uint32) []ActorID {
	out := make([]ActorID, 0, len(b.subs[vni]))
	for a := range b.subs[vni] {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] }) // determinism
	return out
}

// Publish schedules delivery of env. For Broadcast, one delivery per subscriber
// (excluding the source). Each delivery is independently subject to drop /
// partition / latency. Data-packet drops are recorded as transport drops.
func (b *Bus) Publish(env Envelope) {
	dsts := []ActorID{env.Dst}
	if env.Dst == Broadcast {
		dsts = b.subscribers(env.VNI)
	}
	for _, dst := range dsts {
		if dst == env.Src {
			continue
		}
		if b.faults.blocked(env.Src, dst) {
			b.metrics.Blocked++
			continue
		}
		if b.faults.drop(b.sched.Rand()) {
			if env.Type == MsgData {
				b.metrics.DataDropped++ // transport loss — NOT a key-loss invariant failure
			} else {
				b.metrics.CtrlDropped++
			}
			continue
		}
		d := b.faults.latency(b.sched.Rand())
		e := Event{Kind: KindDeliver, Actor: dst, Env: env}
		b.sched.Schedule(b.sched.Now()+d, e)
		b.metrics.Delivered++
	}
}
