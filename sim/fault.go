package sim

import "math/rand"

const (
	faultPartition faultKind = iota
	faultDSDown
)

// FaultConfig is the static fault profile of a scenario (design spec §3.4).
type FaultConfig struct {
	DropProb float64 // per-delivery drop probability [0,1]
	Latency  uint64  // base link latency (logical ticks)
	Jitter   uint64  // extra uniform jitter [0, Jitter]
}

// faultState is the live, mutable fault state (toggled by KindFault events).
type faultState struct {
	cfg        FaultConfig
	partitions []partition // active partitions
	dsDown     map[ActorID]bool
}

type partition struct {
	side map[ActorID]int // actor -> 1 or 2; absent ⇒ unaffected
}

func newFaultState(cfg FaultConfig) *faultState {
	return &faultState{cfg: cfg, dsDown: map[ActorID]bool{}}
}

// drop returns true if this delivery is dropped (seeded).
func (f *faultState) drop(rng *rand.Rand) bool {
	if f.cfg.DropProb <= 0 {
		return false
	}
	if f.cfg.DropProb >= 1 {
		return true
	}
	return rng.Float64() < f.cfg.DropProb
}

// latency returns the delivery delay (base + seeded jitter).
func (f *faultState) latency(rng *rand.Rand) uint64 {
	d := f.cfg.Latency
	if f.cfg.Jitter > 0 {
		d += uint64(rng.Int63n(int64(f.cfg.Jitter) + 1))
	}
	if d == 0 {
		d = 1 // every delivery takes at least one tick (keeps causality strict)
	}
	return d
}

// blocked reports whether src→dst is severed by an active partition.
func (f *faultState) blocked(src, dst ActorID) bool {
	for _, p := range f.partitions {
		a, aok := p.side[src]
		b, bok := p.side[dst]
		if aok && bok && a != b {
			return true
		}
	}
	return false
}

// applyFault toggles a fault on/off.
func (f *faultState) applyFault(op FaultOp) {
	switch op.Kind {
	case faultDSDown:
		f.dsDown[op.DS] = op.On
	case faultPartition:
		if op.On {
			p := partition{side: map[ActorID]int{}}
			for _, a := range op.SideA {
				p.side[a] = 1
			}
			for _, b := range op.SideB {
				p.side[b] = 2
			}
			f.partitions = append(f.partitions, p)
		} else {
			f.partitions = nil // lifting clears all partitions (scenarios lift en masse at settle)
		}
	}
}

func (f *faultState) isDown(ds ActorID) bool { return f.dsDown[ds] }

// liftAll clears every fault for the settle window (design spec §8.2).
func (f *faultState) liftAll() {
	f.partitions = nil
	for k := range f.dsDown {
		f.dsDown[k] = false
	}
	f.cfg.DropProb = 0
}
