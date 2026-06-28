package sim

import (
	"container/heap"
	"math/rand"
)

// Scheduler is the single-threaded logical-time event queue (design spec §2).
// It owns the ONLY source of randomness in the simulation.
type Scheduler struct {
	clock uint64
	seq   uint64
	pq    eventHeap
	rng   *rand.Rand
}

// NewScheduler seeds the RNG from the scenario seed.
func NewScheduler(seed int64) *Scheduler {
	s := &Scheduler{rng: rand.New(rand.NewSource(seed))}
	heap.Init(&s.pq)
	return s
}

// Now returns the current logical time (the At of the last popped event).
func (s *Scheduler) Now() uint64 { return s.clock }

// Rand returns the single seeded RNG; ALL randomness must come from here.
func (s *Scheduler) Rand() *rand.Rand { return s.rng }

// Schedule enqueues e to fire at absolute logical time at. Seq is assigned
// monotonically so (At, Seq) is a strict total order ⇒ deterministic pops.
func (s *Scheduler) Schedule(at uint64, e Event) {
	if at < s.clock {
		at = s.clock // never schedule into the past
	}
	e.At = at
	e.Seq = s.seq
	s.seq++
	heap.Push(&s.pq, e)
}

// Pop removes and returns the next event; ok=false when the queue is empty.
func (s *Scheduler) Pop() (Event, bool) {
	if s.pq.Len() == 0 {
		return Event{}, false
	}
	e := heap.Pop(&s.pq).(Event)
	s.clock = e.At
	return e, true
}

// Empty reports whether the queue is quiescent.
func (s *Scheduler) Empty() bool { return s.pq.Len() == 0 }

// eventHeap orders by (At, Seq).
type eventHeap []Event

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	if h[i].At != h[j].At {
		return h[i].At < h[j].At
	}
	return h[i].Seq < h[j].Seq
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)   { *h = append(*h, x.(Event)) }
func (h *eventHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	*h = old[:n-1]
	return e
}
