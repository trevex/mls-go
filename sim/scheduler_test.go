package sim

import (
	"math/rand"
	"testing"
)

// TestSchedulerPopOrder verifies events pop in non-decreasing At order and,
// within equal At, in increasing Seq order.
func TestSchedulerPopOrder(t *testing.T) {
	s := NewScheduler(42)
	rng := rand.New(rand.NewSource(99))

	// schedule 100 events with random At values in [0, 20)
	for i := 0; i < 100; i++ {
		at := uint64(rng.Intn(20))
		s.Schedule(at, Event{Kind: KindTimer})
	}

	prevAt := uint64(0)
	prevSeq := uint64(0)
	first := true
	for {
		e, ok := s.Pop()
		if !ok {
			break
		}
		if e.At < prevAt {
			t.Fatalf("At went backwards: %d < %d", e.At, prevAt)
		}
		if e.At == prevAt && !first {
			if e.Seq <= prevSeq {
				t.Fatalf("Seq not increasing within equal At=%d: %d <= %d", e.At, e.Seq, prevSeq)
			}
		}
		prevAt = e.At
		prevSeq = e.Seq
		first = false
	}
}

// TestSchedulerDeterministic verifies two schedulers seeded identically and fed
// identical Schedule calls produce byte-identical pop streams (de-risk #1).
func TestSchedulerDeterministic(t *testing.T) {
	seed := int64(7)

	populate := func() *Scheduler {
		s := NewScheduler(seed)
		rng := rand.New(rand.NewSource(12345))
		for i := 0; i < 50; i++ {
			at := uint64(rng.Intn(30))
			s.Schedule(at, Event{Kind: KindDeliver, Actor: ActorID(i % 5)})
		}
		return s
	}

	s1 := populate()
	s2 := populate()

	for {
		e1, ok1 := s1.Pop()
		e2, ok2 := s2.Pop()
		if ok1 != ok2 {
			t.Fatalf("schedulers drained differently: ok1=%v ok2=%v", ok1, ok2)
		}
		if !ok1 {
			break
		}
		if e1.At != e2.At || e1.Seq != e2.Seq || e1.Actor != e2.Actor {
			t.Fatalf("non-deterministic pop: {At:%d Seq:%d Actor:%d} vs {At:%d Seq:%d Actor:%d}",
				e1.At, e1.Seq, e1.Actor, e2.At, e2.Seq, e2.Actor)
		}
	}
}

// TestSchedulerTieBreakStrictTotalOrder verifies no two popped events share
// (At, Seq).
func TestSchedulerTieBreakStrictTotalOrder(t *testing.T) {
	s := NewScheduler(1)
	// schedule many events at the same logical time
	for i := 0; i < 200; i++ {
		s.Schedule(10, Event{Kind: KindTimer})
	}

	seen := map[[2]uint64]bool{}
	for {
		e, ok := s.Pop()
		if !ok {
			break
		}
		key := [2]uint64{e.At, e.Seq}
		if seen[key] {
			t.Fatalf("duplicate (At=%d, Seq=%d)", e.At, e.Seq)
		}
		seen[key] = true
	}
}
