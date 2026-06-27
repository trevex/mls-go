package sequencer_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

// TestSingleRegisterSafety is the §5.1 linearizability proof gate:
// N=200 goroutines each submit a distinct CommitRef for the same (group, epoch)
// to ONE MemorySequencer. Exactly one must be accepted (ok=true). The race
// detector proves the mutex actually serializes the CAS.
func TestSingleRegisterSafety(t *testing.T) {
	const N = 200
	s := sequencer.NewMemorySequencer()
	gid := group.GroupID([]byte("test-group"))
	epoch := uint64(42)

	var wg sync.WaitGroup
	var accepted atomic.Int64
	winner := make(chan group.CommitRef, N)

	wg.Add(N)
	for i := 0; i < N; i++ {
		ref := group.CommitRef([]byte{byte(i >> 8), byte(i)}) // distinct 2-byte refs
		go func(r group.CommitRef) {
			defer wg.Done()
			ok, err := s.AcceptCommit(context.Background(), gid, epoch, r)
			if err != nil {
				t.Errorf("AcceptCommit: unexpected error: %v", err)
				return
			}
			if ok {
				accepted.Add(1)
				winner <- r
			}
		}(ref)
	}
	wg.Wait()
	close(winner)

	// Exactly one goroutine must have been accepted.
	if n := accepted.Load(); n != 1 {
		t.Fatalf("expected exactly 1 accepted, got %d", n)
	}

	// Decided() must return the winner.
	won := <-winner
	decided, ok := s.Decided(gid, epoch)
	if !ok {
		t.Fatal("Decided: expected ok=true after acceptance")
	}
	if string(decided) != string(won) {
		t.Fatalf("Decided value %x != winner %x", decided, won)
	}

	// Idempotent re-accept of the winner.
	ok, err := s.AcceptCommit(context.Background(), gid, epoch, won)
	if err != nil {
		t.Fatalf("idempotent re-accept: %v", err)
	}
	if !ok {
		t.Fatal("idempotent re-accept: expected ok=true")
	}

	// A different ref must be rejected.
	other := group.CommitRef([]byte("other-ref"))
	ok, err = s.AcceptCommit(context.Background(), gid, epoch, other)
	if err != nil {
		t.Fatalf("different ref: %v", err)
	}
	if ok {
		t.Fatal("different ref after decision: expected ok=false")
	}
}

// TestSequencerIdempotentAndSingleValued covers the sequential CAS invariants.
func TestSequencerIdempotentAndSingleValued(t *testing.T) {
	s := sequencer.NewMemorySequencer()
	gid := group.GroupID([]byte("g1"))
	epoch := uint64(1)

	refA := group.CommitRef([]byte("refA"))
	refB := group.CommitRef([]byte("refB"))

	// First submission wins.
	ok, err := s.AcceptCommit(context.Background(), gid, epoch, refA)
	if err != nil || !ok {
		t.Fatalf("first accept: got ok=%v err=%v, want ok=true nil", ok, err)
	}

	// Same ref is idempotent.
	ok, err = s.AcceptCommit(context.Background(), gid, epoch, refA)
	if err != nil || !ok {
		t.Fatalf("idempotent accept: got ok=%v err=%v, want ok=true nil", ok, err)
	}

	// Different ref is rejected.
	ok, err = s.AcceptCommit(context.Background(), gid, epoch, refB)
	if err != nil || ok {
		t.Fatalf("different ref: got ok=%v err=%v, want ok=false nil", ok, err)
	}

	// A different (group, epoch) is fully independent.
	gid2 := group.GroupID([]byte("g2"))
	ok, err = s.AcceptCommit(context.Background(), gid2, epoch, refB)
	if err != nil || !ok {
		t.Fatalf("independent group: got ok=%v err=%v, want ok=true nil", ok, err)
	}

	epoch2 := uint64(2)
	ok, err = s.AcceptCommit(context.Background(), gid, epoch2, refB)
	if err != nil || !ok {
		t.Fatalf("independent epoch: got ok=%v err=%v, want ok=true nil", ok, err)
	}
}
