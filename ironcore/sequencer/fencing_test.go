package sequencer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

// TestFencingSafety is the §5.5 fencing safety gate (N4, 6-step mapping):
// two FencedSequencers sharing one MemoryLeaseStore + FencedRegister + fakeClock.
//
//  1. Primary accepts epoch 5 — acquires lease with token 1, writes X.
//  2. Standby cannot accept epoch 5 while primary lease is valid (fenced out).
//  3. Clock advances past the lease TTL (the §5.4 bounded rekey-only window).
//  4. Standby takes over epoch 6 — acquires new lease with token 2, writes Z.
//  5. Stale primary writes to FencedRegister directly with old token 1 → ErrFenced.
//  6. Register holds exactly X@5 and Z@6 — never two different commits per epoch.
func TestFencingSafety(t *testing.T) {
	const ttl = 5 * time.Second
	clk := newFakeClock(time.Unix(1000, 0))

	store := sequencer.NewMemoryLeaseStore(clk)
	reg := sequencer.NewFencedRegister()
	gid := group.GroupID([]byte("fence-group"))
	const vni = uint32(42)

	refX := group.CommitRef([]byte("commit-X"))
	refY := group.CommitRef([]byte("commit-Y"))
	refZ := group.CommitRef([]byte("commit-Z"))

	primary := sequencer.NewFencedSequencer("primary", vni, gid, store, reg, clk, ttl)
	standby := sequencer.NewFencedSequencer("standby", vni, gid, store, reg, clk, ttl)

	// Step 1: primary accepts epoch 5 (acquires lease, token=1, writes X).
	ok, err := primary.AcceptCommit(context.Background(), gid, 5, refX)
	if err != nil {
		t.Fatalf("primary epoch 5: unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("primary epoch 5: expected ok=true")
	}

	// Step 2: standby fenced while primary lease is valid — cannot accept epoch 5.
	ok, err = standby.AcceptCommit(context.Background(), gid, 5, refY)
	if err != nil {
		t.Fatalf("standby epoch 5 (fenced): unexpected error: %v", err)
	}
	if ok {
		t.Fatal("standby epoch 5 (fenced): expected ok=false (fenced out)")
	}

	// Step 3: advance clock past the lease TTL (§5.4 bounded rekey-only window).
	clk.advance(ttl + time.Second)

	// Step 4: standby takes over — acquires new lease (token=2 > 1), writes Z at epoch 6.
	ok, err = standby.AcceptCommit(context.Background(), gid, 6, refZ)
	if err != nil {
		t.Fatalf("standby epoch 6 (takeover): %v", err)
	}
	if !ok {
		t.Fatal("standby epoch 6 (takeover): expected ok=true")
	}

	// Step 5: stale primary's old token (1) is now below maxToken for vni (2).
	// A direct FencedRegister.Accept with stale token must be rejected with ErrFenced —
	// clock-independent safety: a partitioned primary cannot split-brain even with a
	// lagging clock (design spec §5.5).
	_, err = reg.Accept(vni, 1, gid, 6, group.CommitRef([]byte("stale-commit")))
	if !errors.Is(err, sequencer.ErrFenced) {
		t.Fatalf("stale-token write: expected ErrFenced, got %v", err)
	}

	// Step 5b: stale primary cannot advance into a NEW, never-decided epoch either.
	// Token fencing is epoch-independent: a superseded primary is fenced for ALL
	// future epochs, not just already-decided ones (design spec §5.5). This proves
	// the fence is on the token/writer, not on the epoch being written.
	someFreshRef := group.CommitRef([]byte("fresh-epoch-commit"))
	_, err = reg.Accept(vni, 1, gid, 7, someFreshRef)
	if !errors.Is(err, sequencer.ErrFenced) {
		t.Fatalf("stale-token write to fresh epoch 7: expected ErrFenced, got %v", err)
	}

	// Step 6: register holds exactly X@5 and Z@6 — at no point did both owners
	// decide different commits for the same epoch.
	decided5, ok5 := reg.Decided(gid, 5)
	if !ok5 {
		t.Fatal("Decided epoch 5: expected ok=true")
	}
	if string(decided5) != string(refX) {
		t.Fatalf("epoch 5 decided %x, want X=%x", decided5, refX)
	}

	decided6, ok6 := reg.Decided(gid, 6)
	if !ok6 {
		t.Fatal("Decided epoch 6: expected ok=true")
	}
	if string(decided6) != string(refZ) {
		t.Fatalf("epoch 6 decided %x, want Z=%x", decided6, refZ)
	}
}

// TestLeaseRenewRelease exercises the MemoryLeaseStore lease lifecycle:
// acquire, renew (same token / extended expiry), expiry → new owner acquires
// with a strictly greater token, stale renew fails, release clears ownership.
func TestLeaseRenewRelease(t *testing.T) {
	const ttl = 10 * time.Second
	clk := newFakeClock(time.Unix(2000, 0))
	store := sequencer.NewMemoryLeaseStore(clk)
	const vni = uint32(99)

	// Acquire by ownerA.
	la, ok, err := store.Acquire(vni, "ownerA", ttl)
	if err != nil || !ok {
		t.Fatalf("Acquire ownerA: got ok=%v err=%v", ok, err)
	}
	tokenA := la.Token
	if tokenA == 0 {
		t.Fatal("token must be > 0 after first acquire")
	}

	// Renew extends expiry but keeps the same token (same ownership tenure).
	clk.advance(5 * time.Second)
	la2, ok, err := store.Renew(vni, "ownerA", tokenA, ttl)
	if err != nil || !ok {
		t.Fatalf("Renew ownerA: got ok=%v err=%v", ok, err)
	}
	if la2.Token != tokenA {
		t.Fatalf("Renew changed token: was %d, got %d", tokenA, la2.Token)
	}
	if !la2.Expiry.After(la.Expiry) {
		t.Fatal("Renew did not extend expiry")
	}

	// Advance past expiry — lease expires.
	clk.advance(ttl + time.Second)

	// A different owner acquires after expiry with a strictly greater token.
	lb, ok, err := store.Acquire(vni, "ownerB", ttl)
	if err != nil || !ok {
		t.Fatalf("Acquire ownerB after expiry: got ok=%v err=%v", ok, err)
	}
	if lb.Token <= tokenA {
		t.Fatalf("ownerB token %d must be strictly > ownerA token %d", lb.Token, tokenA)
	}

	// Old owner Renew now fails (superseded).
	_, ok, err = store.Renew(vni, "ownerA", tokenA, ttl)
	if err != nil || ok {
		t.Fatalf("stale Renew ownerA: expected ok=false nil, got ok=%v err=%v", ok, err)
	}

	// Release by the current owner clears ownership.
	if err := store.Release(vni, "ownerB", lb.Token); err != nil {
		t.Fatalf("Release ownerB: %v", err)
	}

	// After release, ownerA can acquire again with a token strictly > ownerB's.
	lc, ok, err := store.Acquire(vni, "ownerA", ttl)
	if err != nil || !ok {
		t.Fatalf("Acquire ownerA after release: got ok=%v err=%v", ok, err)
	}
	if lc.Token <= lb.Token {
		t.Fatalf("ownerA re-acquire token %d must be strictly > ownerB token %d", lc.Token, lb.Token)
	}
}

// TestFencedSequencerWrongGroup verifies that AcceptCommit returns an error
// when called with a GroupID that is not the one the FencedSequencer owns.
func TestFencedSequencerWrongGroup(t *testing.T) {
	const ttl = 5 * time.Second
	clk := newFakeClock(time.Unix(3000, 0))
	store := sequencer.NewMemoryLeaseStore(clk)
	reg := sequencer.NewFencedRegister()
	gid := group.GroupID([]byte("group-owned"))
	wrongGid := group.GroupID([]byte("group-other"))
	const vni = uint32(7)

	fs := sequencer.NewFencedSequencer("owner", vni, gid, store, reg, clk, ttl)
	_, err := fs.AcceptCommit(context.Background(), wrongGid, 1, group.CommitRef([]byte("ref")))
	if err == nil {
		t.Fatal("AcceptCommit with wrong group: expected error, got nil")
	}
}
