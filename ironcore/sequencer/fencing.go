package sequencer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/trevex/mls-mlkem-go/mls/group"
)

// Lease is a time-bounded ownership grant for one VNI, carrying a strictly
// monotonic per-VNI fencing token (design spec §5.5).
type Lease struct {
	VNI    uint32
	Owner  string    // owning RR identity
	Token  uint64    // fencing token: strictly increasing per VNI across acquisitions
	Expiry time.Time // lease valid while clock.Now().Before(Expiry)
}

// Valid reports whether the lease is unexpired at now.
func (l Lease) Valid(now time.Time) bool { return now.Before(l.Expiry) }

// LeaseStore is the strongly-consistent VNI-ownership store backing B1 fencing
// (design spec §5.5; in deployment: etcd / the Kubernetes control plane).
type LeaseStore interface {
	// Acquire grants (or takes over) the lease for vni to owner iff no DIFFERENT
	// owner currently holds a valid (unexpired) lease. On success it returns a
	// lease whose Token is strictly greater than every token previously minted
	// for vni. ok=false (no error) means another owner holds a valid lease.
	Acquire(vni uint32, owner string, ttl time.Duration) (Lease, bool, error)
	// Renew extends the caller's lease iff it still holds it (owner+token match
	// the current lease). The token is unchanged (same ownership tenure).
	Renew(vni uint32, owner string, token uint64, ttl time.Duration) (Lease, bool, error)
	// Release relinquishes the lease iff held by owner with token.
	Release(vni uint32, owner string, token uint64) error
}

// MemoryLeaseStore is an in-process LeaseStore with an injectable Clock so
// failover (lease expiry) is simulated deterministically in tests.
type MemoryLeaseStore struct {
	mu    sync.Mutex
	clock group.Clock
	held  map[uint32]Lease
	next  map[uint32]uint64 // per-VNI next fencing token (monotonic)
}

// NewMemoryLeaseStore returns a ready store using clock for expiry decisions.
func NewMemoryLeaseStore(clock group.Clock) *MemoryLeaseStore {
	return &MemoryLeaseStore{clock: clock, held: map[uint32]Lease{}, next: map[uint32]uint64{}}
}

// Acquire implements LeaseStore.
func (s *MemoryLeaseStore) Acquire(vni uint32, owner string, ttl time.Duration) (Lease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	if cur, ok := s.held[vni]; ok && cur.Owner != owner && cur.Valid(now) {
		return Lease{}, false, nil // another owner holds a valid lease — fenced out
	}
	s.next[vni]++ // strictly monotonic per VNI
	l := Lease{VNI: vni, Owner: owner, Token: s.next[vni], Expiry: now.Add(ttl)}
	s.held[vni] = l
	return l, true, nil
}

// Renew implements LeaseStore.
func (s *MemoryLeaseStore) Renew(vni uint32, owner string, token uint64, ttl time.Duration) (Lease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.held[vni]
	if !ok || cur.Owner != owner || cur.Token != token {
		return Lease{}, false, nil // lost the lease (superseded / never held)
	}
	cur.Expiry = s.clock.Now().Add(ttl)
	s.held[vni] = cur
	return cur, true, nil
}

// Release implements LeaseStore.
func (s *MemoryLeaseStore) Release(vni uint32, owner string, token uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.held[vni]; ok && cur.Owner == owner && cur.Token == token {
		delete(s.held, vni)
	}
	return nil
}

// ErrFenced is returned by FencedRegister.Accept when a write bears a fencing
// token below the highest the register has seen for the VNI (a stale writer).
var ErrFenced = errors.New("sequencer: write fenced by stale token")

// FencedRegister is a shared, strongly-consistent single-linearizable-register
// (like MemorySequencer) that ADDITIONALLY enforces fencing tokens: it rejects
// any write whose token is below the highest token seen for the VNI (design
// spec §5.5). This gives clock-independent safety: a partitioned stale primary
// is fenced at the register even if its lease check wrongly passed.
type FencedRegister struct {
	mu       sync.Mutex
	decided  map[string]group.CommitRef
	maxToken map[uint32]uint64
}

// NewFencedRegister returns a ready, empty FencedRegister.
func NewFencedRegister() *FencedRegister {
	return &FencedRegister{decided: map[string]group.CommitRef{}, maxToken: map[uint32]uint64{}}
}

// Accept records commit for (group, epoch) under token-fencing for vni. It
// returns ErrFenced if token is stale; otherwise it behaves as the §5.1 CAS
// register (first writer wins; idempotent same-commit; reject different commit).
func (r *FencedRegister) Accept(vni uint32, token uint64, g group.GroupID, epoch uint64, commit group.CommitRef) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if token < r.maxToken[vni] {
		return false, ErrFenced
	}
	r.maxToken[vni] = token
	key := seqKey(g, epoch)
	if ex, ok := r.decided[key]; ok {
		return bytes.Equal(ex, commit), nil
	}
	r.decided[key] = cloneRef(commit)
	return true, nil
}

// Decided returns the decided CommitRef for (group, epoch) and whether one
// exists. Exposed for assertions and monitoring (read-only; copies out).
func (r *FencedRegister) Decided(g group.GroupID, epoch uint64) (group.CommitRef, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ref, ok := r.decided[seqKey(g, epoch)]
	if !ok {
		return nil, false
	}
	return cloneRef(ref), true
}

// FencedSequencer is the B1 default Ordering implementation (design spec §5.5):
// it accepts a commit only while it holds a valid lease for its VNI, writing
// through the shared FencedRegister with its fencing token. A standby cannot
// accept while the primary's lease is valid; after the lease provably expires
// the standby takes over (bounded rekey-only unavailability, §5.4). It owns
// exactly one (vni, group) pair — the simplest valid static fencing config.
type FencedSequencer struct {
	owner string
	vni   uint32
	group group.GroupID
	store LeaseStore
	reg   *FencedRegister
	clock group.Clock
	ttl   time.Duration

	mu    sync.Mutex
	lease Lease
	held  bool
}

// NewFencedSequencer binds owner to (vni, group), leasing via store and writing
// through reg. ttl is the lease TTL (≤ the commit-acceptance timeout, §5.5).
func NewFencedSequencer(owner string, vni uint32, g group.GroupID, store LeaseStore, reg *FencedRegister, clock group.Clock, ttl time.Duration) *FencedSequencer {
	return &FencedSequencer{owner: owner, vni: vni, group: g, store: store, reg: reg, clock: clock, ttl: ttl}
}

var _ group.Ordering = (*FencedSequencer)(nil)

// AcceptCommit implements group.Ordering. It (re)acquires the VNI lease as
// needed; if another owner holds a valid lease it returns (false, nil) — fenced
// out, not an error (the standby simply cannot accept yet). On success it writes
// through the FencedRegister carrying its current fencing token.
func (s *FencedSequencer) AcceptCommit(ctx context.Context, g group.GroupID, epoch uint64, commit group.CommitRef) (bool, error) {
	if !bytes.Equal(g, s.group) {
		return false, fmt.Errorf("sequencer: group %x not owned by VNI %d fencer", g, s.vni)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	if !s.held || !s.lease.Valid(now) {
		l, ok, err := s.store.Acquire(s.vni, s.owner, s.ttl)
		if err != nil {
			return false, err
		}
		if !ok {
			s.held = false
			return false, nil // another owner holds the VNI — fenced out
		}
		s.lease, s.held = l, true
	}
	return s.reg.Accept(s.vni, s.lease.Token, g, epoch, commit)
}
