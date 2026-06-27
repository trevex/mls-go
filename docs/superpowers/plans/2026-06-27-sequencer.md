# Sequencer / Ordering Authority — single-linearizable-register, B1 fencing, fork detection, tie-break (Plan 11 of 11) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Depends on Plan 10** (`2026-06-27-ironcore-integration.md`) — the `ironcore/` layer (`GroupID`/`VNIOfGroupID`, `VNIGroup`, `DeriveSAKeys`, the `buildVNIGroup`/`addMember`/`makeSigner`/`makeCred`/`makeLifetime` test helpers) and Plan 9's active `mls/group` engine (`NewGroup`, `Commit`, `ProcessCommit`, `EpochAuthenticator`, the `ports.go` interfaces `DeliveryService`/`CredentialValidator`/`StateStore`/`Clock`) must be merged first. **There is no MLS KAT for this layer** — the gates are PROPERTY / INVARIANT tests that *demonstrate* the design spec's §5 correctness claims. Every non-trivial behaviour below (concurrent single-register safety under `-race`; the lease/fencing-token failover; the tie-break determinism; and — using the *real* MLS engine — that two members committing from the same epoch produce **different** `epoch_authenticator`s) was **empirically validated during planning** with throwaway `package ironcore_test` tests run under `go test -race`. **The throwaways were deleted; the working tree was left clean (only this plan file is new).** Validation log (real run): single-register → exactly 1 of 200 concurrent distinct refs accepted, race-clean, idempotent winner re-accept, post-decision different-ref rejected; tie-break → identical winner across all candidate permutations and confirmed-lowest-hash; fencing → standby fenced while primary lease valid, takeover only after expiry with a strictly-greater token, stale-token write rejected by the register, exactly one commit per epoch; split-brain → a real 3-member X-Wing group at epoch 2, member-0 and member-1 each commit empty → epoch 3 with **distinct** authenticators (`fb4faa45…` vs `d0af6023…`), two independent registers each accept their own branch (two winners = the fork), and the `EpochAuthenticatorRegistry` flags divergence on the second report.

**Goal:** Build the **ordering authority** for the IronCore MLS DS (design spec §5) — the piece the user cares most about ("prove this will always be correct"). Deliverables: **(0)** define the **`Ordering` port** + the `CommitRef` type in `mls/group/ports.go` (the single-linearizable-register contract, §5.1); **(1)** a new `ironcore/sequencer` subpackage holding the reference implementations: **`MemorySequencer`** (the canonical correct CP register — first-valid-commit-per-`(group,epoch)` wins, idempotent re-accept); **(2)** **B1 fenced single-writer per VNI** (§5.5): a `LeaseStore` interface + in-memory `MemoryLeaseStore` with a **monotonic per-VNI fencing token**, a shared token-checked `FencedRegister`, and a `FencedSequencer` that accepts only while it holds a valid lease and writes through with its token; **(3)** fork detection (§5.6): an `EpochAuthenticatorRegistry` that flags two different `epoch_authenticator`s for the same `(group,epoch)`; **(4)** the deterministic recovery tie-break (§5.6): `CanonicalCommit` = lowest `Hash(commitRef)`. **The four PROOF TESTS are the gates** — they demonstrate the §5 claims: single-register safety (concurrent, `-race`), split-brain + fork detection (using the *real* MLS engine for divergence), fencing safety (simulated failover), and tie-break determinism. This plan delivers the **register + fencing + fork detection + tie-break + the invariant proofs**; the actual external-commit *recovery execution* (rejoining the canonical branch) is **deferred** (needs external-commit generation/join not yet built — see roadmap).

**Architecture (design spec §3/§4/§5/§10.2):** The **`Ordering` interface is a domain-agnostic port** and belongs in `mls/group/ports.go` next to the other four ports — design spec §3 ("`mls/` … exposes four ports … plus the Ordering/Sequencer contract (§5)") and §4 ("Library ports (the four interfaces + sequencer)") place the *contract* in the crypto-core's port surface. The **implementations** (`MemorySequencer`, `LeaseStore`/`MemoryLeaseStore`, `FencedRegister`, `FencedSequencer`, `EpochAuthenticatorRegistry`, `CanonicalCommit`) are **deployment glue** (leases backed by etcd / the Kubernetes control plane; §5.5) and live in a **new `ironcore/sequencer` subpackage**, consistent with §3 placing the "fork-detect/recovery helper" in `ironcore/`. **Subpackage, not a single `ironcore/sequencer.go`** (justified): the component is a self-contained ordering authority with ~6 distinct exported types and a `-race` concurrency test; the rest of `ironcore/` (SA derivation, credentials) does **not** depend on it, and metalbond's `Ordering` adapter will mirror it — a dedicated package gives a clean import surface (`sequencer.MemorySequencer`, `sequencer.FencedSequencer`, `sequencer.CanonicalCommit`) and avoids name clashes (`Lease`, `Accept`). The sequencer package is written **VNI-agnostic**: a VNI is just the `uint32` lease key; the VNI↔GroupID mapping stays in the caller (`ironcore` root / metalbond), so `ironcore/sequencer` imports only `mls/group` (for `GroupID`/`CommitRef`/`Ordering`/`Clock`) and `mls/cipher` (for the tie-break `Hash`) — **no import cycle**, no dependency on the `ironcore` root. The §10.2 trust model holds: the sequencer is a **pure ordering authority** — not an MLS member, holds **no group secrets**, sees only opaque `CommitRef`s and (for fork detection) public `epoch_authenticator`s.

**Tech Stack:** Go 1.26 standard library only (hard constraint). `mls/group/ports.go` change uses `context` (already imported). `ironcore/sequencer` uses `bytes`, `context`, `encoding/binary`, `errors`, `fmt`, `sync`, `time` (all stdlib) + `mls/group` + `mls/cipher`. Proof tests use `sync`, `sync/atomic`, `testing`, and (for the split-brain integration test in `ironcore_test`) the Plan-10 helpers `buildVNIGroup` + the real `group.Commit`/`EpochAuthenticator`. The split-brain demonstration lives in `package ironcore_test` (not `sequencer_test`) because it needs real diverging MLS groups, and `buildVNIGroup` is an `ironcore_test` helper that external test packages cannot import.

**Spec reference:** Design spec `docs/superpowers/specs/2026-06-26-mls-mlkem-go-design.md` **§5 in full** — §5.1 (the safety invariant: for every `(group_id, epoch)` at most one Commit is ever accepted = a single-valued **linearizable register**, CAS "first valid writer per epoch wins"); §5.2 (what MLS crypto gives free: transcript-hash chaining → two different Commits at epoch *n* yield cryptographically **incompatible** epoch *n+1* states and **different `epoch_authenticator`s** → forks always **detectable & fail-closed**); §5.3 (the trap: detectability ≠ prevention; **two** independent registers = **two** registers → split-brain = a **real** fork the crypto cannot prevent, only later detect; per-group ordering is **CP**, a route reflector is **AP**, a bare pair has no majority); §5.4 (why CP is affordable: **epoch advancement is OFF the data path** — established ESP SAs keep encrypting; ordering unavailability only delays rekey, never drops packets); §5.5 (the two mechanisms: **B1 fenced single-writer per VNI = DEFAULT**, epoch-numbered lease / fencing token, standby takes over only after the old lease **provably expires**, lease TTL ≤ commit-acceptance timeout; B2 consensus register, needs an odd quorum); §5.6 (defense-in-depth: expose `epoch_authenticator` for out-of-band comparison → fork *actively detected*; deterministic recovery via external Commit under tie-break = **lowest `Hash(Commit)`**, the external Commit ALSO passing through the single linearization point); §5.7 (the proof statement: *Agreement* = linearizability ∘ cryptographic binding; remove linearizability and only *detectability* remains). Also §4 (the `Ordering` port sketch), §10.2 (sequencer = pure ordering authority, holds no secrets). RFC 9420 §§6.1/8/8.2/8.7/12.4.3/14, RFC 9750 §5.

> **Go invocation convention:** Go is **not** on `PATH`. Every Go command runs through the nix devshell, e.g. `nix develop -c go test ./ironcore/sequencer/`. Use this form everywhere below. Expect a harmless `Entered Go dev shell: …` banner (and possibly a `warning: Git tree … is dirty`) on stderr. The concurrency gate **must** be run with the race detector: `nix develop -c go test -race ./ironcore/sequencer/ -run TestSingleRegisterSafety`.

---

## Design notes (read before implementing)

Every claim below was reproduced during planning by throwaway `package ironcore_test` tests under `go test -race` (see the header validation log). **These map directly onto the §5 proof obligations — get them exactly right; the tests ARE the deliverable.**

### N0. The `Ordering` port + `CommitRef` (design spec §4 / §5.1) — goes in `mls/group/ports.go`

The contract is the **single-valued, linearizable register** of §5.1: *"the map `(group_id, epoch) → accepted Commit` is a single-valued, linearizable register (a compare-and-set, 'first valid writer per epoch wins')."* `AcceptCommit` is the CAS:

- **Idempotent:** re-submitting the **same** `commitRef` for an already-decided `(group, epoch)` returns `ok=true` (the decided value is stable and re-confirmable).
- **Single-valued:** a **different** `commitRef` for an already-decided `(group, epoch)` returns `ok=false` (the register never changes its mind).
- **First-writer-wins:** the first valid commit for a fresh `(group, epoch)` returns `ok=true` and becomes the decided value.

`CommitRef` is an **opaque, collision-resistant** reference to one Commit; equality is by bytes. In deployment it is `RefHash("…", framed-commit)` or `Hash(commit-message-bytes)` (the proof tests use `suite.Hash(commitMsg)`); the sequencer never interprets it — it only does byte-equality (§10.2: holds no secrets, sees only the reference).

**Exact addition to `mls/group/ports.go`** (`context` is already imported there):

```go
// CommitRef is an opaque, collision-resistant reference to one Commit (e.g.
// RefHash over the framed commit, or Hash(commit-message-bytes)). The ordering
// authority treats it as opaque and compares it only by bytes (design spec
// §5.1/§5.6, §10.2 — the sequencer holds no group secrets).
type CommitRef []byte

// Ordering is the single-linearization-point contract (design spec §5.1/§5.5):
// the map (group_id, epoch) → accepted Commit as a single-valued, linearizable
// register ("first valid writer per epoch wins"). Implementations: B1 fenced
// single-writer per VNI (default) and B2 consensus register; both are CP and
// provably satisfy §5.1. metalbond selects an implementation in its own repo.
type Ordering interface {
	// AcceptCommit returns ok=true iff commit is accepted as the decided Commit
	// for (group, epoch): true for the first valid commit, and idempotently true
	// when the SAME commit is re-submitted for an already-decided (group, epoch).
	// It returns ok=false for any DIFFERENT commit once (group, epoch) is decided.
	AcceptCommit(ctx context.Context, group GroupID, epoch uint64, commit CommitRef) (ok bool, err error)
}
```

A compile-time `var _ group.Ordering = (*sequencer.MemorySequencer)(nil)` (and `… = (*sequencer.FencedSequencer)(nil)`) in the sequencer package proves both implementations satisfy the port.

### N1. `seqKey` — the collision-free `(group, epoch)` map key (validated)

Go map keys can't be `[]byte`, so encode `(group, epoch)` into a `string`. Use an **8-byte big-endian epoch prefix followed by the raw group bytes**. This is **injective**: the first 8 bytes uniquely determine the epoch, and the remaining bytes are exactly the group id — distinct `(group, epoch)` pairs can never collide (unlike `string(group)+string(epoch)` concatenation, which is ambiguous for variable-length group ids). *Validated: used as the key in all four register/registry implementations; all proof tests pass.*

```go
// seqKey encodes (group, epoch) into a collision-free map key: an 8-byte
// big-endian epoch prefix followed by the raw group bytes (injective).
func seqKey(group group.GroupID, epoch uint64) string {
	b := make([]byte, 8+len(group))
	binary.BigEndian.PutUint64(b[:8], epoch)
	copy(b[8:], group)
	return string(b)
}

// cloneRef returns a defensive copy so a caller mutating its slice cannot alter
// a decided value (the register must be immutable once written).
func cloneRef(r group.CommitRef) group.CommitRef {
	c := make(group.CommitRef, len(r))
	copy(c, r)
	return c
}
```

### N2. `MemorySequencer` — the canonical correct CP register (design spec §5.1/§5.5) — fully validated

The reference single-register implementation: a mutex-guarded `map[seqKey]CommitRef`, CAS semantics exactly per N0. This is **the** correct linearizable register (§5.5 "a single linearization point per group"); B1/B2 are operational ways to keep there being only **one** such register live per VNI. *Validated: `-race` clean; exactly one of 200 concurrent distinct refs accepted; decided value stable; idempotent winner re-accept; post-decision different ref rejected.*

```go
package sequencer

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"

	"github.com/trevex/mls-mlkem-go/mls/group"
)

// MemorySequencer is the reference in-process single-linearizable-register
// implementation of group.Ordering (design spec §5.1/§5.5): the map
// (group, epoch) → CommitRef under a mutex, with first-valid-writer-wins CAS
// and idempotent re-accept. It is the canonical correct CP register; B1/B2
// exist to guarantee only ONE such register is live per VNI (§5.3/§5.5).
type MemorySequencer struct {
	mu      sync.Mutex
	decided map[string]group.CommitRef
}

// NewMemorySequencer returns a ready, empty MemorySequencer.
func NewMemorySequencer() *MemorySequencer {
	return &MemorySequencer{decided: map[string]group.CommitRef{}}
}

var _ group.Ordering = (*MemorySequencer)(nil)

// AcceptCommit implements group.Ordering (design spec §5.1). It is linearizable:
// all calls are serialized by the mutex; the first valid commit for a fresh
// (group, epoch) wins; re-submitting the SAME commit returns true; any DIFFERENT
// commit for a decided (group, epoch) returns false.
func (s *MemorySequencer) AcceptCommit(ctx context.Context, g group.GroupID, epoch uint64, commit group.CommitRef) (bool, error) {
	key := seqKey(g, epoch)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ex, ok := s.decided[key]; ok {
		return bytes.Equal(ex, commit), nil // idempotent if same; reject if different
	}
	s.decided[key] = cloneRef(commit)
	return true, nil
}

// Decided returns the decided CommitRef for (group, epoch) and whether one
// exists. Exposed for fork-detection / monitoring (read-only; copies out).
func (s *MemorySequencer) Decided(g group.GroupID, epoch uint64) (group.CommitRef, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.decided[seqKey(g, epoch)]
	if !ok {
		return nil, false
	}
	return cloneRef(r), true
}
```

**Proof-test mapping → §5.1 (safety invariant) / §5.7 (Agreement ⊇ linearizability):** `TestSingleRegisterSafety` fires *N=200* goroutines, each submitting a **distinct** `CommitRef` for the **same** `(group, epoch)` to **one** `MemorySequencer`, and asserts **exactly one** `ok=true`. The race detector (`-race`) proves the mutex actually serializes the CAS (no torn read-modify-write). It then re-submits the winner (`ok=true`, idempotent) and a fresh different ref (`ok=false`, single-valued). This is a direct, executable demonstration of "for every `(group, epoch)` at most one Commit is ever accepted."

### N3. Split-brain & fork detection (design spec §5.2 / §5.3 / §5.6) — validated with the *real* MLS engine

§5.3's trap: **two** independent registers (e.g. two route reflectors each deciding "locally") are **two** linearizable registers, not one — and the §5.1 invariant is a property of a *single* register. Under split-brain RR-A accepts X and RR-B accepts Y≠X for the same epoch → **a real fork**. §5.2 says the crypto makes this **detectable** (the two branches' epoch *n+1* `epoch_authenticator`s differ) but not **preventable**. §5.6 turns detectable → actively detected by comparing `epoch_authenticator`s out-of-band.

The demonstration is most convincing with the **real engine**: take a converged 3-member group at epoch *n*; have **member 0** and **member 1** each `Commit(empty)` from that same epoch *n* **without** processing each other's commit (two branches). *Validated: this yields epoch *n+1* with two **distinct** `epoch_authenticator`s* (run: `fb4faa45…` vs `d0af6023…`). Two **independent** `MemorySequencer`s each `AcceptCommit` their own branch's `CommitRef` → **both return `ok=true`** (two "winners" = the fork the crypto could not prevent). Feeding both authenticators into the `EpochAuthenticatorRegistry` flags the fork on the second report. **The contrast is the lesson:** route both branches to **one** `MemorySequencer` and only the first wins (N2) — the fork is impossible. Two registers ⇒ fork; one register ⇒ safe.

```go
// EpochAuthenticatorRegistry records the epoch_authenticator(s) reported for each
// (group, epoch) and flags divergence — active fork detection (design spec §5.6
// item 1; the authenticator is DeriveSecret(epoch_secret, "authentication"),
// RFC 9420 §8.7). Two distinct authenticators for the same (group, epoch) is a
// detected fork (§5.2: incompatible epoch n+1 states ⇒ different authenticators).
type EpochAuthenticatorRegistry struct {
	mu   sync.Mutex
	seen map[string][][]byte // seqKey → set of distinct authenticators
}

// NewEpochAuthenticatorRegistry returns a ready, empty registry.
func NewEpochAuthenticatorRegistry() *EpochAuthenticatorRegistry {
	return &EpochAuthenticatorRegistry{seen: map[string][][]byte{}}
}

// Report records auth for (group, epoch) and returns fork=true iff more than one
// DISTINCT authenticator has now been reported for that (group, epoch). Reporting
// the same authenticator repeatedly never flags a fork (idempotent).
func (r *EpochAuthenticatorRegistry) Report(g group.GroupID, epoch uint64, auth []byte) (fork bool) {
	key := seqKey(g, epoch)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.seen[key] {
		if bytes.Equal(a, auth) {
			return len(r.seen[key]) > 1 // already known; fork iff set already diverged
		}
	}
	cp := make([]byte, len(auth))
	copy(cp, auth)
	r.seen[key] = append(r.seen[key], cp)
	return len(r.seen[key]) > 1
}

// Divergent reports whether a fork has been detected for (group, epoch).
func (r *EpochAuthenticatorRegistry) Divergent(g group.GroupID, epoch uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen[seqKey(g, epoch)]) > 1
}
```

**Proof-test mapping → §5.2/§5.3/§5.6:** `TestSplitBrainForkDetected` (in `package ironcore_test`, using `buildVNIGroup`) builds a real X-Wing 3-member group, drives two competing empty commits from the same epoch, asserts the two `CommitRef`s differ and **both** independent registers accept (the fork), asserts the two real `epoch_authenticator`s differ (§5.2), and asserts the registry flags the fork on the second report (§5.6). A companion `TestForkRegistryUnit` (in `package sequencer_test`, synthetic authenticators) proves the registry logic in isolation (same auth twice → no flag; two distinct → flag; third distinct still flagged).

### N4. B1 — fenced single-writer per VNI (design spec §5.5) — failover validated

§5.5 B1 (**the default**): *"Each VNI is owned by exactly one RR at a time via an epoch-numbered lease / fencing token. The standby takes over a VNI only after the old lease provably expires (lease TTL ≤ commit-acceptance timeout), so the two RRs can never both believe they own the VNI."* Two layers, both modeled:

1. **Lease (liveness / normal operation).** A `LeaseStore` grants per-VNI ownership for a TTL. While the primary holds a valid (unexpired) lease, a different owner's `Acquire` **fails** — the standby is fenced out. After expiry, the standby acquires. This is "primary/secondary by config" with the simplest valid static assignment (§12 open item #1: start static).
2. **Fencing token (hard safety, clock-independent).** Each successful acquisition mints a **strictly monotonic per-VNI token**. The protected resource — a shared, strongly-consistent `FencedRegister` (in deployment: the same etcd / k8s control plane backing the lease) — **rejects any write bearing a token below the highest it has seen**. So even a partitioned stale primary with a *lagging clock* that wrongly believes it still owns the VNI is fenced at the register: its old token < the standby's new token. This is the textbook fencing-token guarantee and it makes the safety proof **independent of clock skew** — the lease TTL bound (§5.5) governs *availability* (how long rekey is delayed), the token governs *safety*.

`MemoryLeaseStore` is `Clock`-injectable (reuse `group.Clock`) so failover is simulated deterministically with a fake clock — no `time.Sleep`. *Validated: standby fenced while primary lease valid; takeover only after expiry; standby token strictly greater; a stale-token write to the register rejected; exactly one commit per epoch throughout.*

```go
import (
	"errors"
	"fmt"
	"time"
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

// AcceptCommit implements group.Ordering. It (re)acquires or renews the VNI
// lease as needed; if another owner holds a valid lease it returns (false, nil)
// — fenced out, not an error (the standby simply cannot accept yet). On success
// it writes through the FencedRegister carrying its current fencing token.
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
```

**Proof-test mapping → §5.5 (fencing safety) / §5.4 (bounded rekey-only window):** `TestFencingSafety` (synthetic refs, fake clock):
1. Primary `FencedSequencer.AcceptCommit(epoch=5, X)` → `true` (acquires lease, token 1).
2. Standby `FencedSequencer.AcceptCommit(epoch=5, Y)` → `false` while the primary lease is valid (**both never accept the same epoch** — standby can't even reach the register).
3. Advance the fake clock past the lease TTL (the §5.4 *bounded rekey-only* window — purely a delay; no data-plane loss).
4. Standby `AcceptCommit(epoch=6, Z)` → `true` (takes over, token 2 > 1).
5. **Stale primary** `FencedRegister.Accept(vni, oldToken=1, epoch=6, …)` → `ErrFenced` (clock-independent token fence proves split-brain is impossible even with a lagging primary clock).
6. Assert the shared register holds exactly one commit per epoch (`X` at 5, `Z` at 6) — at no point did two owners decide different commits for the same epoch.

### N5. Deterministic recovery tie-break (design spec §5.6 item 2) — validated

§5.6: a stale/losing member re-converges via external Commit "under a fixed tie-break rule = lowest `Hash(Commit)`." `CanonicalCommit` selects, from candidate branch references, the one with the **lowest `Hash(commitRef)`** — a total order that is **independent of candidate order** and identical on every node, so all losing members pick the same canonical branch. To be fully deterministic even under the (cryptographically negligible) event of a hash collision, the comparison key is `Hash(ref) ‖ ref` (ties broken by the raw bytes), giving a strict total order over distinct refs. *Validated: identical winner across all candidate permutations; winner confirmed to have the minimum hash.*

```go
import "github.com/trevex/mls-mlkem-go/mls/cipher"

// CanonicalCommit returns the canonical branch reference for recovery: the
// candidate with the lowest Hash(commitRef) (design spec §5.6 tie-break). The
// result is independent of candidate order, so every losing member selects the
// same branch. Comparison key = Hash(ref) ‖ ref (a strict total order even under
// a hypothetical hash collision). Returns nil for an empty candidate set.
func CanonicalCommit(suite cipher.Suite, candidates []group.CommitRef) group.CommitRef {
	var best group.CommitRef
	var bestKey []byte
	for _, c := range candidates {
		key := append(suite.Hash(c), c...)
		if best == nil || bytes.Compare(key, bestKey) < 0 {
			best, bestKey = c, key
		}
	}
	return best
}
```

**Proof-test mapping → §5.6 (deterministic recovery):** `TestTieBreakDeterministic` computes `CanonicalCommit` over several **permutations** of the same candidate set and asserts an identical winner each time, and that the winner truly has the minimum `Hash`. This demonstrates the recovery rule converges all nodes on one branch regardless of the order in which they learn of the candidates. **Note (deferred):** the *execution* of recovery — generating the external Commit that rejoins the canonical branch and pushing it through the single linearization point (§5.6: "the external Commit also passes through the single linearization point — otherwise the recovery itself forks") — needs external-commit generation/join, not yet in `mls/group`. This plan delivers the **selection rule + its determinism proof**; see the roadmap.

### N6. Why this layer is "affordable" and where the contract stops (design spec §5.4 / §5.7 / §10.2)

§5.4 is the reason CP is the right call: MLS epoch advancement is **off the data path**; if the ordering register is briefly unavailable during failover, the only effect is **delayed rekey**, never dropped packets. The plan encodes this as *availability is a TTL knob* (lease TTL) while *safety is absolute* (the token fence + the single register). §5.7's proof statement — *Agreement = (DS register linearizability) ∘ (RFC 9420 cryptographic binding)* — is exactly what the four gates jointly demonstrate: N2 proves linearizability of one register; N3 proves that *without* it you keep only detectability (two registers fork) and that the authenticator comparison recovers detection; N4 proves B1 keeps exactly one register live per VNI under failover; N5 proves recovery converges deterministically. §10.2's trust boundary is honored throughout: the sequencer types take only `GroupID`, `epoch`, `CommitRef`, and (for detection) the public `epoch_authenticator` — never any group secret.

---

## File structure

| File | Status | Purpose |
|---|---|---|
| `mls/group/ports.go` | **changed** (Task 0) | Add `CommitRef` type + the `Ordering` interface next to the other four ports (N0). |
| `mls/group/ports_test.go` | **changed** (Task 0) | Compile-time/contract assertion that the in-package nil impls satisfy nothing new is needed; add a doc test referencing `Ordering` only if the file already exercises the ports (otherwise leave to the sequencer package). |
| `ironcore/sequencer/sequencer.go` | **new** (Task 1) | `seqKey`, `cloneRef`, `MemorySequencer` (+ `var _ group.Ordering`), `Decided` (N1, N2). |
| `ironcore/sequencer/sequencer_test.go` | **new** (Task 1) | `TestSingleRegisterSafety` (`-race`, N=200 concurrent), idempotency + single-valued unit assertions (N2). |
| `ironcore/sequencer/tiebreak.go` | **new** (Task 2) | `CanonicalCommit` (N5). |
| `ironcore/sequencer/tiebreak_test.go` | **new** (Task 2) | `TestTieBreakDeterministic` (permutation invariance + lowest-hash, N5). |
| `ironcore/sequencer/fork.go` | **new** (Task 3) | `EpochAuthenticatorRegistry` + `Report`/`Divergent` (N3). |
| `ironcore/sequencer/fork_test.go` | **new** (Task 3) | `TestForkRegistryUnit` (synthetic authenticators, N3). |
| `ironcore/sequencer/fencing.go` | **new** (Task 4) | `Lease`, `LeaseStore`, `MemoryLeaseStore`, `ErrFenced`, `FencedRegister`, `FencedSequencer` (+ `var _ group.Ordering`) (N4). |
| `ironcore/sequencer/fencing_test.go` | **new** (Task 4) | `TestFencingSafety` (fake-clock failover, token fence), `TestLeaseRenewRelease` (N4). |
| `ironcore/sequencer/clock_test.go` | **new** (Task 4) | `fakeClock` test helper (monotonic injectable `group.Clock`). |
| `ironcore/fork_test.go` | **new** (Task 5) | `TestSplitBrainForkDetected` — `package ironcore_test`, uses `buildVNIGroup` + real `group.Commit`/`EpochAuthenticator` + `sequencer.MemorySequencer`/`EpochAuthenticatorRegistry` (N3 integration gate). |

---

## Tasks

> **TDD discipline (REQUIRED SUB-SKILL `superpowers:test-driven-development`):** for every task, write the test(s) first, watch them fail (`nix develop -c go test ./… -run …` → red, usually a compile error against the not-yet-written type), then implement to green. One task = one commit. Before each commit run `nix develop -c gofmt -l <files>` (must print nothing) and `nix develop -c go vet ./mls/group/ ./ironcore/...` (clean). The property/invariant tests **are** the gates — keep their assertions strict and run the concurrency gate under `-race`.

### Task 0 — The `Ordering` port + `CommitRef` (`mls/group/ports.go`) — committed first

- [ ] **0.1** Add the `CommitRef` type and the `Ordering` interface to `mls/group/ports.go` exactly as in N0 (place them just after the `DeliveryService` block so the §4 "ports" grouping reads top-to-bottom; `context` is already imported). No implementation lives in `mls/group` — only the contract.
- [ ] **0.2** Build only: `nix develop -c go build ./mls/...` (no behavioral test here; the contract is exercised by the sequencer package's `var _ group.Ordering = …` assertions in later tasks). `gofmt`/`vet` clean. **Commit** ("mls/group: add Ordering port + CommitRef (design spec §5.1)").

### Task 1 — `MemorySequencer` + the single-register safety gate (`ironcore/sequencer`)

- [ ] **1.1** Write `ironcore/sequencer/sequencer_test.go` (`package sequencer`, so it can read `decided` for white-box stability checks — or `sequencer_test` using `Decided()`; prefer `sequencer_test` + `Decided()` for a black-box gate). `TestSingleRegisterSafety`: one `MemorySequencer`, fixed `(group, epoch)`, N=200 goroutines each `AcceptCommit` a **distinct** `CommitRef`; collect `ok` results with `sync/atomic`; assert **exactly one** `true`; assert `Decided()` returns the winner; assert idempotent re-accept of the winner (`true`) and that a fresh different ref now returns `false`. Add `TestSequencerIdempotentAndSingleValued` for the sequential CAS cases (first wins; same again → true; different → false; a *different* `(group, epoch)` is independent). Red (no `sequencer.go`).
- [ ] **1.2** Implement `ironcore/sequencer/sequencer.go` per N1+N2 (package doc comment: the IronCore ordering authority, design spec §5; `MemorySequencer`, `seqKey`, `cloneRef`, `Decided`, `var _ group.Ordering`). Green, including `nix develop -c go test -race ./ironcore/sequencer/ -run TestSingleRegisterSafety`. `gofmt`/`vet`. **Commit** ("ironcore/sequencer: MemorySequencer single-linearizable register + race-proven safety gate").

### Task 2 — Tie-break determinism (`ironcore/sequencer/tiebreak.go`)

- [ ] **2.1** Write `ironcore/sequencer/tiebreak_test.go` (`package sequencer_test`): `TestTieBreakDeterministic` under suite `0xF001` — pick ≥3 candidate refs, compute the winner, then assert `CanonicalCommit` over multiple **permutations** of the same set returns the byte-equal winner, and that no candidate has a strictly smaller `suite.Hash`. Add an empty-set case → `nil`, and a single-element case → that element. Red.
- [ ] **2.2** Implement `ironcore/sequencer/tiebreak.go` per N5. Green. `gofmt`/`vet`. **Commit** ("ironcore/sequencer: CanonicalCommit lowest-Hash tie-break (design spec §5.6)").

### Task 3 — Fork-detection registry + unit gate (`ironcore/sequencer/fork.go`)

- [ ] **3.1** Write `ironcore/sequencer/fork_test.go` (`package sequencer_test`): `TestForkRegistryUnit` — `Report(g, e, authA)` → `false`; `Report(g, e, authA)` again → `false` (idempotent, same authenticator); `Report(g, e, authB≠authA)` → `true`; `Divergent(g, e)` → `true`; a different `(g, e2)` is independent (`false`). Red.
- [ ] **3.2** Implement `ironcore/sequencer/fork.go` per N3 (`EpochAuthenticatorRegistry`, `Report`, `Divergent`). Green. `gofmt`/`vet`. **Commit** ("ironcore/sequencer: EpochAuthenticatorRegistry fork detection (design spec §5.6)").

### Task 4 — B1 fencing: lease store + fenced register + fenced sequencer (`ironcore/sequencer/fencing.go`)

- [ ] **4.1** Write `ironcore/sequencer/clock_test.go` (`package sequencer_test`): a `fakeClock` implementing `group.Clock` with a mutex-guarded `Now()` and an `advance(d)` helper.
- [ ] **4.2** Write `ironcore/sequencer/fencing_test.go` (`package sequencer_test`):
  - `TestFencingSafety` per N4's 6-step mapping: primary accepts epoch 5; standby fenced (`false`) while primary lease valid; advance clock past TTL; standby takes over epoch 6 with a strictly-greater token; a direct `FencedRegister.Accept` with the **stale** primary token → `ErrFenced`; assert the register holds exactly `X@5` and `Z@6`. Use two `FencedSequencer`s ("primary"/"standby") sharing one `MemoryLeaseStore` + one `FencedRegister` + one `fakeClock`.
  - `TestLeaseRenewRelease`: `Acquire` (token t), `Renew` keeps token t and extends expiry; after expiry a different owner `Acquire`s (token > t); `Renew` by the old owner now fails (`false`); `Release` by the current owner clears ownership.
  - `TestFencedSequencerWrongGroup`: `AcceptCommit` with a `GroupID` ≠ the configured one → error.
  Red (no `fencing.go`).
- [ ] **4.3** Implement `ironcore/sequencer/fencing.go` per N4 (`Lease`, `LeaseStore`, `MemoryLeaseStore`, `ErrFenced`, `FencedRegister`, `FencedSequencer`, `var _ group.Ordering`). Green. `gofmt`/`vet`. **Commit** ("ironcore/sequencer: B1 fenced single-writer per VNI — lease + fencing token (design spec §5.5)").

### Task 5 — Split-brain + real-MLS fork demonstration (`ironcore/fork_test.go`)

- [ ] **5.1** Write `ironcore/fork_test.go` (`package ironcore_test`, reusing the Plan-10 helper `buildVNIGroup`): `TestSplitBrainForkDetected` per N3 —
  1. `buildVNIGroup(t, suite0xF001, vni, 3)`; record `gid := nodes[0].GroupID()`, `epoch := nodes[0].Epoch()`.
  2. `commitA, _, _ := nodes[0].Group().Commit(group.CommitOptions{})`; `commitB, _, _ := nodes[1].Group().Commit(group.CommitOptions{})` — two competing empty commits from the **same** epoch; neither processes the other.
  3. `refA, refB := suite.Hash(commitA), suite.Hash(commitB)`; assert `!bytes.Equal(refA, refB)`.
  4. Two **independent** `sequencer.MemorySequencer`s: `regA.AcceptCommit(…refA)` and `regB.AcceptCommit(…refB)` both → `true` (the fork the crypto cannot prevent, §5.3); add a comment that routing both to **one** register would let only the first win (§5.1 — the lesson).
  5. `authA, authB := nodes[0].Group().EpochAuthenticator(), nodes[1].Group().EpochAuthenticator()`; assert `!bytes.Equal(authA, authB)` (§5.2). Use the **new** epoch (`nodes[0].Epoch()`) as the registry key.
  6. `far := sequencer.NewEpochAuthenticatorRegistry()`; `far.Report(gid, newEpoch, authA)` → `false`; `far.Report(gid, newEpoch, authB)` → `true` (§5.6 detection); `far.Divergent(gid, newEpoch)` → `true`.
  Make every assertion strict (`bytes.Equal`, exact `bool`). Red until the `sequencer` package + the engine are present (both already are after Tasks 1/3 + Plan 10).
- [ ] **5.2** Green: `nix develop -c go test ./ironcore/... ./mls/...` all green; run the concurrency gate once more with `-race`. `gofmt`/`vet` clean. **Commit** ("ironcore: split-brain + fork-detection demonstration over the real MLS engine (design spec §5.2/§5.3/§5.6)").

---

## Definition of Done

- [ ] `nix develop -c go build ./...` succeeds.
- [ ] `nix develop -c go test ./...` is **all green**, including the unchanged `mls/` KAT + active suites and the new `ironcore/sequencer/` + `ironcore/` tests.
- [ ] `nix develop -c go test -race ./ironcore/sequencer/ -run TestSingleRegisterSafety` is green (the linearizability proof is race-clean).
- [ ] `nix develop -c gofmt -l mls/group ironcore` prints **nothing**; `nix develop -c go vet ./mls/group/ ./ironcore/...` is clean.
- [ ] **§5.1 — single-register safety:** with N=200 concurrent distinct refs for one `(group, epoch)` on one `MemorySequencer`, **exactly one** is accepted; the decided value is stable; the winner re-accepts idempotently; a different ref is rejected post-decision. (`-race`.)
- [ ] **§5.2/§5.3/§5.6 — split-brain + detection:** two **independent** `MemorySequencer`s each accept a different real-MLS branch's `CommitRef` for the same `(group, epoch)` (two winners = the fork); the two branches' real `epoch_authenticator`s differ; the `EpochAuthenticatorRegistry` flags the fork on the second report.
- [ ] **§5.5 — fencing safety:** a standby `FencedSequencer` cannot accept while the primary holds a valid lease; after lease expiry it takes over with a strictly-greater token; a stale-token write is `ErrFenced`; the shared register holds exactly one commit per epoch — **never** two different commits for one epoch.
- [ ] **§5.6 — tie-break determinism:** `CanonicalCommit` returns the byte-identical lowest-`Hash` winner across all candidate permutations.
- [ ] Both `MemorySequencer` and `FencedSequencer` satisfy `group.Ordering` (compile-time `var _` assertions); the `Ordering` port + `CommitRef` live in `mls/group/ports.go`; the implementations live in `ironcore/sequencer` (VNI-agnostic; imports only `mls/group` + `mls/cipher`; no import cycle).
- [ ] stdlib-only; no new module dependencies; the only change outside `ironcore/` is the Task 0 `mls/group/ports.go` port addition.

---

## Notes for the remaining roadmap (out of scope here)

- **External-commit recovery EXECUTION (design spec §5.6 item 2 / §9 / §10.3 "Join").** This plan delivers the recovery **selection rule** (`CanonicalCommit`) and its determinism proof, plus active fork **detection** (`EpochAuthenticatorRegistry`). The *execution* — generating the external Commit (`external_init` proposal + `ExternalPub` from a published signed `GroupInfo`) that rejoins the canonical branch, and pushing it **through the single linearization point** (§5.6: otherwise the recovery itself forks) — needs external-commit generation/join which is **not yet in `mls/group`**. That is the next plan; it is also the restart-rejoin path (§9). It will likely add a small `Recoverer` helper in `ironcore/sequencer` (or `ironcore`) that wires `CanonicalCommit` → external-commit build → `Ordering.AcceptCommit`.
- **B2 — consensus-backed register (design spec §5.5).** A Raft/Paxos compare-and-set `Ordering` implementation (odd quorum / 3rd witness; seamless failover). The `Ordering` port already admits it; only the implementation differs. metalbond chooses B1 (default) vs B2.
- **Membership controller (design spec §10.3).** Designated-committer election (lowest-index active leaf, deterministic handover — made race-safe precisely by the §5.1 single-commit rule proven here), `external_senders`-driven Add/Remove, periodic empty-Update rekey for PCS. Wants a small `Group.Members()` accessor (deliberately not added here).
- **metalbond `Ordering` + `DeliveryService` adapters.** Live in metalbond's repo: implement `group.Ordering` (B1 lease over etcd / the k8s control plane) and `group.DeliveryService` against its wire protocol. This library never imports metalbond protobufs; `ironcore/sequencer`'s in-memory `MemorySequencer`/`MemoryLeaseStore`/`FencedRegister` are the reference correctness oracle metalbond's implementation is tested against.
- **gRPC `MLSClient` interop (design spec §6).** Orthogonal to ordering (classical-suite conformance vs OpenMLS/mls-rs); the ordering layer is validated by the §5 property gates, for which there is no IETF KAT.
```
