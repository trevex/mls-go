# metalnet/metalbond Deterministic Simulation Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Depends on** the merged `mls/group` engine (`NewGroup`, `Commit`, `ProcessCommit`, `JoinFromWelcome`, `ExternalCommit`/`ProcessExternalCommit`, `PublishGroupInfo`, `EpochAuthenticator`, `Epoch`, `OwnLeaf`, `ActiveLeaves`, the codecs), the `ironcore` layer (`Controller`, `DeriveSAKeys`, `RecoverViaExternalCommit`, `GroupID`, `NewVNIGroup`), and `ironcore/sequencer` (`CanonicalCommit`, `EpochAuthenticatorRegistry`, `MemorySequencer`). **There is no MLS KAT for this layer** — the gates are deterministic property / invariant tests that drive the *real* library and assert the §3.5 resilience invariants (incl. zero key-loss) over seeds 1..20.
>
> **Empirically de-risked during planning (throwaway `package main` under `nix develop -c go run`, since deleted; the working tree was left clean — only this plan file is new).** Validation log (real run):
> 1. **Scheduler determinism** — a min-heap keyed by `(at, seq)` with a monotonic `seq` tie-break popped a **byte-identical** order across two runs of the same seed, a **different** order for a different seed, and a **strict total order** (no duplicate `(at,seq)` keys). ✓
> 2. **AP fork resolution converges through the PUBLIC API** — a real 3-member X-Wing (`0xF001`) VNI group at epoch 2 was forked (node-0 and node-1 each empty-`Commit` from epoch 2 → divergent `epoch_authenticator`s); the client glue *(observe ≥2 commits for `(vni,base)` → `sequencer.CanonicalCommit` → if off-branch `ironcore.RecoverViaExternalCommit` to the winner's `GroupInfo` → re-broadcast)* converged **all three** members to byte-equal `EpochAuthenticator` **and** `DeriveSAKeys.Key`. **Single-loser** (3rd member followed the canonical branch): converged in 3 message-steps to epoch 4. **Two-loser** (3rd member followed the non-canonical branch): converged in 11 message-steps to epoch 8 — each off-canonical member re-joins via its own external commit, which serialize by the canonical tie-break (one wins each contested epoch; the rest are superseded and retry at the next epoch — the AP analogue of `ErrRecoverySuperseded`). **Result: the existing public API is sufficient; NO library helper is required.** The glue lives in the sim client actor. (An optional `ironcore.ResolveFork(seen, current) → (recoverTo, bool)` convenience wrapper was considered and **rejected** for v1 — see Notes.)
> 3. **Make-before-break + sender-lag ⇒ ZERO key loss** — `DeriveSAKeys` over consecutive epochs produced **distinct SPIs and distinct Keys** (SPI demux is sound). Modeling installed-SA set `[epoch−W … epoch]`, sender-lag = "send under the min group-wide epoch", a packet@p is decryptable by receiver r iff `epoch_r − W ≤ p` (and `p ≤ epoch_r`, always true since `p = min ≤ epoch_r`); the binding constraint is **`spread ≤ W`** where `spread = max_epoch − min_epoch`. For a lagged rekey followed by a 2-loser fork+recovery telescope the observed **max spread was 2**, so **minimum W = 2** gave **0** lost packets. **Negative control** (W=0, no sender-lag — send under own current epoch): **22** lost packets — the invariant has teeth. ✓

**Goal:** Build a **deterministic discrete-event simulation harness** (`sim/` + `cmd/metalsim/`) that drives the *real* `ironcore`+`mls` stack to model metalnet over a realistic AP metalbond: two **independent eventually-consistent fan-out reflectors** (no shared register/lease/consensus), N metalnet client hosts, M VNIs, under failover / packet-drop / partition / churn faults. It is primarily a **fault-injection property test** that the §3.5 resilience invariants hold — every VNI **eventually converges** (byte-equal `epoch_authenticator` **and** ESP SA key), **no permanent fork** (every divergence detected + recovered), behind/recovered members re-converge within the settle window, membership is correct, and — the headline — **ZERO tenant packet is ever undecryptable due to a rekey, fork, or DS failover** (the §3.7 make-before-break + sender-lag data-plane invariant). Secondary: reproducible metrics incl. fork stats and data-plane stats. 5 built-in scenarios; a negative-control test proving inv. 5 is not vacuous. **Zero new dependencies** (root module stays stdlib-only).

**Architecture (design spec §2):** An event-queue actor system. A single-threaded `Scheduler` holds a `container/heap` min-heap of `Event`s keyed by `(at uint64, seq uint64)`; `Run` seeds one `*math/rand.Rand` from the scenario seed, schedules the scenario's initial events, then pops events in `(at, seq)` order; each handler mutates actor state, calls the real library, and schedules follow-on events. **Two `DS` actors** are dumb AP fan-out reflectors (per-VNI committed log + GroupInfo cache + catch-up service; "failover" = one simply stops then restarts; no lease, no ownership). **N `Client` actors** each run a real `ironcore.Controller` per VNI plus the naive-protocol glue: optimistic commit (via an `optimisticOrdering` adapter that always accepts — the AP "no register" model), inbound `HandleCommit`, **fork detection + resolution** (`seen[(vni,base)]` → `CanonicalCommit` → `Controller.AutoRecover` when off-canonical), log-replay / external-commit catch-up, periodic rekey, and the **data-plane model** (per-epoch SA cache of the last `W` epochs, heartbeat-driven min-epoch sender-lag, dataPacket decryptability checks). The `Bus` applies seeded faults (drop / latency+jitter / partition) per delivery. Safety lives entirely in the clients' MLS state machines + glue, never in the DS. **Determinism is sacred** (enforced below).

**Determinism rules (HARD — enforced in every file):** NO goroutines, NO channels, NO `time.Now()`/`time.After()`/`time.Sleep` in control flow (CPU timing is *measured* via `time.Since` for metrics only and never feeds scheduling), NO map-iteration-order dependence (every map iterated in control flow is key-sorted first), ONE `*rand.Rand` seeded from the scenario seed threaded through all fault/timing/churn decisions. `Run(scenario, seed)` ⇒ byte-identical event trace + identical metrics.

**Tech Stack:** Go 1.26 standard library only (hard constraint; `make check-zero-dep` must stay green). `sim/` imports only: `container/heap`, `math/rand`, `sort`, `time` (metrics only), `text/tabwriter`, `encoding/json`, `encoding/binary`, `crypto/ed25519`, `crypto/rand` (key material at setup only), `crypto/sha256` (content-hash dedup), `bytes`, `context`, `fmt`, `errors` — plus the in-repo `mls/*` and `ironcore/*` packages. `cmd/metalsim` adds `flag`, `os`. No third-party deps anywhere.

**Spec reference:** Design spec `docs/superpowers/specs/2026-06-28-metalnet-simulation-design.md` **in full** — §2 (architecture/file layout/determinism), §3 (Bus/DS/Client/Fault/Invariant/Metrics + §3.7 data-plane make-before-break+sender-lag), §4 (5 scenarios), §5 (CLI), §6 (testing gates), §7 (async loss detection + AP `Ordering` adapter), §8 (open questions: committer-election races, settle sizing, partition+fork, read-only observables), §9 (CP-option framing — out of scope), §10 (definition of done). The CP `FencedSequencer`/`LeaseStore`/shared-register upgrade is **explicitly out of scope**; a per-client `optimisticOrdering` (always-accept) models AP.

> **Go invocation convention:** Go is **not** on `PATH`. Every Go command runs through the nix devshell, e.g. `nix develop -c go test ./sim/...`. Expect a harmless `Entered Go dev shell: …` banner (and possibly `warning: Git tree … is dirty`) on stderr. The determinism gate runs the same seed twice and diffs the trace: `nix develop -c go test ./sim/ -run TestDeterminism`.

---

## Definition of Done (design spec §10)

- [ ] `sim/` engine: `scheduler.go`, `event.go`, `bus.go`, `ds.go`, `client.go`, `fault.go`, `invariant.go`, `metrics.go`, `scenario.go`, `sim.go` — AP DS + client actors (with fork-resolution glue + data-plane model), fault model, invariant checker (incl. inv. 5 + the negative control), metrics (incl. fork stats). Stdlib-only; **zero new deps** (`make check-zero-dep` green).
- [ ] `cmd/metalsim/main.go` CLI; `make sim` target wired into the Nix workflow.
- [ ] **Determinism gate** passes: same `(seed, scenario)` ⇒ byte-identical event trace + identical metrics.
- [ ] All **5 scenarios** pass their invariant assertions across **seeds 1..20**; `split_brain` shows every fork **detected + recovered + VNI converged**, with reported fork stats (count, detection latency, recovery rounds, lost rekeys).
- [ ] **Zero key-loss (inv. 5) holds in every scenario across all seeds** — no data packet ever undecryptable due to rekey/fork/failover — and the report states the **minimum SA-overlap depth `W`** and **max send-lag** that achieved it.
- [ ] **Negative-control** test confirms the checker has teeth: with make-before-break disabled (`W=0`, no sender-lag) a rekey/fork scenario MUST produce **PACKET-LOSS FAIL**.
- [ ] Metrics report emits (text table default + `-json`), reproducible by seed.
- [ ] **Library code unchanged** (de-risk #2 proved no helper is needed); `nix develop -c go vet ./...` and `gofmt -l` clean.

---

## File Structure

| Path | Responsibility |
|------|----------------|
| `sim/event.go` | `ActorID`, `Envelope`, `MsgType`, `Event`, `EventKind`, `TimerKind`, `FaultOp`, `ChurnOp`, content-hash helper. The shared vocabulary. |
| `sim/scheduler.go` | `Scheduler{clock, pq, seq, rng}`: `container/heap` min-heap on `(at, seq)`; `Schedule`, `Pop`, `Now`, `Rand`. |
| `sim/fault.go` | `FaultConfig` + seeded per-delivery decisions (`drop`, `latency`, `jitter`, partition test, ds-down test). |
| `sim/bus.go` | `Bus`: per-VNI subscribe/publish; fault application per delivery; dedup metadata. |
| `sim/ds.go` | `DS` actor: AP fan-out + per-VNI commit log + GroupInfo cache + catch-up; down/restart. |
| `sim/client.go` | `Client` actor: `ironcore.Controller` per VNI + commit/catch-up/**fork-resolve**/recover + the §3.7 data-plane SA cache + heartbeat min-epoch sender-lag. |
| `sim/invariant.go` | `InvariantChecker`: the 5 §3.5 invariants incl. inv. 5 (zero key-loss, checked continuously) + negative-control plumbing. |
| `sim/metrics.go` | `Metrics` (incl. fork stats + data-plane stats + CPU timing) + text/JSON report. |
| `sim/scenario.go` | `Scenario` + the 5 built-ins (`nominal`, `drops`, `ds_down`, `partition_recover`, `split_brain`). |
| `sim/sim.go` | `Run(scenario, seed) → Result{InvariantsHeld, Metrics, Trace}`; the event loop; identity/key-package directory; setup. |
| `cmd/metalsim/main.go` | CLI: `-scenario -clients -vnis -seed -drop -rounds -json -v`. |
| `sim/*_test.go` | Per-component unit tests + determinism gate + per-scenario seeded property tests + the negative-control test. |
| `Makefile` | add `sim:` target. |

---

## Design notes (read before implementing)

### N0. Determinism mechanics
`Scheduler` keeps `clock uint64` (logical time = the `At` of the last popped event), a `seq uint64` monotonic counter assigned at `Schedule` time, and the single `*rand.Rand`. The heap `Less` is `a.At < b.At || (a.At == b.At && a.Seq < b.Seq)`. Because `seq` is assigned in scheduling order and never reused, `(At, Seq)` is a strict total order ⇒ deterministic pop. All randomness (drop coin, jitter, churn target, which competing committer "acts first" under a race) comes from `Scheduler.Rand()`. Every `for k := range someMap` in control flow is replaced by sorting the keys first (helper `sortedVNIs`, `sortedActors`). The trace is a `[]string`; each handler appends one line `fmt.Sprintf("%d|%s", at, descr)`; two same-seed runs must produce equal `[]string`.

### N1. AP `Ordering` adapter (spec §7)
The `Controller.commitAndOrder`/`AutoRecover` paths call `Ordering.AcceptCommit`. In AP there is no register, so the sim configures every `Controller` with:
```go
type optimisticOrdering struct{}
func (optimisticOrdering) AcceptCommit(context.Context, group.GroupID, uint64, group.CommitRef) (bool, error) {
    return true, nil // commit optimistically; loss discovered async by fork resolution
}
```
Loss is discovered **asynchronously** by the client's fork-resolution logic (N3), never synchronously. This is the genuine test of recovery composing under async loss detection.

### N2. Identity / KeyPackage directory (needed for real Add/Reconcile)
`Controller.Reconcile(desired)` needs a `KeyPackageResolver` to map a desired identity → published `KeyPackage` MLSMessage bytes, and the joiner needs its `initPriv`/`leafPriv` to `JoinViaWelcome`. The sim owns a `dir *kpDirectory` (in `sim.go`) mapping `identity → {kpMsg, initPriv, leafPriv, signer, cred}`, populated at setup and whenever a client intends to join a VNI. Every `Controller`'s `Resolve` closure reads `dir.kpMsg(identity)`. The committer's `Reconcile` returns `WelcomeMsg`; the client broadcasts it; the joiner client looks up its own `initPriv`/`leafPriv` from `dir` and calls `JoinViaWelcome`. This is faithful to §10.3.

### N3. Fork detection + resolution glue (de-risked — keep in the client actor)
On inbound `commit` for `(vni, base)`: dedup by content hash; append `ref` to `seen[vniKey(vni,base)]`; cache the carrying `GroupInfo` by `ref` (DS-served). If `Controller.Epoch() == base`, `HandleCommit` (advances iff it matches; rejects stale/competing — MLS linearizes the client's own view). After any epoch change, **fork-resolve**: for every contested `(vni, base)` where `len(seen) ≥ 2` and this client applied a ref at `base`, compute `canon := sequencer.CanonicalCommit(suite, seen)`; if the applied ref ≠ `canon` and not yet recovered for that base, call `Controller.AutoRecover(ctx, seen, fetchGI)` (which wraps `RecoverViaExternalCommit` + rotates SA), then broadcast the returned recovery commit to **both** DS. `fetchGI` reads the client's per-ref GroupInfo cache (populated from DS GroupInfo fan-out). Multiple losers serialize via the canonical tie-break across rounds (de-risk confirmed termination). The committer for the canonical branch processes the recovery commit via `HandleCommit` (it dispatches `ProcessExternalCommit` on `new_member_commit` sender). Report each detected fork to a shared `*sequencer.EpochAuthenticatorRegistry` (inv. 2).

### N4. Data-plane model (spec §3.7 — the headline; de-risked W=2)
Each client per VNI keeps `saCache map[uint64]ironcore.SA` (epoch → SA) and a ring of the last `W` epochs. On **every** epoch advance (`HandleCommit`/`AutoRecover`/`Rekey`/join success) the client derives the new SA via `Controller.CurrentSA()` and inserts it, then trims epochs older than `cur−W` (you CANNOT re-derive a past epoch — forward secrecy — so cache **at derive time**). The **installed-SA set** a client can decrypt with = `{e : cur−W ≤ e ≤ cur and e ∈ saCache}`, indexed by SPI (`SA.SPI`, which encodes `(VNI, epoch)`). **Heartbeats** carry each member's current epoch; each client tracks `peerEpoch[vni][actor]`. The **send-epoch** (sender-lag policy) = `min` over all live co-VNI members' epochs (incl. self) — a sender advances to epoch N only once the group-wide min ≥ N. A `dataPacket` event picks a random live member, tags the packet with that member's **send-SA SPI/epoch**, and the Bus fans it out. **inv. 5** fires at each *delivery* to a live co-VNI member: the receiver must hold a matching SA by SPI; a non-dropped undecryptable packet ⇒ **PACKET-LOSS FAIL** (with epoch/fork/failover context). A *transport-dropped* packet is tracked separately and is **not** a failure. `W` and the max observed send-lag are reported; the property tests assert zero loss with the configured `W` (default 4, comfortably above the de-risked min of 2).

### N5. Negative control (inv. 5 has teeth)
`Client` has a `mbbDisabled bool`. When set: `W` is forced to 0 (cache only the current epoch) **and** sender-lag is off (send under the client's own current epoch, not the group min). A dedicated `TestNegativeControl_PacketLoss` runs a rekey+fork scenario with `mbbDisabled=true` and asserts the checker reports **PACKET-LOSS FAIL** (`Result.InvariantsHeld == false` with a non-empty `PacketLoss` detail). This proves inv. 5 is not vacuous.

### N6. Settle window (spec §8.2)
After the scenario's scripted faults/churn end, `Run` lifts all faults and continues popping events until the queue is **quiescent** (empty) or `settleRounds` logical rounds elapse, scheduling periodic rekey/heartbeat/reconcile timers so recovery completes. Invariants 1–4 are evaluated **only after** quiescence; inv. 5 is evaluated **continuously**. Default `settleRounds` is per-scenario and chosen `> max in-flight latency + worst-case recovery rounds`.

---

## Tasks

> Strict TDD, bite-sized, one commit per task. Each task: write the test (red), implement (green), `nix develop -c go vet ./sim/...` + `gofmt -w sim cmd`. Commit message ends with the `Co-Authored-By` trailer.

### Task 1 — `sim/event.go`: the shared vocabulary

- [ ] **Test** `sim/event_test.go`: `TestContentHashStable` — `contentHash(b)` is deterministic and distinguishes distinct payloads; `TestEnvelopeKindString` — `MsgType.String()` round-trips for trace readability.
- [ ] **Implement** `sim/event.go`:

```go
package sim

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// ActorID identifies an actor in the simulation. Clients are 0..C-1; the two
// DS reflectors are C and C+1. -1 means "broadcast to all VNI subscribers".
type ActorID int

const Broadcast ActorID = -1

// MsgType enumerates the envelope payload kinds (design spec §3.1).
type MsgType int

const (
	MsgCommit MsgType = iota // real MLS commit bytes (member or external)
	MsgWelcome               // real MLS Welcome bytes (joiner)
	MsgGroupInfo             // real signed GroupInfo bytes (recovery/external join)
	MsgHeartbeat             // {epoch} liveness beacon (drives min-epoch sender-lag)
	MsgLogRequest            // catch-up request {fromEpoch}
	MsgLogReply              // catch-up reply (carries commit records)
	MsgData                  // tenant ESP data packet {spi, epoch}
)

func (m MsgType) String() string {
	switch m {
	case MsgCommit:
		return "commit"
	case MsgWelcome:
		return "welcome"
	case MsgGroupInfo:
		return "groupInfo"
	case MsgHeartbeat:
		return "heartbeat"
	case MsgLogRequest:
		return "logRequest"
	case MsgLogReply:
		return "logReply"
	case MsgData:
		return "data"
	default:
		return "unknown"
	}
}

// Envelope is one in-flight message (design spec §3.1).
type Envelope struct {
	VNI      uint32
	Type     MsgType
	Src      ActorID
	Dst      ActorID // Broadcast or a specific actor
	Base     uint64  // base epoch a commit was produced FROM (commit), or data/heartbeat epoch
	External bool    // commit is a new_member_commit (external)
	Payload  []byte  // real MLS/ironcore bytes (commit/welcome/groupInfo) or nil
	SPI      uint32  // for MsgData: the sender's send-SA SPI
	Records  []CommitRecord // for MsgLogReply
	Joiner   string  // for MsgWelcome: identity the Welcome is addressed to
	Hash     string  // content hash for dedup (set by sender)
}

// CommitRecord is one entry in a DS per-VNI committed log (design spec §3.2).
type CommitRecord struct {
	Base     uint64
	External bool
	Bytes    []byte
	Hash     string
}

// EventKind tags an event's dispatch (design spec §2).
type EventKind int

const (
	KindDeliver EventKind = iota // deliver Env to Actor
	KindTimer                    // a scheduled timer fires on Actor
	KindFault                    // apply/lift a fault
	KindChurn                    // membership change
)

// TimerKind enumerates client/DS timers.
type TimerKind int

const (
	TimerRekey     TimerKind = iota // committer issues a PCS Update
	TimerHeartbeat                  // client emits a heartbeat
	TimerReconcile                  // committer reconciles desired vs current
	TimerData                       // a tenant data packet is generated
	TimerCatchup                    // client retries catch-up
	TimerDSRestart                  // a downed DS restarts
)

// FaultOp toggles a fault (design spec §3.4).
type FaultOp struct {
	Kind  faultKind
	On    bool
	DS    ActorID // for ds_down
	SideA []ActorID
	SideB []ActorID
}

// ChurnOp is a scheduled membership change (design spec §3.3).
type ChurnOp struct {
	Join   bool
	Client ActorID
	VNI    uint32
}

// Event is one scheduled action (design spec §2).
type Event struct {
	At    uint64
	Seq   uint64
	Kind  EventKind
	Actor ActorID
	Env   Envelope
	Timer TimerKind
	Fault FaultOp
	Churn ChurnOp
}

// contentHash is the dedup/identity hash of a message payload.
func contentHash(b []byte) string {
	h := sha256.Sum256(b)
	return string(h[:])
}

// vniKey encodes (vni, epoch) into a collision-free map key.
func vniKey(vni uint32, epoch uint64) string {
	b := make([]byte, 12)
	binary.BigEndian.PutUint32(b[:4], vni)
	binary.BigEndian.PutUint64(b[4:], epoch)
	return string(b)
}

// CommitRef mirrors group.CommitRef for sim-local fork bookkeeping.
type CommitRef = []byte

var _ = fmt.Sprintf
```

### Task 2 — `sim/scheduler.go`: deterministic min-heap (de-risk #1)

- [ ] **Test** `sim/scheduler_test.go`:
  - `TestSchedulerPopOrder` — schedule events with shuffled `At` (from one `*rand.Rand`); pop and assert non-decreasing `At` and, within equal `At`, increasing `Seq`.
  - `TestSchedulerDeterministic` — two schedulers seeded identically, fed identical `Schedule` sequences, produce identical pop streams (the de-risk #1 guarantee).
  - `TestSchedulerTieBreakStrictTotalOrder` — no two popped events share `(At, Seq)`.
- [ ] **Implement** `sim/scheduler.go`:

```go
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
func (h eventHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)        { *h = append(*h, x.(Event)) }
func (h *eventHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	*h = old[:n-1]
	return e
}
```

### Task 3 — `sim/fault.go`: seeded fault decisions

- [ ] **Test** `sim/fault_test.go`:
  - `TestDropDeterministic` — same seed ⇒ same drop coin sequence; `dropProb=0` ⇒ never drop, `=1` ⇒ always drop.
  - `TestPartitionBlocks` — `src→dst` blocked iff they are on opposite sides of an active partition; symmetric.
  - `TestLatencyJitterBounded` — `latency(rng)` ∈ `[base, base+jitter]`.
- [ ] **Implement** `sim/fault.go`:

```go
package sim

import (
	"math/rand"
	"sort"
)

type faultKind int

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

// sortedActors returns a stable, sorted copy (determinism: never range a map directly).
func sortedActors(m map[ActorID]bool) []ActorID {
	out := make([]ActorID, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
```

### Task 4 — `sim/bus.go`: per-VNI fan-out + fault application

- [ ] **Test** `sim/bus_test.go`:
  - `TestBusFanout` — `Publish(broadcast)` schedules one `deliver` per subscriber except the source; `Dst != Broadcast` schedules exactly one.
  - `TestBusDropExcludesDelivery` — with `DropProb=1` no `deliver` events are scheduled; with a `MsgData` drop the metrics record a transport drop, not a packet loss.
  - `TestBusPartitionBlocks` — partitioned `src→dst` is not delivered.
- [ ] **Implement** `sim/bus.go`:

```go
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
```

### Task 5 — `sim/ds.go`: AP fan-out reflector + log + catch-up

- [ ] **Test** `sim/ds_test.go`:
  - `TestDSFanout` — a commit sent to a DS is re-published to all VNI subscribers; appended to the per-VNI log in receive order.
  - `TestDSGroupInfoCache` — last GroupInfo per VNI is cached; `logRequest{fromEpoch}` returns records ≥ fromEpoch.
  - `TestDSDownStopsFanout` — a downed DS neither fans out nor serves catch-up; after restart it serves again.
  - `TestDSTwoLogsDiverge` — two DS handed different commits for the same base hold different logs (faithful AP).
- [ ] **Implement** `sim/ds.go`:

```go
package sim

import "sort"

// DS is one MetalBond reflector: a dumb, eventually-consistent AP fan-out with a
// per-VNI commit log + GroupInfo cache + catch-up service (design spec §3.2).
// NO register, NO lease, NO ownership, NO consensus.
type DS struct {
	id      ActorID
	bus     *Bus
	faults  *faultState
	logs    map[uint32][]CommitRecord     // vni -> received-order commit log
	giCache map[uint32]map[string][]byte  // vni -> ref(hash) -> GroupInfo bytes
	latest  map[uint32][]byte             // vni -> latest GroupInfo bytes
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
```

### Task 6 — `sim/client.go` part A: Controller wiring + commit/inbound/catch-up

- [ ] **Test** `sim/client_test.go`:
  - `TestClientFounderCommitsAdd` — a founder client `Reconcile`s an Add; the new client `JoinViaWelcome`s; both converge (epoch, EA).
  - `TestClientHandleStaleCommitRejected` — a commit for an already-advanced epoch is a no-op (MLS first-wins).
  - `TestClientCatchupViaLog` — a client that missed a commit catches up via `logRequest`/`logReply` replay.
- [ ] **Implement** `sim/client.go` (part A — the per-VNI controller state + inbound/commit/catch-up; fork-resolve + data plane added in Tasks 7–8):

```go
package sim

import (
	"context"
	"crypto"
	"sort"
	"time"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

// optimisticOrdering is the AP "no register" adapter (design spec §7 / N1).
type optimisticOrdering struct{}

func (optimisticOrdering) AcceptCommit(context.Context, group.GroupID, uint64, group.CommitRef) (bool, error) {
	return true, nil
}

// vniState is one client's per-VNI state.
type vniState struct {
	ctrl      *ironcore.Controller
	joined    bool
	seen      map[string][][]byte           // vniKey(vni,base) -> competing commit refs
	giByRef   map[string][]byte             // ref(hash) -> GroupInfo bytes (for recovery)
	applied   map[uint64][]byte             // base -> the ref this client applied at base
	recovered map[uint64]bool               // base -> already recovered
	// data plane (Task 8)
	saCache   map[uint64]ironcore.SA        // epoch -> SA (derive-time cache; never re-derive)
	peerEpoch map[ActorID]uint64            // last heartbeat epoch per co-VNI member
}

func newVNIState() *vniState {
	return &vniState{
		seen: map[string][][]byte{}, giByRef: map[string][]byte{},
		applied: map[uint64][]byte{}, recovered: map[uint64]bool{},
		saCache: map[uint64]ironcore.SA{}, peerEpoch: map[ActorID]uint64{},
	}
}

// Client is one metalnet host actor (design spec §3.3).
type Client struct {
	id          ActorID
	suite       cipher.Suite
	signer      crypto.Signer
	identity    string
	vnis        map[uint32]*vniState
	bus         *Bus
	sched       *Scheduler
	dir         *kpDirectory
	dsIDs       []ActorID
	metrics     *Metrics
	checker     *InvariantChecker
	W           int  // SA-overlap depth
	mbbDisabled bool // negative control: W=0 + no sender-lag
}

func newClient(id ActorID, suite cipher.Suite, signer crypto.Signer, identity string,
	bus *Bus, s *Scheduler, dir *kpDirectory, dsIDs []ActorID, m *Metrics, ck *InvariantChecker, W int) *Client {
	return &Client{
		id: id, suite: suite, signer: signer, identity: identity,
		vnis: map[uint32]*vniState{}, bus: bus, sched: s, dir: dir,
		dsIDs: dsIDs, metrics: m, checker: ck, W: W,
	}
}

func ctx() context.Context { return context.Background() }

// foundVNI makes this client the founder of vni (epoch 0 group).
func (c *Client) foundVNI(vni uint32) {
	st := newVNIState()
	g := c.dir.newFounderGroup(c.suite, vni, c.identity, c.signer)
	cfg := c.controllerCfg(vni)
	ctrl, err := ironcore.NewController(cfg, g)
	if err != nil {
		panic(err)
	}
	st.ctrl, st.joined = ctrl, true
	c.vnis[vni] = st
	c.bus.Subscribe(vni, c.id)
	c.cacheCurrentSA(vni)
}

// prospectiveVNI registers this client as a prospective joiner of vni (no group
// yet; will JoinViaWelcome). Its KeyPackage is published to the directory.
func (c *Client) prospectiveVNI(vni uint32) {
	st := newVNIState()
	cfg := c.controllerCfg(vni)
	ctrl, _ := ironcore.NewController(cfg, nil) // g=nil until welcome
	st.ctrl = ctrl
	c.vnis[vni] = st
	c.dir.publishKeyPackage(c.suite, vni, c.identity, c.signer)
	c.bus.Subscribe(vni, c.id) // peers with the bus so it receives the Welcome
}

func (c *Client) controllerCfg(vni uint32) ironcore.ControllerConfig {
	return ironcore.ControllerConfig{
		VNI:       vni,
		Suite:     c.suite,
		Ordering:  optimisticOrdering{},
		Clock:     fixedClock{},
		Validator: group.BasicCredentialValidator{},
		Cred:      c.dir.cred(c.identity),
		Signer:    c.signer,
		Lifetime:  maxLifetime(),
		Resolve:   c.dir.resolver(vni),
	}
}

// reconcile is invoked on the TimerReconcile: the committer drives the desired
// membership set toward reality (design spec §3.3 / §10.3).
func (c *Client) reconcile(vni uint32, desired [][]byte) {
	st := c.vnis[vni]
	if st == nil || !st.joined || !st.ctrl.IsCommitter() {
		return
	}
	t0 := time.Now()
	res, err := st.ctrl.Reconcile(ctx(), desired)
	c.metrics.cpu("Reconcile", time.Since(t0))
	if err != nil && !isLostRace(err) {
		return
	}
	if !res.Committed {
		return
	}
	c.cacheCurrentSA(vni)
	c.broadcastCommit(vni, st.ctrl.Epoch()-1, false, res.CommitMsg)
	if len(res.WelcomeMsg) > 0 && len(res.Added) > 0 {
		for _, id := range res.Added {
			c.bus.Publish(c.toDS(Envelope{VNI: vni, Type: MsgWelcome, Joiner: string(id),
				Payload: res.WelcomeMsg, Hash: contentHash(res.WelcomeMsg)}))
		}
	}
}

// rekey is invoked on the TimerRekey: committer issues an empty PCS Update.
func (c *Client) rekey(vni uint32) {
	st := c.vnis[vni]
	if st == nil || !st.joined || !st.ctrl.IsCommitter() {
		return
	}
	base := st.ctrl.Epoch()
	t0 := time.Now()
	msg, won, err := st.ctrl.Rekey(ctx())
	c.metrics.cpu("Rekey", time.Since(t0))
	if err != nil || !won || msg == nil {
		return
	}
	c.cacheCurrentSA(vni)
	c.broadcastCommit(vni, base, false, msg)
}

// onDeliver dispatches an inbound envelope.
func (c *Client) onDeliver(env Envelope) {
	st := c.vnis[env.VNI]
	switch env.Type {
	case MsgCommit:
		c.onCommit(env)
	case MsgWelcome:
		if env.Joiner == c.identity && st != nil && !st.joined {
			c.onWelcome(env)
		}
	case MsgGroupInfo:
		if st != nil {
			st.giByRef[env.Hash] = env.Payload
		}
	case MsgHeartbeat:
		c.onHeartbeat(env)
	case MsgLogReply:
		c.onLogReply(env)
	case MsgData:
		c.onData(env)
	}
}

func (c *Client) onCommit(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || !st.joined {
		return
	}
	key := vniKey(env.VNI, env.Base)
	for _, r := range st.seen[key] {
		if string(r) == env.Hash {
			goto resolve // already seen; still attempt fork-resolve
		}
	}
	st.seen[key] = append(st.seen[key], []byte(env.Hash))
	if st.ctrl.Epoch() == env.Base {
		t0 := time.Now()
		err := st.ctrl.HandleCommit(env.Payload)
		c.metrics.cpu("HandleCommit", time.Since(t0))
		switch {
		case err == nil:
			st.applied[env.Base] = []byte(env.Hash)
			c.cacheCurrentSA(env.VNI)
			c.reportAuth(env.VNI)
		case isSelfRemoved(err):
			c.leaveVNI(env.VNI)
			return
		}
	}
resolve:
	c.forkResolve(env.VNI, env.Base) // Task 7
}

func (c *Client) onWelcome(env Envelope) {
	st := c.vnis[env.VNI]
	kp, ip, lp := c.dir.joinerMaterial(env.VNI, c.identity)
	t0 := time.Now()
	err := st.ctrl.JoinViaWelcome(env.Payload, kp, ip, lp)
	c.metrics.cpu("JoinViaWelcome", time.Since(t0))
	if err != nil {
		return // Welcome not addressed to our epoch / superseded; will catch up
	}
	st.joined = true
	c.cacheCurrentSA(env.VNI)
	c.reportAuth(env.VNI)
}

// onHeartbeat updates peer epoch tracking and triggers catch-up if behind.
func (c *Client) onHeartbeat(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || !st.joined {
		return
	}
	st.peerEpoch[env.Src] = env.Base
	if env.Base > st.ctrl.Epoch() {
		c.requestCatchup(env.VNI, st.ctrl.Epoch())
	}
}

func (c *Client) requestCatchup(vni uint32, from uint64) {
	c.bus.Publish(c.toDS(Envelope{VNI: vni, Type: MsgLogRequest, Base: from}))
	c.metrics.CatchupRequests++
}

func (c *Client) onLogReply(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || !st.joined {
		return
	}
	recs := append([]CommitRecord(nil), env.Records...)
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Base < recs[j].Base })
	for _, r := range recs {
		if st.ctrl.Epoch() != r.Base {
			continue
		}
		key := vniKey(env.VNI, r.Base)
		st.seen[key] = append(st.seen[key], []byte(r.Hash))
		if err := st.ctrl.HandleCommit(r.Bytes); err == nil {
			st.applied[r.Base] = []byte(r.Hash)
			c.cacheCurrentSA(env.VNI)
			c.reportAuth(env.VNI)
		}
	}
	// fallback: still behind and no usable log ⇒ external-commit recovery
	if hb := c.maxPeerEpoch(env.VNI); hb > st.ctrl.Epoch() {
		c.recoverViaLatestGI(env.VNI)
	}
}

func (c *Client) reportAuth(vni uint32) {
	st := c.vnis[vni]
	c.checker.reportAuth(vni, st.ctrl.Epoch(), st.ctrl.Group().EpochAuthenticator())
}

func (c *Client) maxPeerEpoch(vni uint32) uint64 {
	st := c.vnis[vni]
	var mx uint64
	for _, a := range sortedActorEpochs(st.peerEpoch) {
		if st.peerEpoch[a] > mx {
			mx = st.peerEpoch[a]
		}
	}
	return mx
}

func (c *Client) leaveVNI(vni uint32) {
	c.bus.Unsubscribe(vni, c.id)
	delete(c.vnis, vni)
}

// broadcastCommit publishes a commit to BOTH reflectors (dual-peering).
func (c *Client) broadcastCommit(vni uint32, base uint64, external bool, msg []byte) {
	env := Envelope{VNI: vni, Type: MsgCommit, Base: base, External: external,
		Payload: msg, Hash: contentHash(msg)}
	c.bus.Publish(c.toDS(env))
	c.metrics.commitFanout(vni, len(msg), len(c.dsIDs))
	// publish our GroupInfo too (for recovery / external join)
	if st := c.vnis[vni]; st != nil && st.joined {
		if gi, err := st.ctrl.PublishGroupInfo(); err == nil {
			if gb, err := gi.MarshalMLS(); err == nil {
				c.bus.Publish(c.toDS(Envelope{VNI: vni, Type: MsgGroupInfo, Base: st.ctrl.Epoch(),
					Payload: gb, Hash: contentHash(msg)})) // keyed by the commit hash → fetchGI
				st.giByRef[contentHash(msg)] = gb
			}
		}
	}
}

// toDS addresses an envelope to BOTH reflectors by scheduling a copy to each.
func (c *Client) toDS(env Envelope) Envelope {
	env.Src = c.id
	for _, ds := range c.dsIDs {
		e := env
		e.Dst = ds
		c.bus.Publish(e)
	}
	// return value unused by callers that already published; kept for the
	// single-DS Welcome path above (re-published below).
	return env
}
```

> Note: `toDS` publishes to both reflectors directly; the returned value is ignored by `broadcastCommit`/`requestCatchup`. (Implementers may inline it; kept as a helper for readability. Adjust the two callers that wrap `c.toDS(...)` in `c.bus.Publish(...)` to call `c.toDS(...)` only — the test `TestClientFounderCommitsAdd` will catch a double-publish.)

`sortedActorEpochs`, `fixedClock`, `maxLifetime`, `isLostRace`, `isSelfRemoved` are small helpers in `sim.go` (Task 11).

### Task 7 — `sim/client.go` part B: fork detection + resolution + recovery (de-risk #2)

- [ ] **Test** `sim/client_test.go` (added):
  - `TestForkResolveSingleLoser` — induce a 2-DS fork (two committers from one base via direct `Group().Commit`, dual-peered); the off-canonical client `AutoRecover`s to the canonical branch and re-broadcasts; all converge (EA + SA). Mirrors de-risk #2 single-loser (3 message-steps).
  - `TestForkResolveTwoLosers` — the 3rd member follows the non-canonical branch; assert convergence via the telescoping recovery (de-risk #2 two-loser).
  - `TestForkDetectedRegistry` — the shared `EpochAuthenticatorRegistry` flags the fork.
- [ ] **Implement** (append to `sim/client.go`):

```go
// forkResolve runs the §3.3 / N3 resolution glue for a contested (vni, base).
func (c *Client) forkResolve(vni uint32, base uint64) {
	st := c.vnis[vni]
	if st == nil || !st.joined {
		return
	}
	key := vniKey(vni, base)
	refs := dedupRefs(st.seen[key])
	if len(refs) < 2 {
		return
	}
	c.checker.markDivergence(vni, base)
	applied, ok := st.applied[base]
	if !ok || st.recovered[base] {
		return
	}
	canon := sequencer.CanonicalCommit(c.suite, toGroupRefs(refs))
	if string(canon) == string(applied) {
		return // already on the canonical branch
	}
	// Off-canonical: recover to the canonical branch via external commit.
	fetchGI := func(ref group.CommitRef) (*group.GroupInfo, error) {
		gb := st.giByRef[string(ref)]
		if gb == nil {
			return nil, errNoGI
		}
		var gi group.GroupInfo
		if err := gi.UnmarshalMLS(gb); err != nil {
			return nil, err
		}
		return &gi, nil
	}
	t0 := time.Now()
	recMsg, err := st.ctrl.AutoRecover(ctx(), toGroupRefs(refs), fetchGI)
	c.metrics.cpu("AutoRecover", time.Since(t0))
	if err != nil {
		return // target GI not yet available; retried as more GroupInfos arrive
	}
	st.recovered[base] = true
	c.cacheCurrentSA(vni)
	c.reportAuth(vni)
	c.metrics.Recoveries++
	c.metrics.LostRekeys++ // the loser's branch rekey is discarded (design spec §3.6)
	// broadcast the recovery (external) commit; its base is the canonical epoch.
	newBase := st.ctrl.Epoch() - 1
	st.applied[newBase] = []byte(contentHash(recMsg))
	c.broadcastCommit(vni, newBase, true, recMsg)
}

// recoverViaLatestGI is the catch-up fallback (partition / no usable log).
func (c *Client) recoverViaLatestGI(vni uint32) {
	st := c.vnis[vni]
	// pick any cached GroupInfo whose epoch > ours as the recovery target
	var best []byte
	for _, ref := range sortedRefKeys(st.giByRef) {
		best = st.giByRef[ref]
	}
	if best == nil {
		return
	}
	var gi group.GroupInfo
	if gi.UnmarshalMLS(best) != nil {
		return
	}
	vg := ironcore.NewVNIGroup(vni, st.ctrl.Group())
	refs := []group.CommitRef{group.CommitRef(c.suite.Hash(best))}
	st.giByRef[string(refs[0])] = best
	fetchGI := func(group.CommitRef) (*group.GroupInfo, error) { return &gi, nil }
	recMsg, err := ironcore.RecoverViaExternalCommit(ctx(), vg, c.suite, refs, fetchGI,
		optimisticOrdering{}, c.dir.cred(c.identity), c.signer, maxLifetime())
	if err != nil {
		return
	}
	c.cacheCurrentSA(vni)
	c.reportAuth(vni)
	c.metrics.Recoveries++
	c.broadcastCommit(vni, st.ctrl.Epoch()-1, true, recMsg)
}
```

Helpers `dedupRefs`, `toGroupRefs`, `sortedRefKeys`, `errNoGI` live in `sim.go`.

### Task 8 — `sim/client.go` part C: data-plane SA cache + sender-lag (de-risk #3, the headline)

- [ ] **Test** `sim/client_test.go` (added):
  - `TestSACacheRetainsW` — after advancing through > W epochs, the cache holds exactly the last `W+1` epochs and trims older ones.
  - `TestSendEpochIsMin` — `sendEpoch(vni)` equals the min over self + heartbeat peer epochs.
  - `TestDataDecryptableUnderLag` — a packet sent at the group min-epoch is decryptable by every co-VNI member whose spread ≤ W (no PACKET-LOSS).
- [ ] **Implement** (append to `sim/client.go`):

```go
// cacheCurrentSA derives and stores the current-epoch SA (derive-time cache;
// past epochs cannot be re-derived — forward secrecy, design spec §3.7).
func (c *Client) cacheCurrentSA(vni uint32) {
	st := c.vnis[vni]
	if st == nil || !st.joined {
		return
	}
	sa, err := st.ctrl.CurrentSA()
	if err != nil {
		return
	}
	st.saCache[sa.Epoch] = sa
	c.trimSAs(vni)
	c.metrics.observeOverlap(len(st.saCache))
}

// trimSAs enforces the overlap window: keep only [cur-W .. cur]. W=0 (negative
// control) keeps only the current epoch.
func (c *Client) trimSAs(vni uint32) {
	st := c.vnis[vni]
	cur := st.ctrl.Epoch()
	w := uint64(c.effectiveW())
	for _, e := range sortedEpochs(st.saCache) {
		if cur >= w && e < cur-w {
			delete(st.saCache, e)
		}
	}
}

func (c *Client) effectiveW() int {
	if c.mbbDisabled {
		return 0
	}
	return c.W
}

// sendEpoch is the sender-lag policy: send under the latest GROUP-WIDE-converged
// epoch = min over self + all heartbeat peers (design spec §3.7). With
// mbbDisabled it sends under the client's own current epoch (negative control).
func (c *Client) sendEpoch(vni uint32) uint64 {
	st := c.vnis[vni]
	cur := st.ctrl.Epoch()
	if c.mbbDisabled {
		return cur
	}
	mn := cur
	for _, a := range sortedActorEpochs(st.peerEpoch) {
		if st.peerEpoch[a] < mn {
			mn = st.peerEpoch[a]
		}
	}
	return mn
}

// sendData generates a tenant packet tagged with the send-SA (TimerData).
func (c *Client) sendData(vni uint32) {
	st := c.vnis[vni]
	if st == nil || !st.joined {
		return
	}
	se := c.sendEpoch(vni)
	sa, ok := st.saCache[se]
	if !ok {
		sa, ok = st.saCache[st.ctrl.Epoch()] // fall back to current if min was trimmed
		se = st.ctrl.Epoch()
	}
	if !ok {
		return
	}
	c.metrics.observeSendLag(st.ctrl.Epoch() - se)
	c.bus.Publish(Envelope{VNI: vni, Type: MsgData, Src: c.id, Dst: Broadcast,
		Base: se, SPI: sa.SPI})
	c.metrics.DataSent++
}

// onData is the inv. 5 check point: a delivered (non-dropped) packet MUST be
// decryptable by this receiver (design spec §3.5 inv. 5 / §3.7).
func (c *Client) onData(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || !st.joined {
		return // not a live member of this VNI ⇒ packet is not "for" us
	}
	// hold a matching SA by SPI?
	for _, e := range sortedEpochs(st.saCache) {
		if st.saCache[e].SPI == env.SPI {
			c.metrics.DataDecryptable++
			return
		}
	}
	// undecryptable, non-dropped ⇒ PACKET-LOSS FAIL (design spec inv. 5).
	c.checker.packetLoss(env.VNI, env.Base, st.ctrl.Epoch(), c.sched.Now())
}

// emitHeartbeat advertises our current epoch on each VNI (TimerHeartbeat).
func (c *Client) emitHeartbeat(vni uint32) {
	st := c.vnis[vni]
	if st == nil || !st.joined {
		return
	}
	c.bus.Publish(Envelope{VNI: vni, Type: MsgHeartbeat, Src: c.id, Dst: Broadcast,
		Base: st.ctrl.Epoch()})
}
```

### Task 9 — `sim/invariant.go`: the 5 invariants + inv. 5 + negative control

- [ ] **Test** `sim/invariant_test.go`:
  - `TestInvariantConvergencePass` — all members byte-equal EA+SA ⇒ no DIVERGENCE FAIL.
  - `TestInvariantDivergenceCaught` — a hand-injected unrecovered divergence ⇒ FORK FAIL.
  - `TestInvariantPacketLossCaught` — a recorded `packetLoss` ⇒ inv. 5 fails (drives the negative control).
  - `TestInvariantMembership` — live set per VNI matches the intended set.
- [ ] **Implement** `sim/invariant.go`:

```go
package sim

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

// InvariantChecker evaluates the §3.5 invariants. inv. 5 is checked continuously
// (via packetLoss); inv. 1–4 at quiescence (via Evaluate).
type InvariantChecker struct {
	far        *sequencer.EpochAuthenticatorRegistry
	diverged   map[string]bool // vniKey(vni,base) -> a fork was observed
	lossEvents []LossEvent
}

type LossEvent struct {
	VNI       uint32
	SentEpoch uint64
	RecvEpoch uint64
	At        uint64
}

func newInvariantChecker() *InvariantChecker {
	return &InvariantChecker{
		far: sequencer.NewEpochAuthenticatorRegistry(), diverged: map[string]bool{},
	}
}

func (k *InvariantChecker) reportAuth(vni uint32, epoch uint64, auth []byte) {
	if k.far.Report(group.GroupID(ironcore.GroupID(vni)), epoch, auth) {
		// a fork at (vni, epoch) is now detected
	}
}

func (k *InvariantChecker) markDivergence(vni uint32, base uint64) {
	k.diverged[vniKey(vni, base)] = true
}

func (k *InvariantChecker) packetLoss(vni, sentEpoch, recvEpoch, at uint64) {
	k.lossEvents = append(k.lossEvents, LossEvent{vni32(vni), sentEpoch, recvEpoch, at})
}

// Result is the per-run verdict.
type Result struct {
	InvariantsHeld bool
	Divergence     []string    // inv. 1 failures
	Fork           []string    // inv. 2 failures
	Liveness       []string    // inv. 3 failures
	Membership     []string    // inv. 4 failures
	PacketLoss     []LossEvent // inv. 5 failures
	Metrics        *Metrics
}

// Evaluate runs inv. 1–4 at quiescence over the live clients, and folds in the
// continuously-collected inv. 5 events.
func (k *InvariantChecker) Evaluate(clients []*Client, intended map[uint32]map[string]bool) Result {
	r := Result{InvariantsHeld: true, PacketLoss: k.lossEvents}
	if len(k.lossEvents) > 0 {
		r.InvariantsHeld = false
	}
	// group live members per VNI
	type tip struct {
		epoch uint64
		ea    []byte
		key   []byte
	}
	byVNI := map[uint32][]tip{}
	live := map[uint32]map[string]bool{}
	for _, c := range clients {
		for _, vni := range sortedVNIKeys(c.vnis) {
			st := c.vnis[vni]
			if !st.joined {
				continue
			}
			sa, err := st.ctrl.CurrentSA()
			if err != nil {
				continue
			}
			byVNI[vni] = append(byVNI[vni], tip{st.ctrl.Epoch(), st.ctrl.Group().EpochAuthenticator(), sa.Key})
			if live[vni] == nil {
				live[vni] = map[string]bool{}
			}
			live[vni][c.identity] = true
		}
	}
	// inv. 1 (convergence) + inv. 3 (liveness): one EA+key per VNI
	for _, vni := range sortedUint32(byVNI) {
		tips := byVNI[vni]
		for i := 1; i < len(tips); i++ {
			if tips[i].epoch != tips[0].epoch || !bytes.Equal(tips[i].ea, tips[0].ea) {
				r.Divergence = append(r.Divergence, fmt.Sprintf("vni=%d epoch mismatch %d vs %d", vni, tips[i].epoch, tips[0].epoch))
				r.InvariantsHeld = false
			}
			if !bytes.Equal(tips[i].key, tips[0].key) {
				r.Divergence = append(r.Divergence, fmt.Sprintf("vni=%d SA key mismatch", vni))
				r.InvariantsHeld = false
			}
		}
	}
	// inv. 2 (no permanent fork): every observed divergence must NOT remain a
	// live multi-EA at quiescence (already covered by inv. 1); record any base
	// that diverged but did not re-converge for diagnostics.
	for _, vni := range sortedUint32(byVNI) {
		tips := byVNI[vni]
		for i := 1; i < len(tips); i++ {
			if !bytes.Equal(tips[i].ea, tips[0].ea) {
				r.Fork = append(r.Fork, fmt.Sprintf("vni=%d unrecovered fork", vni))
				r.InvariantsHeld = false
			}
		}
	}
	// inv. 4 (membership): live set matches intended
	for _, vni := range sortedIntendedKeys(intended) {
		want := intended[vni]
		got := live[vni]
		if !sameSet(want, got) {
			r.Membership = append(r.Membership, fmt.Sprintf("vni=%d membership mismatch", vni))
			r.InvariantsHeld = false
		}
	}
	return r
}
```

Helpers `vni32`, `vniarg`, `sortedVNIKeys`, `sortedUint32`, `sortedIntendedKeys`, `sameSet` live in `sim.go`. (`packetLoss` takes `uint64` vni for signature uniformity; `vni32` narrows.)

### Task 10 — `sim/metrics.go`: counts + fork stats + data-plane stats + CPU

- [ ] **Test** `sim/metrics_test.go`:
  - `TestMetricsTextReport` — `Report()` emits an aligned table via `text/tabwriter`.
  - `TestMetricsJSON` — `ReportJSON()` round-trips through `encoding/json`.
  - `TestMetricsDeterministic` — identical inputs ⇒ identical report bytes.
- [ ] **Implement** `sim/metrics.go`:

```go
package sim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"
	"time"
)

// Metrics holds deterministic counters + measured (non-scheduling) CPU timing.
type Metrics struct {
	Delivered       int
	Reflected       int
	CtrlDropped     int
	DataDropped     int // transport loss (NOT a key-loss failure)
	Blocked         int
	CatchupRequests int
	LogRetransmits  int
	Recoveries      int
	LostRekeys      int
	Forks           int
	DataSent        int
	DataDecryptable int
	CommitMsgs      int
	CommitBytes     int
	MaxOverlap      int    // max |saCache| observed (the W actually needed +1)
	MaxSendLag      uint64 // max (currentEpoch - sendEpoch) observed
	cpuNanos        map[string]int64
	cpuCount        map[string]int64
}

func newMetrics() *Metrics {
	return &Metrics{cpuNanos: map[string]int64{}, cpuCount: map[string]int64{}}
}

// cpu records measured wall time of a real crypto call (NEVER used for scheduling).
func (m *Metrics) cpu(op string, d time.Duration) {
	m.cpuNanos[op] += d.Nanoseconds()
	m.cpuCount[op]++
}

func (m *Metrics) commitFanout(vni uint32, size, nDS int) {
	m.CommitMsgs += nDS // dual-peering ~doubles fan-out
	m.CommitBytes += size * nDS
}

func (m *Metrics) observeOverlap(n int) {
	if n > m.MaxOverlap {
		m.MaxOverlap = n
	}
}
func (m *Metrics) observeSendLag(lag uint64) {
	if lag > m.MaxSendLag {
		m.MaxSendLag = lag
	}
}

// Report renders the text table (default output).
func (m *Metrics) Report() string {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "metric\tvalue\n")
	fmt.Fprintf(w, "delivered\t%d\n", m.Delivered)
	fmt.Fprintf(w, "ctrl-dropped\t%d\n", m.CtrlDropped)
	fmt.Fprintf(w, "data-sent\t%d\n", m.DataSent)
	fmt.Fprintf(w, "data-decryptable\t%d\n", m.DataDecryptable)
	fmt.Fprintf(w, "data-dropped(transport)\t%d\n", m.DataDropped)
	fmt.Fprintf(w, "forks\t%d\n", m.Forks)
	fmt.Fprintf(w, "recoveries\t%d\n", m.Recoveries)
	fmt.Fprintf(w, "lost-rekeys\t%d\n", m.LostRekeys)
	fmt.Fprintf(w, "catchup-requests\t%d\n", m.CatchupRequests)
	fmt.Fprintf(w, "log-retransmits\t%d\n", m.LogRetransmits)
	fmt.Fprintf(w, "commit-msgs(fanout)\t%d\n", m.CommitMsgs)
	fmt.Fprintf(w, "commit-bytes(fanout)\t%d\n", m.CommitBytes)
	fmt.Fprintf(w, "max-SA-overlap(W+1)\t%d\n", m.MaxOverlap)
	fmt.Fprintf(w, "max-send-lag\t%d\n", m.MaxSendLag)
	for _, op := range sortedStr(m.cpuCount) {
		n := m.cpuCount[op]
		avg := time.Duration(0)
		if n > 0 {
			avg = time.Duration(m.cpuNanos[op] / n)
		}
		fmt.Fprintf(w, "cpu/%s (n=%d)\t%s\n", op, n, avg)
	}
	w.Flush()
	return b.String()
}

// ReportJSON renders a stable JSON object (deterministic key order via struct).
func (m *Metrics) ReportJSON() ([]byte, error) {
	type cpuEntry struct {
		Op      string `json:"op"`
		Count   int64  `json:"count"`
		AvgNano int64  `json:"avg_nanos"`
	}
	var cpus []cpuEntry
	for _, op := range sortedStr(m.cpuCount) {
		n := m.cpuCount[op]
		var avg int64
		if n > 0 {
			avg = m.cpuNanos[op] / n
		}
		cpus = append(cpus, cpuEntry{op, n, avg})
	}
	return json.MarshalIndent(struct {
		*Metrics
		CPU []cpuEntry `json:"cpu"`
	}{m, cpus}, "", "  ")
}

func sortedStr(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

### Task 11 — `sim/sim.go`: directory, helpers, the event loop, `Run`

- [ ] **Test** `sim/sim_test.go`:
  - `TestRunNominalConverges` — `Run(nominal, seed=1)` ⇒ `InvariantsHeld == true`.
  - `TestDeterminism` — `Run(split_brain, 7)` twice ⇒ identical `Trace` + identical `Report()` bytes (the §6 determinism gate).
- [ ] **Implement** `sim/sim.go` — the `kpDirectory`, all small helpers referenced above, the event-loop dispatch, and `Run`:

```go
package sim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// fixedClock is an inert injectable clock (lifetimes are infinite; time never
// drives control flow — determinism rule).
type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func maxLifetime() tree.Lifetime { return tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)} }

var errNoGI = errors.New("sim: no GroupInfo for ref")

func isLostRace(err error) bool    { return errors.Is(err, ironcore.ErrLostRace) }
func isSelfRemoved(err error) bool { return errors.Is(err, ironcore.ErrSelfRemoved) }

// kpEntry is one identity's published KeyPackage material per VNI.
type kpEntry struct {
	kpMsg, initPriv, leafPriv []byte
}

// kpDirectory maps identity → credential/signer and (identity,vni) → KeyPackage
// material (design spec N2 / §10.3).
type kpDirectory struct {
	creds   map[string]tree.Credential
	signers map[string]crypto.Signer
	kps     map[string]map[uint32]kpEntry // identity -> vni -> material
}

func newKPDirectory() *kpDirectory {
	return &kpDirectory{
		creds: map[string]tree.Credential{}, signers: map[string]crypto.Signer{},
		kps: map[string]map[uint32]kpEntry{},
	}
}

func (d *kpDirectory) register(identity string, signer crypto.Signer) {
	d.creds[identity] = tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte(identity)}
	d.signers[identity] = signer
}

func (d *kpDirectory) cred(identity string) tree.Credential { return d.creds[identity] }

func (d *kpDirectory) newFounderGroup(suite cipher.Suite, vni uint32, identity string, signer crypto.Signer) *group.Group {
	g, err := group.NewGroup(suite, ironcore.GroupID(vni), d.cred(identity), signer, maxLifetime())
	if err != nil {
		panic(err)
	}
	return g
}

func (d *kpDirectory) publishKeyPackage(suite cipher.Suite, vni uint32, identity string, signer crypto.Signer) {
	kp, ip, lp, err := group.NewKeyPackage(suite, d.cred(identity), signer, maxLifetime())
	if err != nil {
		panic(err)
	}
	kpMsg, err := group.EncodeKeyPackageMessage(kp)
	if err != nil {
		panic(err)
	}
	if d.kps[identity] == nil {
		d.kps[identity] = map[uint32]kpEntry{}
	}
	d.kps[identity][vni] = kpEntry{kpMsg, ip, lp}
}

func (d *kpDirectory) resolver(vni uint32) ironcore.KeyPackageResolver {
	return func(identity []byte) ([]byte, bool) {
		if e, ok := d.kps[string(identity)][vni]; ok {
			return e.kpMsg, true
		}
		return nil, false
	}
}

func (d *kpDirectory) joinerMaterial(vni uint32, identity string) (kp, ip, lp []byte) {
	e := d.kps[identity][vni]
	return e.kpMsg, e.initPriv, e.leafPriv
}

// ─── determinism helpers (never range a map in control flow) ──────────────────

func sortedVNIKeys(m map[uint32]*vniState) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func sortedEpochs(m map[uint64]ironcore.SA) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func sortedActorEpochs(m map[ActorID]uint64) []ActorID {
	out := make([]ActorID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func sortedRefKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func dedupRefs(in [][]byte) [][]byte {
	seen := map[string]bool{}
	var out [][]byte
	for _, r := range in {
		if !seen[string(r)] {
			seen[string(r)] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}
func toGroupRefs(in [][]byte) []group.CommitRef {
	out := make([]group.CommitRef, len(in))
	for i, r := range in {
		out[i] = group.CommitRef(r)
	}
	return out
}
func vni32(v uint64) uint32 { return uint32(v) }

func sortedUint32[T any](m map[uint32]T) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func sortedIntendedKeys(m map[uint32]map[string]bool) []uint32 { return sortedUint32(m) }
func sameSet(want, got map[string]bool) bool {
	if len(want) != len(got) {
		return false
	}
	for k := range want {
		if !got[k] {
			return false
		}
	}
	return true
}

func makeSigner() crypto.Signer {
	_, s, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return s
}

// Run executes one (scenario, seed) deterministically and returns the verdict.
func Run(sc Scenario, seed int64) Result {
	s := NewScheduler(seed)
	metrics := newMetrics()
	faults := newFaultState(sc.Faults)
	bus := newBus(s, faults, metrics)
	checker := newInvariantChecker()
	dir := newKPDirectory()

	nClients := sc.Clients
	dsIDs := []ActorID{ActorID(nClients), ActorID(nClients + 1)}
	suite, ok := cipher.Lookup(sc.Suite)
	if !ok {
		panic(fmt.Sprintf("suite %#x not registered", sc.Suite))
	}

	clients := make([]*Client, nClients)
	for i := 0; i < nClients; i++ {
		id := fmt.Sprintf("client-%d", i)
		signer := makeSigner()
		dir.register(id, signer)
		clients[i] = newClient(ActorID(i), suite, signer, id, bus, s, dir, dsIDs, metrics, checker, sc.W)
		clients[i].mbbDisabled = sc.MBBDisabled
	}
	dss := []*DS{newDS(dsIDs[0], bus, faults), newDS(dsIDs[1], bus, faults)}

	world := &world{sc: sc, s: s, bus: bus, faults: faults, metrics: metrics,
		checker: checker, dir: dir, clients: clients, dss: dss, suite: suite,
		intended: map[uint32]map[string]bool{}, desired: map[uint32]map[string]bool{}}
	world.bootstrap() // founders, initial subscriptions, timers, scripted faults/churn

	// Main loop: process until queue empty (settle window is scheduled events).
	var trace []string
	for {
		e, ok := s.Pop()
		if !ok {
			break
		}
		trace = append(trace, world.dispatch(e))
		if s.Now() >= world.settleDeadline && world.faultsLifted == false {
			world.faults.liftAll()
			world.faultsLifted = true
		}
	}
	r := checker.Evaluate(clients, world.intended)
	metrics.Forks = world.forkCount
	r.Metrics = metrics
	r.Trace = trace
	return r
}
```

> The `world` struct + `bootstrap`/`dispatch` (founder setup, timer rescheduling, scripted churn/fault injection, `Result.Trace` field, `settleDeadline`, `forkCount`) are part of this task. `dispatch` switches on `e.Kind`:
> - `KindDeliver` → `clients[e.Actor].onDeliver(e.Env)` or `dss[idx].handle(e.Env, metrics)`;
> - `KindTimer` → the matching client/DS timer method, then **reschedule** the periodic timer (rekey/heartbeat/reconcile/data) until `settleDeadline`;
> - `KindFault` → `faults.applyFault(e.Fault)` (+ schedule a `TimerDSRestart` when bringing a DS down for a window);
> - `KindChurn` → register the joining client's KP and update `world.desired`/`intended`, then fire a `TimerReconcile` at the current committer.
> Each branch returns a deterministic one-line trace string (`fmt.Sprintf("%d|%s|a=%d", e.At, kindStr, e.Actor)`). Add `Trace []string` to `Result`.

### Task 12 — `sim/scenario.go`: the 5 built-in scenarios + the seeded property tests

- [ ] **Test** `sim/scenario_test.go` — one seeded property test per scenario, asserting all 5 invariants over **seeds 1..20**:
  - `TestScenarioNominal`, `TestScenarioDrops`, `TestScenarioDSDown`, `TestScenarioPartitionRecover`, `TestScenarioSplitBrain` — each loops `for seed := int64(1); seed <= 20; seed++ { r := Run(scenarioX(), seed); if !r.InvariantsHeld { t.Fatalf("seed %d: %+v", seed, failureSummary(r)) } }`.
  - `TestSplitBrainForkStats` — `split_brain` must record `Forks > 0` across the seed range and every fork must be recovered (`r.Fork == nil`), with `r.PacketLoss == nil` (zero key-loss throughout the fork).
  - `TestNegativeControl_PacketLoss` — run `splitBrain()` (or a `rekeyFork()` variant) with `MBBDisabled=true`; assert `r.InvariantsHeld == false` **and** `len(r.PacketLoss) > 0` (inv. 5 has teeth — design spec §10 negative control).
- [ ] **Implement** `sim/scenario.go`:

```go
package sim

import "github.com/trevex/mls-mlkem-go/mls/cipher"

// Scenario is a built-in simulation profile (design spec §4).
type Scenario struct {
	Name         string
	Clients      int
	VNIs         int
	Suite        cipher.CipherSuite
	W            int // SA-overlap depth (default 4; de-risked min is 2)
	Faults       FaultConfig
	Partitions   []scriptedPartition
	DSDowns      []scriptedDSDown
	Churn        []ChurnOp
	SettleRounds uint64
	MBBDisabled  bool // negative control
}

type scriptedPartition struct {
	At, Until    uint64
	SideA, SideB []ActorID
}
type scriptedDSDown struct {
	At, Until uint64
	DS        ActorID
}

const defaultSuite = cipher.XWING_AES256GCM_SHA256_Ed25519

func base(name string, clients, vnis int) Scenario {
	return Scenario{Name: name, Clients: clients, VNIs: vnis, Suite: defaultSuite,
		W: 4, SettleRounds: 200,
		Faults: FaultConfig{Latency: 2, Jitter: 2}}
}

// Nominal: churn across M VNIs, no faults (baseline; expect zero forks).
func Nominal() Scenario {
	s := base("nominal", 5, 2)
	s.Churn = churnPlan(5, 2)
	return s
}

// Drops: steady 10–30% per-delivery drops + churn.
func Drops() Scenario {
	s := base("drops", 5, 2)
	s.Faults.DropProb = 0.2
	s.Churn = churnPlan(5, 2)
	return s
}

// DSDown: one reflector stops mid-run then restarts; clients ride the other.
func DSDown() Scenario {
	s := base("ds_down", 5, 2)
	s.Churn = churnPlan(5, 2)
	s.DSDowns = []scriptedDSDown{{At: 50, Until: 120, DS: ActorID(5)}} // first DS id = Clients
	return s
}

// PartitionRecover: a client subset is cut from one DS, then heals.
func PartitionRecover() Scenario {
	s := base("partition_recover", 6, 2)
	s.Churn = churnPlan(6, 2)
	s.Partitions = []scriptedPartition{{At: 40, Until: 140,
		SideA: []ActorID{0, 1}, SideB: []ActorID{6}}} // cut clients 0,1 from DS #0
	return s
}

// SplitBrain: DS↔DS partition + concurrent churn pressure ⇒ competing commits.
func SplitBrain() Scenario {
	s := base("split_brain", 6, 1)
	s.Churn = churnPlanDense(6, 1)
	s.Partitions = []scriptedPartition{{At: 30, Until: 160,
		SideA: []ActorID{6}, SideB: []ActorID{7}}} // sever the two DS from each other
	s.SettleRounds = 400
	return s
}

// All returns the suite in deterministic order.
func All() []Scenario {
	return []Scenario{Nominal(), Drops(), DSDown(), PartitionRecover(), SplitBrain()}
}

// ByName looks up a scenario for the CLI.
func ByName(name string) (Scenario, bool) {
	for _, s := range All() {
		if s.Name == name {
			return s, true
		}
	}
	return Scenario{}, false
}
```

> `churnPlan`/`churnPlanDense` build deterministic `[]ChurnOp` (joins then a few leaves across the VNIs, scheduled in `bootstrap`). `failureSummary` formats a `Result` for test output. The DS-partition in `split_brain` severs the two reflectors so that, combined with churn-driven committer-election races (§8.1), members commit divergent branches that each DS reflects to its own side — the realistic fork generator. Convergence is asserted only after the settle window lifts the partition (§8.3).

### Task 13 — `cmd/metalsim/main.go` + `make sim`

- [ ] **Test** `sim/cli_smoke_test.go` (in `sim` package, exercising the same `Run` path the CLI calls) — `TestCLIAllScenariosSmoke` runs `All()` at one seed and asserts no panic + `InvariantsHeld`.
- [ ] **Implement** `cmd/metalsim/main.go`:

```go
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/trevex/mls-mlkem-go/sim"
)

func main() {
	scenario := flag.String("scenario", "all", "scenario name or 'all'")
	clients := flag.Int("clients", 0, "override client count (0 = scenario default)")
	vnis := flag.Int("vnis", 0, "override VNI count (0 = scenario default)")
	seed := flag.Int64("seed", 1, "RNG seed")
	drop := flag.Float64("drop", -1, "override per-delivery drop probability")
	rounds := flag.Uint64("rounds", 0, "override settle rounds")
	jsonOut := flag.Bool("json", false, "emit JSON metrics")
	verbose := flag.Bool("v", false, "print the per-event trace")
	flag.Parse()

	var scenarios []sim.Scenario
	if *scenario == "all" {
		scenarios = sim.All()
	} else {
		s, ok := sim.ByName(*scenario)
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown scenario %q\n", *scenario)
			os.Exit(2)
		}
		scenarios = []sim.Scenario{s}
	}

	exit := 0
	for _, sc := range scenarios {
		if *clients > 0 {
			sc.Clients = *clients
		}
		if *vnis > 0 {
			sc.VNIs = *vnis
		}
		if *drop >= 0 {
			sc.Faults.DropProb = *drop
		}
		if *rounds > 0 {
			sc.SettleRounds = *rounds
		}
		r := sim.Run(sc, *seed)
		if !r.InvariantsHeld {
			exit = 1
		}
		fmt.Printf("=== %s (seed=%d) invariantsHeld=%v ===\n", sc.Name, *seed, r.InvariantsHeld)
		if !r.InvariantsHeld {
			fmt.Printf("  divergence=%v\n  fork=%v\n  liveness=%v\n  membership=%v\n  packetLoss=%d\n",
				r.Divergence, r.Fork, r.Liveness, r.Membership, len(r.PacketLoss))
		}
		if *jsonOut {
			b, _ := r.Metrics.ReportJSON()
			fmt.Println(string(b))
		} else {
			fmt.Print(r.Metrics.Report())
		}
		if *verbose {
			for _, line := range r.Trace {
				fmt.Println("  ", line)
			}
		}
	}
	os.Exit(exit)
}
```

- [ ] **Makefile** — add (place beside `test:`):

```make
sim: ## Run the metalnet/metalbond deterministic simulation property suite
	$(NIX) go test ./sim/...
```

  and add `sim` to the `.PHONY` line. Optionally extend `test:` to include `./sim/...` (it already does via `./...`).

### Task 14 — determinism gate + zero-dep gate + final sweep

- [ ] **Test** `sim/determinism_test.go` — `TestDeterminismFaultHeavy`: `Run(SplitBrain(), 13)` twice; assert `Trace` slices are byte-equal and `Report()` strings are equal (§6 determinism gate).
- [ ] Run `nix develop -c go test ./sim/...`, `nix develop -c go vet ./...`, `nix develop -c gofmt -l sim cmd` (must be empty), `make check-zero-dep` (root stays stdlib-only), `make sim`.
- [ ] Confirm `git status` shows only the new `sim/` + `cmd/metalsim/` + Makefile change.

---

## Notes

- **No library change (de-risk #2 result).** The AP fork resolution converges entirely through the existing public API (`sequencer.CanonicalCommit` + `Controller.AutoRecover`/`ironcore.RecoverViaExternalCommit` + `Group.ProcessExternalCommit` + the read-only accessors `Epoch`/`EpochAuthenticator`/`CurrentSA`/`IsCommitter`/`ActiveLeaves`/`PublishGroupInfo`). The optional `ironcore.ResolveFork(seen []group.CommitRef, applied group.CommitRef) (recoverTo group.CommitRef, mustRecover bool)` wrapper was **considered and rejected for v1**: it would only relocate three lines of glue (`CanonicalCommit` + an equality check) into the library without removing any sim responsibility (the sim still owns `seen`-set assembly, GroupInfo caching, and re-broadcast). If a second consumer ever needs the same decision, promote it then — a separate, justified, read-only/additive task with no behaviour change to existing tests.
- **Multi-loser recovery cost (de-risk #2 finding).** When ≥2 members are off-canonical, each rejoins via its own external commit; these serialize by the canonical tie-break (one wins per contested epoch, the rest are superseded and retry at the next epoch — the AP analogue of `ErrRecoverySuperseded`). Convergence is guaranteed but can burn several epochs per fork (the two-loser de-risk telescoped to epoch 8). This is exactly the `LostRekeys` / `Recoveries` cost the metrics track and the honest price of AP-without-a-register (design spec §9).
- **Zero key-loss parameters (de-risk #3 result).** Minimum overlap depth `W = max epoch-spread`; with sender-lag (send under the group-wide min epoch) the de-risked rekey+fork needed `W = 2`. The default `Scenario.W = 4` is a safety margin; the metrics report `MaxOverlap` (the W actually exercised, +1) and `MaxSendLag` so each scenario states the operational ESP-overlap window. The negative control (`W=0`, no sender-lag) produced 22 losses — inv. 5 is not vacuous.
- **Determinism is sacred.** Single `*rand.Rand` in the `Scheduler`; every map iterated in control flow is key-sorted (`sortedVNIKeys`/`sortedEpochs`/`sortedActorEpochs`/`sortedRefKeys`/`sortedUint32`); no goroutines/channels; `time` only via `Metrics.cpu(...)` (measured, never scheduling). The determinism gate diffs the full event trace + report bytes across two same-seed runs.
- **Settle window (§8.2).** Faults are lifted once logical time reaches `settleDeadline` (derived from `SettleRounds`); periodic timers keep firing so recovery completes; inv. 1–4 are evaluated only at quiescence, inv. 5 continuously. `split_brain` uses a larger settle (400) so convergence is asserted only after the DS↔DS partition heals (§8.3).
- **CP option out of scope (§9).** A future `cp_compare` scenario could give both DS the real shared `FencedRegister` to quantify the fork-prevention delta; not built in v1.
- **Trace field.** `Result` carries `Trace []string` (used by the determinism gate and `-v`); keep handler trace strings free of pointer addresses / map order so they stay reproducible.
