# metalnet/metalbond Simulation Harness — Design Spec

- **Status:** Draft for review
- **Date:** 2026-06-28
- **Repo:** `github.com/trevex/mls-mlkem-go`
- **Context:** The library now provides the full MLS+PQC engine, the IronCore integration (`ironcore`: VNI groups, ESP SA derivation, the `Controller` membership orchestrator), and the provable ordering layer (`ironcore/sequencer`: `FencedSequencer`, `LeaseStore`, `FencedRegister`, `EpochAuthenticatorRegistry`, `CanonicalCommit`), plus external-commit fork recovery (`ironcore.RecoverViaExternalCommit`). This spec adds a **deterministic, in-memory simulation harness** that drives the *real* library to model how it behaves in metalnet — two MLS Delivery Services ("MetalBond"), N member hosts ("metalnet" clients), multiple VNIs — under failover, packet drops, and partitions, primarily as a **fault-injection property test** that the resilience invariants hold, with performance/observability metrics as secondary output.

---

## 1. Goals and non-goals

### Goals
- A **deterministic discrete-event** simulation: a single-threaded logical-time scheduler with a seeded RNG, so any failover/drop/partition scenario fully replays from `(seed, scenario)`.
- Drive the **real** `ironcore` stack (real `Controller`, real `FencedSequencer`/`LeaseStore`, real `Group`/X-Wing crypto) — the sim validates the actual library, not a model of it.
- **Primary:** assert the resilience invariants under adversarial fault sequences — every VNI always re-converges (byte-equal `epoch_authenticator` **and** ESP SA key) and never permanently forks; behind/recovering members re-converge within bounded rounds.
- **Secondary:** emit reproducible metrics (rounds-to-converge, per-commit message/byte fan-out, recoveries, retransmits, failover recovery time, real crypto CPU per op).
- **Zero new dependencies** — lives in the root module (stdlib-only); preserves the library's dependency-free guarantee.

### Non-goals
- No real network, sockets, or wall-clock concurrency (deterministic single-threaded by design).
- No scenario DSL, no large scaling sweeps, no plotting — v1 ships ~5 built-in scenarios + a text/JSON report.
- Not a metalbond reimplementation — the DS actor is a *faithful-enough* model (sequencer + per-VNI log + GroupInfo + fan-out), not metalbond's wire protocol.
- Does not change any library code; the sim is a pure consumer of the public `ironcore`/`mls` API. (If a tiny read-only accessor is genuinely required, it is called out as a separate, justified task — the default is no library change.)

---

## 2. Architecture (event-queue actors)

```
sim/                      (root module, stdlib-only)
  scheduler.go   Scheduler{clock, pq, rng}: timestamped event priority queue
  event.go       Event{at, actor, kind, payload}; kinds: deliver|timer|fault|churn
  bus.go         Bus: per-VNI topic fan-out + fault application (drop/partition/latency)
  ds.go          DS actor ("MetalBond"): FencedSequencer + per-VNI log + latest GroupInfo
  client.go      Client actor ("metalnet"): ironcore.Controller per VNI + catch-up/recover
  fault.go       FaultConfig + the seeded fault decisions
  invariant.go   InvariantChecker: convergence + no-fork + liveness assertions
  metrics.go     Metrics collection + report (text table / JSON)
  scenario.go    Scenario definition + the ~5 built-in scenarios
  sim.go         top-level Run(scenario, seed) -> Result{invariantsHeld, metrics}
cmd/metalsim/
  main.go        CLI: -clients -vnis -seed -scenario -drop -rounds -json
sim/*_test.go    per-component tests + a deterministic end-to-end test per scenario
```

**Execution model.** The `Scheduler` holds a min-heap of events keyed by logical timestamp (ties broken deterministically by a monotonic sequence number). `Run` seeds the RNG, schedules the scenario's initial events, then pops events in order; each handler mutates actor state, calls the real library, and schedules follow-on events. Single-threaded → identical `(seed, scenario)` ⇒ identical run, byte-for-byte. Logical time advances only via scheduled delays (message latency, timer intervals); there is no wall clock in control flow (real CPU time is *measured* per op but never *drives* scheduling).

**Determinism rules (hard constraints).** No goroutines, no channels, no `time.Now()`/`time.After()` in control flow, no map-iteration-order dependence (sort keys before iterating), one `*rand.Rand` seeded from the scenario seed threaded through all fault/timing decisions. (`Date.now`/`Math.random`-equivalents are forbidden in the engine, exactly as in the library's own discipline.)

---

## 3. Components

### 3.1 Bus (the in-memory transport / "naive protocol")
- Per-VNI **topics**; actors `Subscribe(vni)` / `Publish(vni, msg)`. A published message is fanned out to all current subscribers of that VNI as scheduled `deliver` events.
- Message envelope (the naive protocol): `{vni, kind, srcActor, dstActor (or broadcast), epoch, payload []byte}` where `kind ∈ {proposal, commit, welcome, groupInfo, logRequest, logReply, heartbeat}` and `payload` is the real MLS/ironcore bytes (commit `MLSMessage`, `Welcome`, `GroupInfo`, etc.).
- **Fault application on every delivery:** consult `FaultConfig` + the seeded RNG to (a) **drop** with per-link probability, (b) **delay** by sampled latency/jitter, (c) **block** if the `src→dst` link is currently partitioned. Drops/partitions apply to *deliveries*, so a committed message in the DS log is never lost — only its fan-out copy is — which is exactly what the catch-up path must heal.

### 3.2 DS actor ("MetalBond") — two instances
Each DS, per VNI it currently **owns** (holds a valid lease):
- Runs the real **`FencedSequencer`** backed by a **shared** `LeaseStore` + `FencedRegister` (the single linearization point — both DS instances share this CP backbone, so even concurrent ordering attempts cannot fork; this is the §5 safety property under test).
- Maintains a per-VNI **append-only committed log** `[]commitRecord` (each: epoch, the committed `MLSMessage` bytes, the resulting `GroupInfo`) and caches the **latest signed `GroupInfo`**.
- **Ordering flow:** receives a client's commit → `AcceptCommit(vni, epoch, ref)` on the shared register → on success appends to the log + updates GroupInfo + best-effort `Publish(vni, commit)` to subscribers; on `ok=false` (lost race), replies reject to the proposer.
- **Catch-up service:** answers `logRequest{vni, fromEpoch}` with the missing `commitRecord`s (`logReply`), and serves the latest `GroupInfo` on request.
- **Lease/failover:** a DS owns a VNI iff it holds the lease in the shared `LeaseStore`. A scheduled `fault: failover` marks a DS "down" for a VNI; after the lease TTL elapses (a scheduled timer), the standby `Acquire`s the lease (monotonic fencing token) and resumes ordering for that VNI from the shared register — no fork, bounded rekey-only unavailability (§5.4/§5.5).
- **Heartbeat:** each owned VNI periodically `Publish`es a `heartbeat{vni, currentEpoch}` so lagging clients can detect they're behind even if no new commit arrives.

### 3.3 Client actor ("metalnet") — N instances
Each client runs the real **`ironcore.Controller`** for every VNI it is a member of, plus a small per-VNI cursor (last applied epoch).
- **Membership:** `churn` events make a client join/leave a VNI. Join = create-or-be-added; the designated committer (lowest active leaf, per the Controller) drives the Add commit through the owning DS; the joiner consumes the Welcome (or external-commits if it has no Welcome).
- **Outbound:** when this client is the designated committer for a pending change/rekey, it produces a commit via the Controller and `Publish`es it to the owning DS (which orders it). A rejected commit (`ok=false`) triggers `AutoRecover`.
- **Inbound:** `deliver(commit)` → `Controller.HandleCommit`; `deliver(welcome)` → join; `deliver(heartbeat)` with `epoch > myEpoch` → start catch-up.
- **Catch-up (the resilience core):** on detecting a gap (a commit references an epoch ahead of my cursor, or a heartbeat shows I'm behind): (1) send `logRequest{vni, fromEpoch=myEpoch+1}` to the owning DS and replay the returned `commitRecord`s in order via `HandleCommit`; (2) **fallback** — if the DS is unreachable (partition/failover-in-progress) or the log can't advance me (tail lost on failover, or I'm a removed/forked branch), fetch the latest `GroupInfo` and **`RecoverViaExternalCommit`** to re-join the canonical branch, routed through the (new) owning DS's sequencer.
- **Periodic rekey:** the designated committer issues an empty Update commit on a scheduled timer (PCS), through the owning DS.

### 3.4 Fault model (`FaultConfig`, seeded)
- `dropProb float64` — per-delivery drop probability (per-link override allowed).
- `latency`, `jitter` — logical-time delivery delay distribution.
- `partitions []partitionEvent{at, until, sideA, sideB}` — isolate actor sets; `DS↔DS` partition = the split-brain test (the shared register still serializes → no fork; ordering for a VNI is unavailable only while its owner is on the wrong side, then heals).
- `failovers []failoverEvent{at, ds, vni}` — mark a DS down for a VNI (or all), forcing lease handover.
- All decisions drawn from the single seeded `*rand.Rand`.

### 3.5 Invariant checker (the primary deliverable)
Evaluated at **quiescence** (event queue empty or only periodic timers remain) and at **end-of-scenario**, after a bounded **settle window** (extra rounds with faults lifted so recovery can complete):
1. **Convergence (safety):** for each VNI, all *live* members agree on `Group.EpochAuthenticator()` **and** on the derived `ironcore` ESP SA `Key` (byte-equal). Any mismatch among members that should be in the same epoch ⇒ **DIVERGENCE FAIL**.
2. **No undetected fork (safety):** feed every member's per-epoch `epoch_authenticator` to an `EpochAuthenticatorRegistry`; any divergence at the *same* `(vni, epoch)` that was not resolved by recovery before the settle window closes ⇒ **FORK FAIL**.
3. **Liveness:** every member that fell behind (drops/partition) or was forced to recover (failover) must have re-converged within the settle window ⇒ else **LIVENESS FAIL** (records which member/VNI stalled).
4. **Membership correctness:** the live member set per VNI matches the scenario's intended set after churn settles.

A scenario run returns `invariantsHeld bool` + a per-invariant detail; the e2e test for each built-in scenario asserts `invariantsHeld == true`.

### 3.6 Metrics (secondary)
Collected deterministically (counts/logical-time) plus real CPU timing of the actual crypto calls:
- rounds-to-converge after each membership change / failover;
- messages and bytes fanned out per commit (the O(N) per-VNI cost) + total;
- # recoveries (external-commit) and # log-retransmits triggered;
- failover recovery time (logical rounds from DS-down to VNI re-converged);
- real crypto CPU per op type (`Commit`, `HandleCommit`, `DeriveSAKeys`, X-Wing encap/decap) via `time` measurement around the real calls (measured, never used for scheduling).
Reported as a text table (default) or JSON (`-json`), reproducible by seed.

---

## 4. Built-in scenarios (v1)
Each is `Scenario{name, clients, vnis, membership, faults, settleRounds}`; all assert the invariants.
1. **`nominal`** — N clients across M VNIs, steady membership churn (joins/leaves), no faults. Baseline convergence + metrics.
2. **`drops`** — same churn + steady per-delivery drop probability (e.g. 10–30%). Exercises log-retransmit catch-up; asserts convergence despite loss.
3. **`failover`** — a single DS goes down mid-run for some VNIs; standby takes over after lease TTL. Asserts re-convergence + measures failover recovery time; asserts no fork.
4. **`partition_recover`** — a subset of clients is partitioned from their owning DS for a window, then heals; partitioned clients catch up (log then external-commit fallback). Asserts liveness + convergence.
5. **`split_brain`** — the two DS are partitioned from each other while both have churn pressure on shared VNIs; asserts the shared linearization point prevents any fork (zero FORK FAIL) and that ordering heals when the partition lifts (the §5 headline safety claim, demonstrated under load).

---

## 5. CLI (`cmd/metalsim`)
Flags: `-scenario <name|all>`, `-clients N`, `-vnis M`, `-seed S`, `-drop p`, `-rounds R` (settle), `-json`, `-v` (per-event trace). Exit nonzero if any invariant fails. Running `-scenario all` runs the suite and prints a summary table (scenario × invariants-held × key metrics). Deterministic: `-seed` reproduces a run exactly.

---

## 6. Testing
- **Unit:** scheduler ordering/determinism (same seed ⇒ identical event sequence), bus drop/partition/latency application, DS log+retransmit + lease handover, client catch-up + recovery fallback, invariant checker (positive: a converged state passes; negative: a hand-injected divergence is caught).
- **Determinism gate:** a test runs a fault-heavy scenario twice with the same seed and asserts byte-identical event traces + identical metrics.
- **End-to-end gate (the point):** each of the 5 built-in scenarios runs as a `go test` and asserts `invariantsHeld == true` over a range of seeds (e.g. seeds 1..20) — a seeded fault-injection property test over the real library. `split_brain` specifically asserts zero forks.
- All under the existing `nix develop` workflow; add a `make sim` target (and wire `sim` into the suite). Root module stays zero-dep.

---

## 7. Risks / open questions
1. **Designated-committer churn under faults.** When the committer (lowest active leaf) is itself partitioned/failed, handover to the next-lowest must still make progress; the sim must not deadlock waiting on an unreachable committer. Mitigation: the Controller already elects by lowest *surviving* leaf; the sim's settle window + heartbeat-driven catch-up must give the elect a chance to commit. Validated by the `partition_recover` + `failover` scenarios.
2. **Settle-window sizing.** Too short ⇒ false LIVENESS FAIL; the window must scale with scenario depth. Mitigation: settle = function of (max in-flight latency, lease TTL, recovery rounds); make it a scenario parameter with a safe default and assert quiescence (empty queue) before declaring failure.
3. **External-commit recovery routing during failover.** A client recovering exactly while the lease is mid-handover must route its external commit to the *new* owner; the sim resolves "owning DS" via the shared `LeaseStore` at send time so recovery follows ownership.
4. **Read-only library accessors.** The invariant checker needs each member's `EpochAuthenticator()`, epoch, SA key, and live-member set — all already public (`Group.EpochAuthenticator`, `Group.Epoch`, `ironcore.DeriveSAKeys`, `Group.ActiveLeaves`). If any needed observable is missing, add it as a minimal read-only accessor in a separate, justified task — default expectation: none needed.

---

## 8. Definition of done
- `sim/` engine + DS + client actors + fault model + invariant checker + metrics, stdlib-only, zero new deps.
- `cmd/metalsim` CLI; `make sim` target.
- The determinism gate passes (same seed ⇒ identical run).
- All 5 built-in scenarios pass their invariant assertions across seeds 1..20; `split_brain` shows zero forks.
- Metrics report emits (text + JSON).
- Library code unchanged (or one justified read-only accessor, if strictly necessary).
