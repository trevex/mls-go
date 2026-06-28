# metalnet/metalbond Simulation Harness — Design Spec

- **Status:** Draft for review (rev 2 — realistic AP metalbond model)
- **Date:** 2026-06-28
- **Repo:** `github.com/trevex/mls-mlkem-go`
- **Context:** The library provides the MLS+PQC engine, the IronCore integration (`ironcore`: VNI groups, ESP SA derivation, the `Controller` membership orchestrator, `RecoverViaExternalCommit`, `CanonicalCommit`, `EpochAuthenticatorRegistry`). This spec adds a **deterministic, in-memory simulation harness** that drives the *real* library to model how it behaves in metalnet — two MetalBond Delivery Services, N metalnet hosts, multiple VNIs — under failover, packet drops, and partitions. It is primarily a **fault-injection property test** that the resilience invariants hold, with metrics as secondary output.

> **rev 2 — the load-bearing correction.** metalbond is a BGP-style **route-reflector pair with no consensus and no strongly-consistent store**; clients peer with both reflectors. So the simulation does **not** assume a single linearizable register (that would be metalbond *plus* invented infra — etcd/Raft/a witness). Instead it models metalbond as it really is: two **independent, eventually-consistent fan-out** reflectors. Commit-ordering safety therefore comes from the **MLS layer**, not the DS: (1) a **deterministic committer election** (only the lowest-leaf member commits the next epoch) makes concurrent commits *rare*; (2) the MLS predecessor-binding makes any residual fork **immediately detectable** (epoch_authenticator divergence); (3) **external-commit recovery to the deterministic canonical branch** (`CanonicalCommit`, lowest-`Hash`) **auto-heals** it — while the **data plane never drops a packet** (existing ESP SAs keep flowing; only a *rekey* is lost on the losing branch, design §5.4). The invariant under test is therefore **"always EVENTUALLY converges; no PERMANENT fork"**, not "never forks." This is the regime IronCore actually gets with metalbond as-is. (See §9 for how this relates to the `ironcore/sequencer` CP option.)

---

## 0. PRIMARY MODEL (rev 5): dual-group pure redundancy — supersedes the per-mode details below for v1

The reflector strategy is a sim **mode**. **v1 implements `dual_redundancy` first** (this section); the `precedence` mode (§3.2–§3.4 rev 4, §9 option 2) is a **deferred second mode** for a later comparison. Where this section conflicts with §3.2–§3.4, **this section wins for v1**.

**The model.** A metalbond pair exists for **redundancy**, so use it as pure redundancy: for each VNI, run **two independent MLS groups** — `replica 0` ordered by reflector R0, `replica 1` ordered by R1. Every member host is in **both**. Each replica derives its **own** ESP SA; the data plane installs **both** SPIs and demuxes by SPI (RFC 4303 ESP already does this). Senders use whichever replica they share a healthy SA with; receivers, holding both, decrypt either.

- **No forks, ever.** A *single* reflector ordering a group cannot fork it — its **local accept-once register** (`sequencer.MemorySequencer`, one **per reflector**, never shared) serializes commits *before* fan-out, so it emits a true total order and all of that replica's members converge. Two single-sequencer replicas ⇒ neither ever forks. **`CanonicalCommit`/`RecoverViaExternalCommit`/fork-resolution are NOT used** — correctness is just "two independent single-sequencer groups + catch-up + dual-SA." (This is why dual-redundancy is the simpler, more robust path.)
- **Reflector / DS actor.** R_r holds, per VNI, replica-`r`'s `MemorySequencer` + committed log + GroupInfo cache. On a commit for `(vni, r, epoch)`: `AcceptCommit` on its own register → if accepted, append + fan out the winner to that VNI's subscribers; else drop. Catch-up service per replica. `ds_down` = R_r stops (its replica stalls; **the other replica keeps the data plane alive** — the redundancy headline); on restart it catches its register/log up before clients resume committing replica-`r`.
- **Client / metalnet host.** Runs **two `ironcore.Controller`s per VNI** (one per replica), with distinct group IDs (e.g. `GroupID(vni*numDS + r)`) and **distinct SA derivation per replica** (use `saVNI = vni*numDS + r` for `DeriveSAKeys` so the two SAs have distinct keys **and distinct SPIs** — no collision). A `churn` event applies to **both** replicas (the designated committer of each replica commits Add/Remove via that replica's reflector); the two replicas may transiently differ in membership — fine, because the data plane uses whichever replica both endpoints currently share.
- **Data plane (zero-loss, stronger).** A member installs the last `W` epochs' SAs **per replica** (make-before-break, cached on-derive). For a `(sender, receiver)` pair, the sender sends under **some replica `r` where both are members and converged at a mutually-decryptable epoch** (per-replica sender-lag: `sendEpoch_r = min over replica-r members of last-known epoch`); with two replicas, such an `r` exists even if one replica is stale/partitioned/down for that member. **Inv. 5 (zero key-loss) becomes: for every non-dropped data packet there EXISTS a replica SA the receiver holds for it** — survives a whole replica being degraded.
- **Invariants for v1.** (1) **Per-replica convergence:** within each replica, all live members agree on `EpochAuthenticator` + that replica's SA key at settle. (2) **Data-plane zero-loss (inv. 5, above)** — the headline. (3) **Liveness:** partitioned-then-reconnected members catch up both replicas within the settle window. (4) **Membership correctness** per replica. *No "no-permanent-fork" invariant — there are no forks.*
- **Scenarios (v1, dual-redundancy).** `nominal`, `drops`, `ds_down` (R0 stops → replica-0 stalls; assert **zero data-plane loss** because replica-1's SA carries traffic; replica-0 catches up on R0's return — the redundancy headline), `partition_recover` (a client subset partitioned from one reflector keeps the data plane on the other replica, catches up on heal), and `both_rekey` (concurrent periodic rekeys in both replicas; assert zero loss via per-replica make-before-break). The **negative control** (W=0, no sender-lag, *and* model only one replica) must FAIL inv. 5.
- **Metrics / comparison hook.** Report per-replica convergence rounds, **control-plane cost (commits + bytes — note ~2× a single group)**, **SA-state per member (~2×)**, data-plane loss (target 0), catch-up rounds. These are the numbers a later `precedence`-mode run is compared against to quantify the redundancy-vs-scaling trade-off.

---

## 1. Goals and non-goals

### Goals
- A **deterministic discrete-event** simulation: single-threaded logical-time scheduler + seeded RNG; any failover/drop/partition scenario fully replays from `(seed, scenario)`.
- Drive the **real** `ironcore` stack (real `Controller`, `Group`, X-Wing crypto, `RecoverViaExternalCommit`, `CanonicalCommit`) — validate the actual library, not a model of it.
- Model metalbond **realistically**: two independent AP fan-out reflectors, no consensus, no shared store; clients peer with both.
- **Primary (control plane):** assert the resilience invariants under adversarial faults — every VNI **eventually converges** (byte-equal `epoch_authenticator` **and** ESP SA key); **no permanent fork** (every divergence is detected and recovered); behind/recovering members re-converge within a bounded settle window.
- **Primary (data plane — zero packet loss):** assert that **no tenant packet is ever lost due to key rotation, forking, or DS failover.** Modeled explicitly: members exchange ESP-style data packets encrypted under per-VNI SAs throughout the run; the invariant is that **every data packet from a live member is decryptable by every other live member of the same VNI at all times** — including mid-rekey, mid-fork, and mid-failover. This empirically validates the design's §5.4 ("epoch advancement is off the data path → failover/rekey never drops packets") and §10.4 (make-before-break SA) claims, *including the fork case the original argument only sketched*.
- **Secondary:** reproducible metrics, including **fork statistics** (count, detection latency, recovery rounds, lost rekeys), **data-plane stats** (max SA-overlap depth required, packets sent/decryptable, any loss), convergence rounds, per-commit message/byte fan-out, and real crypto CPU per op.
- **Zero new dependencies** — `sim/` lives in the root module (stdlib-only); preserves the dependency-free guarantee.

### Non-goals
- No real network/sockets/wall-clock concurrency (deterministic single-threaded).
- No scenario DSL, no large scaling sweeps, no plotting — v1 ships ~5 built-in scenarios + a text/JSON report.
- **Not** a model of metalbond gaining consensus/a CP store. The CP variant (shared register → zero forks) is explicitly **out of scope for v1** (noted in §9 as the optional upgrade the sim could later compare against).
- Does not change library code; the sim is a consumer of the public `ironcore`/`mls` API. (If a small read-only accessor or a thin fork-resolution helper is genuinely required, it is a separate, justified task — see §7.)

---

## 2. Architecture (event-queue actors)

```
sim/                      (root module, stdlib-only)
  scheduler.go   Scheduler{clock, pq, rng}: timestamped event priority queue
  event.go       Event{at, actor, kind, payload}; kinds: deliver|timer|fault|churn
  bus.go         Bus: per-VNI fan-out + fault application (drop/partition/latency)
  ds.go          DS actor ("MetalBond"): independent AP fan-out + per-VNI log + GroupInfo cache
  client.go      Client actor ("metalnet"): ironcore.Controller per VNI + commit/catch-up/fork-resolve/recover
  fault.go       FaultConfig + the seeded fault decisions
  invariant.go   InvariantChecker: eventual-convergence + no-permanent-fork + liveness + membership
  metrics.go     Metrics (incl. fork stats) + report (text table / JSON)
  scenario.go    Scenario definition + the ~5 built-in scenarios
  sim.go         Run(scenario, seed) -> Result{invariantsHeld, metrics}
cmd/metalsim/
  main.go        CLI: -scenario -clients -vnis -seed -drop -rounds -json -v
sim/*_test.go    per-component tests + a seeded property test per scenario
```

**Execution model.** The `Scheduler` holds a min-heap of events keyed by logical timestamp (ties broken by a monotonic sequence number). `Run` seeds the RNG, schedules the scenario's initial events, then pops events in order; each handler mutates actor state, calls the real library, and schedules follow-ons. Single-threaded → identical `(seed, scenario)` ⇒ byte-identical run. Logical time advances only via scheduled delays (latency, timer intervals); real CPU time is *measured* per op but never *drives* scheduling.

**Determinism rules (hard).** No goroutines/channels; no `time.Now()`/`time.After()` in control flow; no map-iteration-order dependence (sort keys before iterating); one `*rand.Rand` seeded from the scenario seed threaded through all fault/timing decisions.

**Where ordering safety lives (key architectural point).** There is **no DS-side serializer**. The two DS are dumb transports. Safety is a property of the *clients’ MLS state machines* + the *naive protocol glue* in the client actor:
- **Election:** all members compute the designated committer identically (`Group.ActiveLeaves()[0]`), so normally exactly one commit is produced per epoch.
- **Intrinsic first-wins:** MLS `ProcessCommit` only applies a commit matching the current epoch and predecessor; a second commit for an already-advanced epoch is rejected. Each client linearizes *its own* view.
- **Fork resolution:** because each client peers with **both** reflectors, it eventually receives **both** competing commits of any fork. It computes `CanonicalCommit` (lowest `Hash`) over the competing commits it has seen; if it had applied the non-canonical branch, it `RecoverViaExternalCommit`s to the canonical one (from that branch's GroupInfo). All clients pick the same canonical ⇒ all converge.

---

## 3. Components

### 3.1 Bus (in-memory transport / "naive protocol")
- Per-VNI fan-out: actors `Subscribe(vni)` / `Publish(vni, msg)`; a publish becomes scheduled `deliver` events to current subscribers.
- Envelope: `{vni, kind, src, dst|broadcast, epoch, payload []byte}`, `kind ∈ {proposal, commit, welcome, groupInfo, logRequest, logReply, heartbeat}`; `payload` is the real MLS/ironcore bytes.
- **Clients peer with BOTH DS.** A client's outbound commit/proposal is published to both reflectors; inbound, a client may receive the same logical message via both (dedup by content hash). This dual-peering is what lets clients observe both branches of a fork.
- **Fault application per delivery:** seeded **drop** (per-link prob), **delay** (latency/jitter), **block** (if `src→dst` partitioned). Drops/partitions hit *deliveries*, not the DS log copy — the catch-up path heals them.

### 3.2 DS actor ("MetalBond") — two **independent** reflectors with a **local** ordering register (rev 4 — static precedence)
The two reflectors **never communicate with each other** (no mesh, no shared store, no lease, no consensus). Each is an independent fan-out that *also* runs a **per-reflector LOCAL accept-once register** (`sequencer.MemorySequencer`, one **per reflector**, never shared):
- **Static per-VNI primary:** a deterministic, statically-configured assignment `primaryDS(vni) = vni % numDS` (baked into every client's config — no coordination). The other reflector is the hot **standby** for that VNI.
- **Local serialize + fan-out:** on receiving a `commit` for `(vni, epoch)`, the reflector calls its **own** `AcceptCommit(vni, epoch, ref)`; on `ok=true` it appends to its per-VNI log, updates its GroupInfo cache, and `Publish`es the winner to the VNI subscribers; on `ok=false` (a competing commit already won *at this reflector*) it drops/`reject`s. Because all clients of a VNI adopt the **primary** reflector's serialized stream, the primary's local register **is a total-order broadcast for that VNI** — fork-free in the common case, with **zero coordination**.
- **Catch-up service:** answers `logRequest{vni, fromEpoch}` from its log and serves its cached `GroupInfo`.
- **`ds_down` / restart:** a reflector simply stops (no fan-out, no catch-up) and restarts with an empty register; on restart it must **catch its register/log up** to the group's current epoch (learned from client heartbeats/GroupInfo) before clients defer to it as authoritative — a client only re-prefers a reflector once that reflector's advertised epoch ≥ the client's. (No store; staleness handled by the epoch check.)

### 3.3 Client actor ("metalnet") — N instances (static-precedence routing)
Each client runs the real **`ironcore.Controller`** per VNI, plus a per-VNI cursor and a per-VNI **authoritative-reflector** choice driven by **static precedence**.
- **Static precedence:** the client's reflector order per VNI is `[primaryDS(vni), the other]`. The **authoritative** reflector = the highest-precedence one it can currently **reach** (and that is epoch-caught-up). Commits are sent to (and ordering adopted from) the authoritative reflector; the client still *subscribes* to both for liveness/catch-up.
- **Membership / churn / outbound:** the designated committer (lowest active leaf) produces a commit via the `Controller` and sends it to the **authoritative** reflector (which serializes via its local register and fans out the winner). The committer learns it lost (lost the local race, or the authoritative reflector rejected it) and retries next epoch / `AutoRecover`s.
- **Inbound:** `deliver(commit)` from the authoritative reflector → `Controller.HandleCommit` (applies if it matches the current epoch; rejects stale). `deliver(welcome)` → join. `deliver(heartbeat/groupInfo)` newer → catch-up.
- **Fork detection + recovery (precedence-based, NOT lowest-Hash):** a fork can only arise when the **primary is partitioned** (some clients keep reaching it, others fall back to the standby). Detection: a client whose `epoch_authenticator`/GroupInfo for `(vni, epoch)` **disagrees with the higher-precedence reflector's** (observed once it can reach it again, via heartbeat/GroupInfo) knows it is on the non-canonical branch. Recovery: it **`RecoverViaExternalCommit`** to the **precedence-authoritative reflector's** branch (its published `GroupInfo`). The canonical branch is defined by **static precedence** — a client need **not** see both branches, and the reflectors need **not** coordinate. (`CanonicalCommit`/lowest-Hash remains only a last-resort tiebreak for two competing commits *from the same reflector*, which the local register already prevents.)
- **Catch-up (drops/partition):** on a gap: (1) `logRequest` to a reachable reflector + replay; (2) fallback → `RecoverViaExternalCommit` from the authoritative reflector's latest `GroupInfo`.
- **Periodic rekey:** the designated committer issues an empty Update on a timer (PCS), via the authoritative reflector.

### 3.4 Fault model (`FaultConfig`, seeded)
- `dropProb` (per-link override allowed); `latency`, `jitter`.
- `partitions []{at, until, sideA, sideB}` — isolate actor sets. **The fork generator is now a `client-subset ↔ primary-reflector` partition**: the partitioned clients fall back to the standby (a *different* local register) → a competing branch develops → healed by precedence-based recovery when the partition lifts. (`DS↔DS` is irrelevant — the reflectors never talk.)
- `dsDown []{at, until, ds, vni|all}` — a reflector stops then restarts (clients ride the standby; primary catches up on return).
- `churn` — scheduled membership add/remove.
- **Quiescent settle:** after `settleDeadline` the loop schedules **no new churn or periodic-rekey** and **lifts all faults**, then drains long enough for all catch-up + recovery to complete — so laggards/forks converge against a *stationary* group, not a moving target.
- All decisions from the single seeded `*rand.Rand`.

### 3.5 Invariant checker (the primary deliverable)
Evaluated at **quiescence** and **end-of-scenario**, after a bounded **settle window** (extra rounds with faults lifted so recovery completes):
1. **Eventual convergence (safety):** for each VNI, all *live* members agree on `Group.EpochAuthenticator()` **and** the derived ESP SA `Key` (byte-equal). Mismatch after the settle window ⇒ **DIVERGENCE FAIL**. (Transient mismatch *during* the run is allowed — it's the fork being healed.)
2. **No permanent fork (safety):** every divergence observed at a `(vni, epoch)` during the run must have been **detected** (recorded by the `EpochAuthenticatorRegistry`) **and recovered** (all members re-converged to one branch) before the settle window closes. An undetected or unrecovered fork ⇒ **FORK FAIL**.
3. **Liveness:** every member that fell behind or forked must have re-converged within the settle window ⇒ else **LIVENESS FAIL** (records which member/VNI/epoch stalled).
4. **Membership correctness:** the live member set per VNI matches the scenario's intended set after churn settles.
5. **Data-plane continuity — ZERO key-loss (the headline data-plane invariant):** for **every** data packet generated during the run (§3.7) that is *not* dropped by the transport, the receiver **must hold a matching SA** (by SPI) to decrypt it — i.e., no packet is ever undecryptable **because of** a rekey, fork, or DS failover. Checked continuously *during* the run (not just at settle): at the moment each `dataPacket` is delivered to a live co-VNI member, that member must be able to decrypt it under the make-before-break + sender-lag policy (§3.7). Any undecryptable non-dropped packet ⇒ **PACKET-LOSS FAIL**, recording the epoch/fork/failover context. (Transport drops are tracked separately and are *not* failures — they model lossy links, not key-rotation loss; the property is "rotation/forking/failover never *causes* loss," distinct from "the link is perfect.")

`Run` returns `invariantsHeld bool` + per-invariant detail; each scenario's property test asserts it over seeds 1..20.

### 3.6 Metrics (secondary)
Deterministic counts/logical-time + real CPU timing of the actual crypto calls:
- **Fork stats (headline for this model):** # forks, fork **detection latency** (rounds from divergence to detection), **recovery rounds** (divergence → re-converged), **lost rekeys** (epochs discarded on losing branches), commits superseded.
- rounds-to-converge per membership change / failover;
- messages + bytes fanned out per commit (the O(N) per-VNI cost) + totals (note: dual-peering ~doubles fan-out vs a single reflector);
- # external-commit recoveries and # log-retransmits;
- ds-down recovery time (logical rounds);
- real crypto CPU per op (`Commit`, `HandleCommit`, `DeriveSAKeys`, X-Wing encap/decap), measured, never scheduling.
Reported as text table (default) or JSON (`-json`), reproducible by seed.

### 3.7 Data-plane model + the make-before-break / sender-lag policy (zero-loss core)
The sim models the ESP data path explicitly so it can *prove* zero packet loss across rekeys/forks/failovers.
- **SA derivation (real library):** each member derives its per-VNI epoch SA via `ironcore.DeriveSAKeys` and retains the prior epoch's SA via the `Controller`'s make-before-break exposure (`CurrentSA()` / `PreviousSA()`), generalized to an **overlap set** of the last `W` epochs' SAs (W is a policy knob; the sim measures the minimum W that yields zero loss).
- **Installed-SA set per member:** the SAs a member can **decrypt** with = its current epoch SA ∪ the last `W` retained ones. Indexed by `SPI` (which encodes `(VNI, epoch)`), so a receiver selects the SA by the packet's SPI (exactly RFC 4303 ESP demux).
- **Send-SA selection (the policy under test):** a member **sends** under the SA of the **latest epoch it believes is group-wide-converged**, *not* necessarily its own current epoch. Concretely the sender lags: it advances its send-epoch to `N` only once `N` is confirmed established across the VNI (e.g., observed via a converged heartbeat / all-acked GroupInfo); until then it keeps sending under the last confirmed-common epoch's SA. **During a fork, no new epoch is group-wide, so every member keeps sending under the last common epoch's SA — which all branches still hold (make-before-break) — so all packets remain decryptable.** Once the fork heals and a new common epoch is confirmed, senders lag-advance to it; the now-superseded SAs age out of the overlap set after `W` epochs.
- **Data traffic generation:** a scheduled `dataPacket` event has a random live member of a VNI "send" a packet (tagged with the SPI/epoch of its current send-SA) to the VNI; the Bus fans it out (subject to drops/partition — but a *dropped* data packet is a transport loss, **not** a key-rotation loss, and is excluded from the zero-key-loss invariant; the invariant is about *decryptability*, see §3.5 inv. 5). Each receiver checks whether it holds the matching SA.
- **What this validates:** that the library's SA material (current + retained-previous, via the exporter) plus the make-before-break + sender-lag policy means **a sender and every receiver always share a usable SA**, so neither a rekey nor a fork nor a failover ever makes a packet undecryptable. The sim also reports the **minimum overlap depth `W`** and **maximum send-lag** needed — the concrete operational parameters metalnet would configure for the ESP overlap window.

---

## 4. Built-in scenarios (v1)
Each is `Scenario{name, clients, vnis, membership, faults, settleRounds}`; **all run continuous data traffic (§3.7) and assert all five §3.5 invariants — including ZERO key-loss (inv. 5) throughout.** `ds_down`, `failover`-style, and `split_brain` are the critical zero-loss tests: they assert that not a single data packet becomes undecryptable while a reflector is down or while branches are forked/healing.
1. **`nominal`** — churn across M VNIs, no faults. Baseline convergence + fan-out metrics. (Expect zero forks: deterministic committer ⇒ one commit/epoch.)
2. **`drops`** — churn + steady per-delivery drops (10–30%). Exercises log-retransmit catch-up; asserts eventual convergence; few/no forks (drops cause lag, not divergence, unless they trigger a recovery race).
3. **`ds_down`** — one reflector stops mid-run (then restarts); clients ride the other; asserts convergence and measures the (small) impact — confirms no exclusive-owner failover is needed.
4. **`partition_recover`** — a client subset is partitioned from one DS for a window, then heals; partitioned clients catch up (log → external-commit fallback). Asserts liveness + convergence.
5. **`split_brain`** — **a client subset is partitioned from the VNI's *primary* reflector while churn continues**, so the partitioned clients fall back to the **standby** reflector and a competing branch develops on the standby's *separate* local register (the reflectors never talk). Then the partition lifts. Asserts: every fork is **detected** and **recovered to the precedence-authoritative (primary) branch**, the VNI **eventually converges**, and reports fork count + detection latency + recovery rounds + lost rekeys. This is the headline test of the static-precedence regime — the honest answer to "does our library survive metalbond as it actually is (two independent reflectors, static client precedence)?"

---

## 5. CLI (`cmd/metalsim`)
Flags: `-scenario <name|all>`, `-clients N`, `-vnis M`, `-seed S`, `-drop p`, `-rounds R` (settle), `-json`, `-v` (per-event trace). Exit nonzero on any invariant failure. `-scenario all` runs the suite and prints a summary table (scenario × invariants-held × fork stats × key metrics). `-seed` reproduces a run exactly.

---

## 6. Testing
- **Unit:** scheduler determinism; bus drop/partition/latency; DS fan-out + log/retransmit; client commit / catch-up / **fork-resolution (CanonicalCommit + recover)** / recovery fallback; invariant checker (positive + a hand-injected divergence is caught as a detected+recovered or a FORK FAIL if left unhealed).
- **Determinism gate:** a fault-heavy scenario run twice with the same seed ⇒ byte-identical event trace + identical metrics.
- **Property gate (the point):** each of the 5 scenarios runs as a `go test` asserting `invariantsHeld == true` over seeds 1..20 — a seeded fault-injection property test over the real library. `split_brain` specifically asserts every fork detected + recovered + converged (and records the stats).
- `make sim` target; wired into the suite under the existing `nix develop` workflow. Root module stays zero-dep.

---

## 7. Async loss detection & the AP `Ordering` adapter (the one real subtlety)
The `Controller.commitAndOrder` path calls `Ordering.AcceptCommit` and treats `ok=false` as a **synchronous** "I lost" signal — which assumed a register exists. In the AP model there is no register, so:
- The sim provides an **AP `Ordering` adapter** whose `AcceptCommit` returns success **optimistically** (the client commits and broadcasts). Loss is discovered **asynchronously** by the client actor's fork-resolution logic (§3.3): seeing a competing commit win the canonical tie-break ⇒ recover.
- This is a genuine test of whether the library's recovery composes under *async* (not synchronous-register) loss detection. The orchestration glue ("saw two commits → pick canonical → recover if loser") lives in the **sim client actor** as the naive-protocol layer. **If this glue turns out to be generally useful, promote it to a small library helper** (e.g. `ironcore.ResolveFork(seen []CommitRef, current) -> (recoverTo, bool)`) as a separate, justified task — but the default is to keep it in the sim and leave the library unchanged.

## 8. Other risks / open questions
1. **Committer-election races as the primary fork source.** Concurrent commits arise mainly when the designated committer changes during churn (the removed committer + the elect both act, or a stale view) — the sim should target this in `split_brain`/`partition_recover`. The Controller elects by lowest *surviving* leaf; the sim must let the elect make progress (heartbeat-driven), not deadlock on an unreachable committer.
2. **Settle-window sizing.** Too short ⇒ false LIVENESS/DIVERGENCE FAIL. Settle = f(max in-flight latency, recovery rounds); assert quiescence (empty queue) before declaring failure; expose as a scenario param with a safe default.
3. **Both DS log different branches.** Recovery's deterministic canonical choice (`CanonicalCommit` lowest-`Hash`) relies on every client eventually seeing both branches — guaranteed by dual-peering, but a client partitioned from one DS during a fork may see only one branch until the partition heals; the settle window must outlast the partition. The sim asserts convergence only after partitions lift.
4. **Read-only observables.** The checker needs each member's `EpochAuthenticator()`, epoch, SA key, live-member set — all public today. None expected to be missing; if so, a minimal read-only accessor is a separate justified task.

## 9. Three ordering regimes — and why static precedence is the recommended default
There are **three** ways to get per-VNI commit ordering for a metalbond pair; this sim validates the middle one as the operational default:

1. **CP / fork-prevented (`FencedSequencer` + `LeaseStore`, design §5.5 B1).** A *shared* strongly-consistent store / lease / consensus. Zero transient forks, zero lost rekeys — but requires infra metalbond **doesn't have** (etcd / a witness). The library code remains valid for deployments that *do* add such a store.
2. **Static-precedence single-de-facto-sequencer (THIS sim, recommended).** Each reflector runs its **own LOCAL accept-once register** (`MemorySequencer`, per reflector, never shared); clients pick the authoritative reflector by **static per-VNI precedence** (`vni % numDS`) and fall back to the standby only when the primary is unreachable. **No store, no consensus, no reflector-to-reflector contact.** Fork-free in the common case *and* under a clean primary crash; the **only** fork window is a *partitioned-but-alive* primary, healed deterministically by precedence-based external-commit recovery. This is essentially **B1 without the lease/fence** — the single writer is chosen by static config instead of a leased token.
3. **Pure AP / lowest-Hash (earlier rev).** Dumb fan-out, no register; canonical = lowest-`Hash` of competing commits. Forks on *every* concurrent commit and needs *all* clients to see *both* branches to heal — fragile under partition. **Rejected** in favor of (2).

The sim shows that **regime (2)** keeps every VNI converged + zero data-plane loss under adversarial faults, and quantifies its cost (fork frequency — only on primary-partition — recovery latency, lost rekeys). This refines design §5: the recommended metalbond default is **static-precedence local registers**, not the leased CP store (§5.5 B1, which assumed infra that isn't there) nor pure AP.

## 10. Definition of done
- `sim/` engine + AP DS + client actors (with fork-resolution glue) + fault model + invariant checker + metrics (incl. fork stats), stdlib-only, zero new deps.
- `cmd/metalsim` CLI; `make sim` target.
- Determinism gate passes (same seed ⇒ identical run).
- All 5 scenarios pass their invariant assertions across seeds 1..20; `split_brain` shows every fork detected + recovered + VNI converged, with reported fork stats.
- **Zero key-loss (inv. 5) holds in every scenario across all seeds** — no data packet ever undecryptable due to rekey/fork/failover — and the report states the minimum SA-overlap depth `W` and max send-lag that achieved it.
- A data-plane **negative control** test confirms the checker has teeth: with make-before-break disabled (W=0, no sender-lag), a rekey/fork scenario MUST produce PACKET-LOSS FAIL — proving inv. 5 actually catches loss rather than being vacuous.
- Metrics report emits (text + JSON).
- Library code unchanged (or one justified read-only accessor / fork-resolution helper, if strictly necessary).
