# metalnet/metalbond Simulation Harness — Design Spec

- **Status:** Draft for review (rev 2 — realistic AP metalbond model)
- **Date:** 2026-06-28
- **Repo:** `github.com/trevex/mls-mlkem-go`
- **Context:** The library provides the MLS+PQC engine, the IronCore integration (`ironcore`: VNI groups, ESP SA derivation, the `Controller` membership orchestrator, `RecoverViaExternalCommit`, `CanonicalCommit`, `EpochAuthenticatorRegistry`). This spec adds a **deterministic, in-memory simulation harness** that drives the *real* library to model how it behaves in metalnet — two MetalBond Delivery Services, N metalnet hosts, multiple VNIs — under failover, packet drops, and partitions. It is primarily a **fault-injection property test** that the resilience invariants hold, with metrics as secondary output.

> **rev 2 — the load-bearing correction.** metalbond is a BGP-style **route-reflector pair with no consensus and no strongly-consistent store**; clients peer with both reflectors. So the simulation does **not** assume a single linearizable register (that would be metalbond *plus* invented infra — etcd/Raft/a witness). Instead it models metalbond as it really is: two **independent, eventually-consistent fan-out** reflectors. Commit-ordering safety therefore comes from the **MLS layer**, not the DS: (1) a **deterministic committer election** (only the lowest-leaf member commits the next epoch) makes concurrent commits *rare*; (2) the MLS predecessor-binding makes any residual fork **immediately detectable** (epoch_authenticator divergence); (3) **external-commit recovery to the deterministic canonical branch** (`CanonicalCommit`, lowest-`Hash`) **auto-heals** it — while the **data plane never drops a packet** (existing ESP SAs keep flowing; only a *rekey* is lost on the losing branch, design §5.4). The invariant under test is therefore **"always EVENTUALLY converges; no PERMANENT fork"**, not "never forks." This is the regime IronCore actually gets with metalbond as-is. (See §9 for how this relates to the `ironcore/sequencer` CP option.)

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

### 3.2 DS actor ("MetalBond") — two independent instances
Each reflector, per VNI, is a **dumb eventually-consistent fan-out** — **no register, no lease, no ownership, no consensus**:
- **Fan-out:** on receiving a `commit`/`proposal`/`welcome`/`groupInfo` from any peer, best-effort `Publish` it to all VNI subscribers (the other clients) — exactly a BGP-RR reflecting routes.
- **Per-VNI committed log:** appends commits it has accepted into its local view, *in the order it received them*. **The two DS may hold different logs / different GroupInfo for the same epoch** when a fork occurred — this is faithful to AP and is the source of the competing branches clients must resolve.
- **GroupInfo cache:** the latest signed `GroupInfo` it has seen per VNI (used to serve recovery).
- **Catch-up service:** answers `logRequest{vni, fromEpoch}` with the `commitRecord`s it holds (`logReply`) and serves its cached `GroupInfo`.
- **"Failover" = a reflector simply stops** (scheduled `fault: ds_down`): it ceases fan-out and can't serve catch-up until it restarts. **No lease handover is needed** — the other reflector was already live and fanning out; clients keep using it. A restarted reflector re-learns state from the bus / a client snapshot. (This is the real metalbond HA story: redundant peers, not failover of an exclusive owner.)

### 3.3 Client actor ("metalnet") — N instances
Each client runs the real **`ironcore.Controller`** for every VNI it is in, plus a per-VNI cursor (last applied epoch) and a small **seen-commits** set per `(vni, baseEpoch)` for fork resolution.
- **Membership / churn:** `churn` events join/leave a VNI; the designated committer (lowest active leaf) drives Add/Remove commits; joiners consume Welcome or external-commit.
- **Outbound (optimistic):** when this client is the designated committer for a pending change/rekey, it produces a commit via the Controller and broadcasts it to **both** DS. There is no synchronous "did I win" — the commit is optimistic (the AP `Ordering` adapter, §7, returns success locally); loss is discovered **asynchronously** (below).
- **Inbound:** `deliver(commit)` → record in `seen[(vni,baseEpoch)]`, then `Controller.HandleCommit` (applies if it matches the current epoch; rejects stale/competing). `deliver(welcome)` → join. `deliver(heartbeat/groupInfo)` with a newer epoch → start catch-up.
- **Fork detection + resolution (the resilience core):** when a client observes **≥2 distinct valid commits for the same `(vni, baseEpoch)`** (it will, via dual-peering), or its `epoch_authenticator` disagrees with a peer's/DS's for the same epoch: it computes `winner = CanonicalCommit(seen[(vni,baseEpoch)])`; if it had applied a *different* commit for that epoch, it **`RecoverViaExternalCommit`** to the winner's branch (using that branch's latest `GroupInfo`). All clients pick the same `winner` ⇒ all converge.
- **Catch-up (drops/partition):** on a gap (commit refs an epoch ahead, or heartbeat shows behind): (1) `logRequest` to a reachable DS and replay; (2) **fallback** if no DS reachable / log can't advance it → `RecoverViaExternalCommit` from the latest `GroupInfo`.
- **Periodic rekey:** the designated committer issues an empty Update on a scheduled timer (PCS).

### 3.4 Fault model (`FaultConfig`, seeded)
- `dropProb` (per-link override allowed); `latency`, `jitter`.
- `partitions []{at, until, sideA, sideB}` — isolate actor sets. `client↔DS` partition → client falls behind, must catch up via the other DS or recover. **`DS↔DS` partition + concurrent churn → the realistic fork generator** (reordering/divergent fan-out yields competing commits for an epoch).
- `dsDown []{at, until, ds, vni|all}` — a reflector stops then restarts.
- `churn` — scheduled membership add/remove.
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
5. **`split_brain`** — **DS↔DS partition + concurrent churn pressure on shared VNIs** → genuinely produces competing commits / divergent branches. Asserts: every fork is **detected** and **recovered**, the VNI **eventually converges**, and reports fork count + detection latency + recovery rounds + lost rekeys. This is the headline test of the AP+recovery regime — the honest answer to "does our library survive metalbond as it actually is?"

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

## 9. Relationship to the `ironcore/sequencer` (CP option) — honest framing
The library's `FencedSequencer`/`LeaseStore`/`FencedRegister` (design §5.5 **B1**) and the single-linearizable-register proof (§5.1) model the **CP upgrade**: *if* metalbond gained a strongly-consistent store / consensus / a 3rd witness, you get **fork-prevention** (zero transient forks, zero lost rekeys). That code remains valid and is the right choice when such a store exists. **But metalbond as it is today is AP**, so the operational regime this simulation validates is **detection + recovery** (§5.6) — forks are possible but transient, always detected, always healed, with the data plane unaffected. The sim's job is to show that this AP+recovery regime keeps every VNI converged under adversarial faults, and to quantify its cost (fork frequency, recovery latency, lost rekeys) — i.e. to answer empirically whether IronCore *needs* the CP store or whether AP+recovery suffices. A future `cp_compare` scenario (two DS sharing the real `FencedRegister`) could quantify the delta; it is out of scope for v1.

## 10. Definition of done
- `sim/` engine + AP DS + client actors (with fork-resolution glue) + fault model + invariant checker + metrics (incl. fork stats), stdlib-only, zero new deps.
- `cmd/metalsim` CLI; `make sim` target.
- Determinism gate passes (same seed ⇒ identical run).
- All 5 scenarios pass their invariant assertions across seeds 1..20; `split_brain` shows every fork detected + recovered + VNI converged, with reported fork stats.
- **Zero key-loss (inv. 5) holds in every scenario across all seeds** — no data packet ever undecryptable due to rekey/fork/failover — and the report states the minimum SA-overlap depth `W` and max send-lag that achieved it.
- A data-plane **negative control** test confirms the checker has teeth: with make-before-break disabled (W=0, no sender-lag), a rekey/fork scenario MUST produce PACKET-LOSS FAIL — proving inv. 5 actually catches loss rather than being vacuous.
- Metrics report emits (text + JSON).
- Library code unchanged (or one justified read-only accessor / fork-resolution helper, if strictly necessary).
