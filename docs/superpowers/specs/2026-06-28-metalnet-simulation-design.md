# metalnet/metalbond Simulation Harness — Design Spec

- **Status:** Implemented — dual-group pure redundancy
- **Date:** 2026-06-28
- **Repo:** `github.com/trevex/mls-go`
- **Context:** The library provides the MLS+PQC engine and the IronCore integration (`ironcore`: VNI groups, ESP SA derivation, the `Controller` membership orchestrator, `RecoverViaExternalCommit`, `CanonicalCommit`, `EpochAuthenticatorRegistry`, and `ironcore/sequencer` ordering primitives). This spec describes the **deterministic, in-memory simulation harness** (`sim/` + `cmd/metalsim/`) that drives the *real* library to model how it behaves in metalnet — two MetalBond reflectors, N metalnet hosts, M VNIs — under reflector failure, packet drops, and partitions. It is primarily a **fault-injection property test** that a resilience property holds, with metrics as secondary output.

The honest framing: this is a deterministic *model*, not a production deployment. What it validates is a specific, falsifiable property — **zero tenant-data-plane packet loss under reflector failure/partition** — against the actual library code, reproducibly by seed.

---

## 1. The model — dual-group pure redundancy

A metalbond pair exists for **redundancy**, so the design uses it as pure redundancy. For each VNI, the simulation runs **two independent MLS groups**:

- `replica 0` ordered by reflector **R0**,
- `replica 1` ordered by reflector **R1**.

Every member host is in **both** groups. Each replica derives its **own** ESP SA; the data plane installs **both** SPIs and demuxes by SPI (exactly as RFC 4303 ESP already does). Senders use whichever replica they currently share a healthy SA with; receivers, holding both, decrypt either.

### Why this has no forks
A *single* reflector ordering a group **cannot fork it**. Each reflector runs its own **local accept-once register** (`sequencer.MemorySequencer`, one **per reflector, never shared**) that serializes commits *before* fan-out, so it emits a true total order and every member of that replica converges. Two single-sequencer replicas ⇒ neither ever forks. The reflectors **never communicate** — no mesh, no shared store, no lease, no consensus. Because there are no forks, **`CanonicalCommit` / `RecoverViaExternalCommit` / fork-resolution are NOT on the path** in this model; correctness reduces to "two independent single-sequencer groups + catch-up + dual-SA." This is what makes dual-redundancy the simplest and most robust path.

### Actors
- **Reflector / DS actor (`R_r`).** Holds, per VNI, replica-`r`'s `MemorySequencer` + committed log + GroupInfo cache. On a commit for `(vni, r, epoch)`: `AcceptCommit` on its own register → if accepted, append + fan out the winner to that VNI's subscribers; else drop. Runs a per-replica catch-up service. `ds_down` = `R_r` stops (its replica stalls; **the other replica keeps the data plane alive** — the redundancy headline); on restart it catches its register/log up before clients resume committing replica-`r`.
- **Client / metalnet host.** Runs **two `ironcore.Controller`s per VNI** (one per replica), with distinct group IDs (e.g. `GroupID(vni*numDS + r)`) and **distinct SA derivation per replica** (`saVNI = vni*numDS + r` for `DeriveSAKeys`, so the two SAs have distinct keys **and** distinct SPIs — no collision). A churn event applies to **both** replicas (the designated committer of each replica commits Add/Remove via that replica's reflector); the two replicas may transiently differ in membership — fine, because the data plane uses whichever replica both endpoints currently share.
- **Data plane (zero-loss).** A member installs the last `W` epochs' SAs **per replica** (make-before-break, cached on-derive). For a `(sender, receiver)` pair, the sender sends under **some replica `r` where both are members and converged at a mutually-decryptable epoch** (per-replica sender-lag: `sendEpoch_r = min over replica-r members of last-known epoch`); with two replicas, such an `r` exists even if one replica is stale, partitioned, or down for that member.

### Invariants
The simulation asserts **three** invariants (see §6.5 for the checker):

1. **Per-replica convergence (safety):** within each replica, all live members agree on `EpochAuthenticator` **and** that replica's ESP SA key at settle.
2. **Data-plane zero key-loss (the headline):** for every non-dropped data packet there **exists a replica SA the receiver holds** for it — so no rekey, partition, or reflector failure ever makes a packet undecryptable. This survives a whole replica being degraded.
3. **Membership correctness** per replica (liveness folded in: a member that failed to catch up is absent from the live set and trips this check).

There is deliberately **no "no-permanent-fork" invariant** — in this model there are no forks to detect or recover.

---

## 2. Validated result

Implemented as `sim/` (root module, stdlib-only) + the `cmd/metalsim` CLI. Across the **5 scenarios** (`nominal`, `drops`, `ds_down`, `partition_recover`, `both_rekey`) over **seeds 1..20**:

- **Zero data-plane packet loss** in every scenario at every seed, including while a reflector is fully down (`ds_down`) and while a client subset is partitioned from a reflector (`partition_recover`). When one replica stalls or is unreachable for a member, the other replica's SA carries that member's traffic — no packet becomes undecryptable.
- **Per-replica convergence and membership correctness** hold at settle for both replicas of every VNI.
- **Deterministic:** a fixed `(scenario, seed)` produces a byte-identical run (the `TestDeterminism` gate asserts identical trace + metrics for a repeated seed).
- **Library unchanged, zero new dependencies:** `sim/` is a pure consumer of the public `ironcore`/`mls` API and lives in the root module, preserving the stdlib-only guarantee.
- **The checker has teeth:** a **negative control** (`negative_control`: a single replica, `W=0`, no sender-lag) deliberately **fails** invariant 2 — it produces undecryptable packets under rekey+churn — proving the zero-loss check is not vacuous.

Cost of the property (reported by the harness): roughly **2× control-plane** cost (commits + bytes) and **~2× SA state per member** versus a single group — the price of running two independent groups for redundancy. Observed operational parameters at the default `W=4`: max SA-overlap depth `W+1 = 5`, max send-lag `2`.

---

## 3. Goals and non-goals

### Goals
- A **deterministic discrete-event** simulation: single-threaded logical-time scheduler + a single seeded RNG; any failover/drop/partition scenario fully replays from `(seed, scenario)`.
- Drive the **real** `ironcore` stack (real `Controller`, `Group`, X-Wing crypto, `DeriveSAKeys`) — validate the actual library, not a model of it.
- Model metalbond **realistically**: two **independent** fan-out reflectors, no consensus, no shared store, no reflector-to-reflector contact.
- **Primary (data plane — zero packet loss):** assert that **no tenant packet is ever lost due to key rotation or reflector failover/partition** — every data packet from a live member is decryptable by every live co-VNI member at all times, including mid-rekey and mid-failover, because the redundant replica's SA always covers it. This empirically validates the main design's §5.4 ("epoch advancement is off the data path → failover/rekey never drops packets") and §10.4 (make-before-break SA) claims.
- **Primary (control plane):** assert per-replica convergence (byte-equal `EpochAuthenticator` **and** ESP SA key) and membership correctness after a bounded settle window.
- **Secondary:** reproducible metrics — convergence rounds, per-commit message/byte fan-out (note ~2× vs a single group), SA-overlap depth and send-lag actually needed, catch-up/log-retransmit counts, and real crypto CPU per op.
- **Zero new dependencies** — `sim/` lives in the root module (stdlib-only); preserves the dependency-free guarantee.

### Non-goals
- No real network/sockets/wall-clock concurrency (deterministic single-threaded).
- No scenario DSL, no large scaling sweeps, no plotting — the harness ships ~5 built-in scenarios + a negative control + a text/JSON report.
- **Not** a model of metalbond gaining consensus or a CP store; the leased/CP variant is out of scope (it assumes infra metalbond does not have — see Appendix A).
- Does not change library code; the sim is a consumer of the public `ironcore`/`mls` API.

---

## 4. Architecture (event-queue actors)

```
sim/                      (root module, stdlib-only)
  scheduler.go   Scheduler{clock, pq, rng}: timestamped event priority queue
  event.go       Event{at, actor, kind, payload}; kinds: deliver|timer|fault|churn
  bus.go         Bus: per-VNI/per-replica fan-out + fault application (drop/partition/latency)
  ds.go          DS actor ("MetalBond"): per-reflector local accept-once register + per-replica log + GroupInfo cache
  client.go      Client actor ("metalnet"): two ironcore.Controllers per VNI (one per replica) + commit/catch-up
  fault.go       FaultConfig + the seeded fault decisions
  invariant.go   InvariantChecker: per-replica convergence + data-plane zero-loss + membership
  metrics.go     Metrics + report (text table / JSON)
  scenario.go    Scenario definition + the built-in scenarios
  sim.go         Run(scenario, seed) -> Result{InvariantsHeld, Divergence, PacketLoss, Membership, Metrics, Trace}
cmd/metalsim/
  main.go        CLI: -scenario -clients -vnis -seed -rounds -drop -json -v
sim/*_test.go    per-component tests + a seeded property test per scenario + TestDeterminism
```

**Execution model.** The `Scheduler` holds a min-heap of events keyed by logical timestamp (ties broken by a monotonic sequence number). `Run` seeds the RNG, schedules the scenario's initial events, then pops events in order; each handler mutates actor state, calls the real library, and schedules follow-ons. Single-threaded → identical `(seed, scenario)` ⇒ byte-identical run. Logical time advances only via scheduled delays (latency, timer intervals); real CPU time is *measured* per op but never *drives* scheduling.

**Determinism rules (hard).** No goroutines/channels; no `time.Now()`/`time.After()` in control flow (`time` is used only to *measure* crypto CPU); no map-iteration-order dependence (sort keys before iterating); one `*rand.Rand` seeded from the scenario seed threaded through all fault/timing decisions. The `TestDeterminism` gate replays a fault-heavy scenario at the same seed and asserts an identical event trace + identical metrics.

**Where ordering safety lives.** Each reflector runs its **own** local `MemorySequencer` (accept-once per `(group, epoch)`) and serializes a replica's commits *before* fan-out. That single-writer-per-replica register **is** the total-order broadcast for that replica — so each replica is fork-free by construction, with **zero reflector-to-reflector coordination**. No client-side fork resolution is required.

---

## 5. Components

### 5.1 Bus (in-memory transport)
- Per-VNI/per-replica fan-out: actors `Subscribe(channel)` / `Publish(channel, msg)`; a publish becomes scheduled `deliver` events to current subscribers. A *channel* is `(vni, replica)`.
- Envelope: `{channel, kind, src, dst|broadcast, epoch, payload []byte}`, `kind ∈ {proposal, commit, welcome, groupInfo, logRequest, logReply, heartbeat, dataPacket}`; `payload` is the real MLS/ironcore bytes.
- **Fault application per delivery:** seeded **drop** (per-link prob), **delay** (latency/jitter), **block** (if `src→dst` partitioned). Drops/partitions hit *deliveries*, not the reflector's log copy — the catch-up path heals them.

### 5.2 DS actor ("MetalBond") — two independent reflectors with a local register
The two reflectors **never communicate** (no mesh, no shared store, no lease, no consensus). Each is an independent fan-out that *also* runs a **local accept-once register** (`sequencer.MemorySequencer`, per reflector, never shared):
- **Local serialize + fan-out:** on receiving a `commit` for its replica's `(vni, epoch)`, the reflector calls its **own** `AcceptCommit`; on accept it appends to that replica's log, updates its GroupInfo cache, and `Publish`es the winner to the replica's subscribers; on reject (a competing commit already won *at this reflector*) it drops. The local register is a total-order broadcast for that replica.
- **Catch-up service:** answers `logRequest{channel, fromEpoch}` from its log and serves its cached `GroupInfo`.
- **`ds_down` / restart:** a reflector stops (no fan-out, no catch-up); **the other replica keeps the data plane alive**. On restart it catches its register/log up to the replica's current epoch before clients resume committing to it.

### 5.3 Client actor ("metalnet") — N instances
Each client runs **two** real `ironcore.Controller`s per VNI (one per replica), each with its own group ID and SA derivation (`saVNI = vni*numDS + r`).
- **Membership / churn / outbound:** for each replica, the designated committer (lowest active leaf) produces a commit via that replica's `Controller` and sends it to that replica's reflector, which serializes via its local register and fans out the winner. A churn op is applied to both replicas.
- **Inbound:** `deliver(commit)` from a reflector → the matching replica's `Controller.HandleCommit` (applies if it matches the current epoch; rejects stale). `deliver(welcome)` → join. `deliver(heartbeat/groupInfo)` newer → catch-up.
- **Catch-up (drops/partition):** on a gap, `logRequest` to the replica's reflector + replay; if the gap is too large, `RecoverViaExternalCommit` from that replica's latest `GroupInfo`. (This is the only place recovery is used — purely as a behind-member catch-up, never to resolve a fork.)
- **Periodic rekey:** the designated committer issues an empty Update on a timer (PCS), per replica, via that replica's reflector.

### 5.4 Fault model (`FaultConfig`, seeded)
- `DropProb` (per-link override allowed); `Latency`, `Jitter`.
- `Partitions []{At, Until, SideA, SideB}` — isolate actor sets. A `client-subset ↔ reflector` partition makes the partitioned clients fall behind on that reflector's replica while they keep the data plane on the **other** replica; they catch up on heal.
- `DSDowns []{At, Until, DS}` — a reflector stops then restarts (the other replica carries traffic; the stopped replica catches up on return).
- `Churn` — scheduled membership add/remove (applied to both replicas).
- **Quiescent settle:** after the settle deadline the loop schedules **no new churn or periodic-rekey** and **lifts all faults**, then drains long enough for all catch-up to complete — so laggards converge against a *stationary* group, not a moving target.
- All decisions come from the single seeded `*rand.Rand`.

### 5.5 Invariant checker (the primary deliverable)
Invariant 2 (data-plane zero-loss) is checked **continuously** during the run; invariants 1 and 3 are evaluated at **quiescence** after the settle window:
1. **Per-replica convergence (safety):** for each replica channel, all *live* members agree on `Group.EpochAuthenticator()` **and** the derived ESP SA `Key` (byte-equal). Mismatch after settle ⇒ **DIVERGENCE FAIL**.
2. **Data-plane zero key-loss (headline):** for every data packet generated during the run that is *not* dropped by the transport, the receiver **must hold a matching SA** (by SPI) to decrypt it. Any undecryptable non-dropped packet ⇒ **PACKET-LOSS FAIL**, recording the sent/received epoch and time. (Transport drops are tracked separately and are *not* failures — they model lossy links, not key-rotation loss; the property is "rotation/failover never *causes* loss," distinct from "the link is perfect.")
3. **Membership correctness:** the live member set per replica channel matches the scenario's intended set after churn settles ⇒ else **MEMBERSHIP FAIL**. Liveness is folded in: a member that failed to catch up is absent from the live set and trips this check.

`Run` returns `InvariantsHeld bool` + per-invariant detail; each scenario's property test asserts it over seeds 1..20.

### 5.6 Metrics (secondary)
Deterministic counts/logical-time + real CPU timing of the actual crypto calls:
- rounds-to-converge per membership change / failover;
- messages + bytes fanned out per commit + totals (note: two groups ~double the fan-out vs a single reflector — the redundancy cost);
- SA state per member (~2×), max SA-overlap depth (`W+1`), and max send-lag actually required for zero loss — the concrete ESP overlap-window parameters metalnet would configure;
- data packets sent / decryptable, packet-loss events (target 0);
- catch-up requests, log-retransmits, external-commit recoveries;
- ds-down recovery time (logical rounds);
- real crypto CPU per op (`HandleCommit`, `JoinViaWelcome`, `Reconcile`, `Rekey`, `DeriveSAKeys`), measured, never scheduling.

Reported as a text table (default) or JSON (`-json`), reproducible by seed.

### 5.7 Data-plane model + make-before-break / sender-lag (zero-loss core)
The sim models the ESP data path explicitly so it can *prove* zero packet loss across rekeys and failovers.
- **SA derivation (real library):** each member derives its per-replica epoch SA via `ironcore.DeriveSAKeys` and retains the last `W` epochs' SAs (overlap set; `W` is a policy knob the sim measures the minimum useful value of).
- **Installed-SA set per member:** the SAs a member can **decrypt** with = its current epoch SA ∪ the last `W` retained ones, **per replica**. Indexed by `SPI` (which encodes the replica channel + epoch), so a receiver selects the SA by the packet's SPI (exactly RFC 4303 ESP demux).
- **Send-SA selection (the policy under test):** a member **sends** under the latest epoch it believes is replica-wide-converged, *not* necessarily its own current epoch (per-replica sender-lag), and chooses a replica `r` where both endpoints share a usable SA. With two replicas, such an `r` exists even while one replica is stalled/partitioned/down — which is exactly why a reflector failure costs **zero** data-plane packets.
- **Data traffic generation:** a scheduled `dataPacket` event has a random live member of a VNI "send" a packet (tagged with the SPI/epoch of its current send-SA on the chosen replica); the Bus fans it out (subject to drops/partition — a *dropped* data packet is a transport loss, **not** a key-rotation loss, and is excluded from invariant 2). Each receiver checks whether it holds the matching SA.

---

## 6. Built-in scenarios
Each is a `Scenario{Name, Clients, VNIs, Suite, W, Faults, Partitions, DSDowns, Churn, SettleRounds, ...}`; **all run continuous data traffic (§5.7) and assert all three §5.5 invariants — including zero key-loss (inv. 2) throughout.** `ds_down` and `partition_recover` are the critical zero-loss tests: not a single data packet may become undecryptable while a reflector is down or while a client is partitioned from one reflector.

1. **`nominal`** — churn across the VNIs, no faults. Baseline per-replica convergence + fan-out metrics.
2. **`drops`** — churn + steady per-delivery drops (20%). Exercises log-replay catch-up and committer resend; both replicas still converge with zero key-loss.
3. **`ds_down`** — reflector R0 stops mid-run (then restarts) → replica 0 stalls. The redundancy headline: **replica 1's SA carries all data (zero loss)** while R0 is down; replica 0 catches up on R0's return. Demonstrates graceful-freeze-with-no-loss.
4. **`partition_recover`** — a client subset is cut from reflector R0 → those clients fall behind on replica 0 and ride **replica 1 (zero loss)**; they catch up replica 0 on heal. Asserts liveness + per-replica convergence + zero loss across an active cross-replica failover.
5. **`both_rekey`** — concurrent periodic rekeys across both replicas of multiple VNIs + churn, no faults. Asserts zero key-loss via per-replica make-before-break while both groups rotate keys independently.

**Negative control (`negative_control`, not in the property suite).** A single replica (no redundancy), `W=0`, no sender-lag, with drops + churn. A rekey **must** produce undecryptable packets ⇒ invariant 2 **fails**. This proves the zero-loss checker has teeth rather than being vacuous. It is reachable from the CLI (`-scenario negative_control`) but excluded from `All()` because it is expected to fail.

---

## 7. CLI (`cmd/metalsim`)
Flags: `-scenario <name|all>`, `-clients N`, `-vnis M`, `-seed S`, `-rounds R` (settle), `-drop p`, `-json`, `-v` (per-event trace). Exit nonzero on any invariant failure (safe as a CI gate). `-scenario all` runs the property suite and prints a summary table (scenario × status × packet-loss × commit fan-out × data-decryptable × max-overlap × max-send-lag). `-seed` reproduces a run exactly.

```sh
make sim                                          # go test ./sim/... + the all-scenarios CLI smoke
nix develop -c go run ./cmd/metalsim -scenario all
nix develop -c go run ./cmd/metalsim -scenario partition_recover -seed 7
```

---

## 8. Testing
- **Unit:** scheduler determinism; bus drop/partition/latency; DS local-register serialize + log/retransmit; client commit / catch-up; invariant checker (positive + a hand-injected divergence/loss is caught).
- **Determinism gate (`TestDeterminism`):** a fault-heavy scenario run twice with the same seed ⇒ byte-identical event trace + identical metrics.
- **Property gate (the point):** each of the 5 scenarios runs as a `go test` asserting `InvariantsHeld == true` over seeds 1..20 — a seeded fault-injection property test over the real library — plus the negative-control test asserting invariant 2 *fails* when redundancy + make-before-break are disabled.
- `make sim` target; root module stays zero-dep.

---

## 9. Definition of done
- `sim/` engine + dual-redundancy DS + client actors + fault model + invariant checker + metrics, stdlib-only, zero new deps.
- `cmd/metalsim` CLI; `make sim` target.
- Determinism gate passes (same seed ⇒ identical run).
- All 5 scenarios pass their invariant assertions across seeds 1..20.
- **Zero key-loss (inv. 2) holds in every scenario across all seeds** — no data packet ever undecryptable due to rekey or reflector failover/partition — and the report states the SA-overlap depth `W+1` and max send-lag observed.
- A data-plane **negative control** confirms the checker has teeth: a single replica with make-before-break disabled (`W=0`, no sender-lag) under rekey+churn **must** produce PACKET-LOSS FAIL.
- Metrics report emits (text + JSON).
- Library code unchanged.

---

## Appendix A — Alternatives considered (design journey)

Three ways exist to get per-VNI commit ordering for a metalbond reflector pair. The library code supports all of them; this section records why **dual-group pure redundancy** was chosen as the default the simulation validates, and preserves the reasoning behind the rejected/deferred alternatives.

### A.1 Pure AP / lowest-Hash (earliest revision) — rejected
Dumb fan-out, no register at either reflector; the canonical branch of a fork is defined by **lowest `Hash(Commit)`** among the competing commits, healed by external-commit recovery (`CanonicalCommit`). **Rejected:** it **forks on *every* concurrent commit** and needs *all* clients to eventually see *both* branches to pick the same canonical winner — fragile under partition (a client that sees only one branch cannot heal until the partition lifts). It also requires async loss-detection glue in the client (commit optimistically, discover loss later) that the other models avoid.

### A.2 Leased CP store (main design §5.5 "B1") — rejected as the *default*
A *shared*, strongly-consistent store / lease / fencing token (etcd, a witness, or the K8s control plane) makes exactly one reflector the writer for a VNI. Zero transient forks, zero lost rekeys. **Rejected as the default** because real metalbond is an independent route-reflector *pair* with **no consensus and no shared store** — B1 as written assumes infra that isn't there. The library code remains valid for deployments that *do* add such a store.

### A.3 Static-precedence local registers (rev 4) — deferred (a valid scaling alternative)
Each reflector runs its **own local** accept-once register (`MemorySequencer`, never shared); clients choose the authoritative reflector by **static per-VNI precedence** (`primaryDS(vni) = vni % numDS`) and fall back to the standby only when the primary is unreachable. This is essentially "B1 without the lease/fence" — the single writer per VNI is chosen by static config instead of a leased token. It is **fork-free in the common case and under a clean primary crash**; the only residual fork window is a *partitioned-but-alive* primary, healed deterministically by precedence-based external-commit recovery (a client need not see both branches; reflectors need not coordinate). It uses **one** group per VNI (≈ half the control-plane/SA cost of dual-redundancy) and naturally **shards** load across the two reflectors by VNI — so it is attractive when scaling, not redundancy, is the priority. It is **deferred** as a possible *second simulation mode*: running it alongside dual-redundancy would quantify the redundancy-vs-scaling trade-off (≈2× cost + guaranteed zero-loss vs ≈1× cost + a partition-only fork window).

### A.4 Dual-group pure redundancy — chosen (this simulation)
Two independent single-sequencer groups per VNI, one per reflector (§1). **No forks ever** (each replica is serialized by one local register; no shared state to diverge), **no client-side fork resolution**, the **strongest** zero-loss property (a whole replica can be down/partitioned and the other carries traffic), at the cost of **~2× control-plane and SA state**. Chosen as the default because it is the simplest model that is unconditionally fork-free *and* gives the strongest data-plane guarantee under metalbond-as-it-actually-is (two independent reflectors, no coordination).

### A.5 Comparison of the three ordering regimes

| Regime | Shared store? | Reflector coordination? | Groups/VNI | Forks | Zero data-plane loss | Verdict |
|---|---|---|---|---|---|---|
| **Leased CP store** (A.2, design §5.5 B1) | **yes** (etcd/lease) | via the store | 1 | none | yes (CP) | valid only if a consistent store exists — metalbond has none |
| **Static-precedence local registers** (A.3) | no | none | 1 | only under *partitioned-but-alive* primary, auto-healed | yes outside the fork window | **deferred** — the scaling-oriented alternative |
| **Dual-group pure redundancy** (A.4, **chosen**) | no | none | 2 | **none** | **yes, unconditionally** (redundant replica) | **chosen** — simplest, strongest, ~2× cost |

This refines main design §5: the recommended metalbond model is **dual-group redundancy** (validated here) or **static-precedence local registers** (A.3) — **not** the leased CP store (§5.5 B1), which assumed infra metalbond lacks.
