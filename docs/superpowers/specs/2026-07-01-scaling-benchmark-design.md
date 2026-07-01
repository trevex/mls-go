# MLS-vs-IKEv2 Scaling Benchmark Design

**Date:** 2026-07-01
**Status:** Design approved, pending implementation plan.

## Goal

Answer, with measured numbers rather than asymptotics: **as metalnet scales
(hosts, VNIs, members-per-VNI, churn and VM-migration rate), what control-plane
load does the MLS-per-VNI design impose on (a) metalbond reflectors and (b)
metalnet hosts, and how does that compare to a pairwise-IKEv2 baseline?**

The output must turn the `O()` scaling claims for MLS-per-VNI key agreement into
concrete constants, and produce a falsifiable "MLS is / isn't a good fit"
verdict for a datacenter-scale envelope.

## Target envelope

Datacenter scale: **H ∈ [10³, 10⁴] hosts, V ∈ [10³, 10⁵] VNIs**, VMs sparse
across hosts, tens of members per VNI. The sweep must reach the point where the
reflector Σ-load (linear in V) actually bites — that is the regime the verdict
turns on. The IKEv2 baseline is costed **analytically** over the same points.

## Core modeling insight

The two scarce resources scale on **different axes**:

- **Host load is density-bounded, not V-bounded.** A host is a member of only
  the VNIs whose VMs it runs. With mean members-per-VNI `M`, the mean
  VNIs-per-host is `D = V·M / H`. A host in `D` VNIs bears `D` VNIs' commit
  rate regardless of how many VNIs exist elsewhere.
- **Reflector load is Σ-bounded.** A reflector must forward and linearize
  commits for every VNI it serves — linear in `V`. **Metalbond does not shard
  today**: the reflector is a single redundant pair, so the baseline is `S = 1`
  and reflector load is the *full* `V·(r_rekey + λ_move)·(M−1)` fan-out. The
  sweep's headline is therefore the `V` at which that single reflector
  saturates a forwarding budget — the number that would *motivate* sharding.

Sharding is a **deferred future optimization**, not part of the baseline. The
model keeps shard count `S` as a parameter (default `1`) purely so "what would
sharding buy" is answerable later; every baseline sweep and the fit verdict run
at `S = 1`. Surfacing *when* a single reflector saturates is half the
deliverable.

## Why three tiers

You cannot run real MLS crypto for 10⁵ groups in a discrete-event sim. So the
sim's job is to **measure constants and prove convergence**, and a pure
analytical layer **projects** those constants across the datacenter envelope.

### Tier 1 — Micro-benchmarks (real crypto, `testing.B`)

Measure per-event constants as functions of members-per-VNI `M`
(`M = 2 … few hundred`):

- `cpu_per_commit(M)` (committer), `cpu_per_apply(M)` (member),
- `bytes_per_commit(M)`, `bytes_per_welcome(M)`,
- `state_per_group(M)` (in-memory group/TreeKEM footprint — feeds
  `host_state_bytes`),
- broken out per operation (`Join` / `Leave` / `Update`) and per suite
  (classical `0x0001` **and** X-Wing `0xF001` — ML-KEM ciphertexts inflate
  `bytes_per_commit`, and that PQ cost is a real fit input).

These are the constants that replace `O(log M)` / `O(M)` with numbers.

### Tier 2 — Analytical scaling model (fed by Tier-1 constants)

A pure function over the envelope, no crypto. Given the measured constants and
wall-clock rates (`r_rekey` = 1 / rekey-interval-seconds; `λ_move` = migration
events per VNI per second, from ops data):

```
D                       = V·M / H                                    # mean VNIs-per-host
reflector_fwd_bytes/s   = (V/S)·(r_rekey + λ_move)·(M−1)·bytes_per_commit(M)   # per shard
reflector_order_ops/s   = (V/S)·(r_rekey + λ_move)                   # linearization throughput, per shard
host_apply/s            = D·(r_rekey + λ_move)                       # flat in V
host_cpu/s              = D·(r_rekey + λ_move)·cpu_per_apply(M)
host_SA_installs/s      = host_apply/s                               # one XFRM/rte_ipsec SA per epoch
host_state_bytes        ≈ D · state_per_group(M)
```

Swept over `H` and `V` at the baseline `S = 1` (the redundant single reflector
metalbond has today). Emits CSV; the **knee** is where `reflector_fwd_bytes/s`
or `reflector_order_ops/s` exceeds a configurable forwarding budget — i.e. the
`V` at which the single reflector saturates. `S` remains a parameter so a
follow-up sweep can quantify what sharding would buy, but that is out of
baseline scope.

**IKEv2 analytical overlay** — same `(H, V, M, λ)` points:

- Establishment: `Σ = V · M²/2` pairwise IKE_SA + CHILD_SA handshakes.
- Per migration: `O(M)` re-handshakes with the affected peer's group, each with
  round trips + half-open state (no reflector, but O(M²) mesh per VNI).
- Data-plane SA count: **identical** to MLS (topology-bound, not keying-bound).

Output: one head-to-head CSV backing the `O(N²)`-vs-MLS scaling comparison with
*measured* MLS constants vs *modeled* IKEv2.

### Tier 3 — Sim validation (real stack, tractable scale)

Extend the existing discrete-event sim to the largest tractable point
(~10²–10³ hosts/VNIs) to:

1. **Validate** Tier-2's constants against a real run (measured
   `reflector_fwd` / `host_apply` per tick must match the model's prediction at
   that point within tolerance), and
2. Confirm **`commit_to_converge_ticks < churn_inter_arrival`** — the actual
   "MLS falls behind" failure mode — at the target `λ_move`.

## Model gaps to close first (in the sim)

1. **Leave + migration churn.** `churnPlan` / `ChurnOp` are join-only today.
   Add a `Leave` op, and a **migrate primitive = leave(src-host) + join(dst-host)**
   per affected VNI — the realistic "changing mappings across hosts" case.
2. **Rate + per-actor metrics.** `Metrics.CommitMsgs` is an aggregate total.
   Split into `reflector_fwd` (fan-out the reflector forwards) vs `host_apply`
   (commits a host decrypts+applies), **per-VNI** and **per logical tick**, so
   the sim emits rates comparable to Tier-2's projection. Add
   `commit_to_converge_ticks` and `pending_epoch_backlog`.

## Units discipline

The sim stays **dimensionless** (per-event, per-tick). Tier 2 applies real
wall-clock rates. No pretending a logical tick is a fixed millisecond; the
projection's honesty comes from measured per-event constants × ops-sourced
rates.

## The fit verdict

Three falsifiable numbers across the datacenter envelope:

1. **Host load density-bounded** — `D·rate`, flat in `V` ⇒ hosts are fine iff
   `D` is bounded.
2. **Reflector load Σ-bounded** — linear in `V` at the single-reflector
   baseline (`S = 1`). The model reports the `V` at which the single reflector
   saturates a given forwarding budget; if that `V` is beyond the target
   envelope, MLS fits as-is, and if not, that number is the concrete trigger
   for the deferred sharding optimization.
3. **Convergence under churn** — `commit_to_converge_ticks < churn_inter_arrival`
   at target `λ_move`.

If all three hold, MLS is a good fit. Whichever breaks first is the precise,
quantified reason it isn't.

## Deliverables

- Tier-1 `testing.B` benchmarks producing a constants table (per M, op, suite).
- Tier-2 pure Go scaling model + CLI that sweeps `(H, V, S)` and emits CSV,
  with the IKEv2 analytical overlay.
- Tier-3 sim extensions: leave/migrate churn, per-actor/per-tick rate metrics,
  convergence-vs-inter-arrival check, and a validation test asserting the sim's
  measured rates match Tier-2's prediction at a shared point.
- A short results write-up (constants + the three verdict numbers) suitable as
  further input to the `O(N²)`-vs-MLS scaling discussion.

## Non-goals

- Not a production metalnet/dpservice integration; the data-plane SA
  programming cost is modeled, not exercised.
- Not sweeping the *real* crypto to 10⁵ groups (infeasible; that is exactly
  why Tier 2 exists).
- Not re-deriving MLS correctness — that is covered by the existing KATs,
  conformance gate, and OpenMLS e2e.
