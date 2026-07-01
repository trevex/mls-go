# MLS-per-VNI Scaling Benchmark — Measured Results

**Purpose:** turn the `O()` claims in `comment.md`'s scaling section into concrete,
measured constants and a falsifiable "MLS is / isn't a good fit" verdict for a
datacenter-scale envelope. Design and methodology:
[`docs/superpowers/specs/2026-07-01-scaling-benchmark-design.md`](superpowers/specs/2026-07-01-scaling-benchmark-design.md).

All numbers below are copied from actual command output on an AMD Ryzen 7 7840U
(Go 1.26.4, linux/amd64). Reproduce with `make bench` and `make scalebench`.
Where two suites are shown, **classical (`0x0001`) is the optimistic case and
X-Wing (`0xF001`, X25519 + ML-KEM-768) is the pessimistic (post-quantum) case.**

---

## Tier 1 — Measured per-event constants (real crypto)

Deterministic wire sizes of an `Update` (empty PCS-rekey) commit and the Welcome
produced when adding one member, as a function of members-per-VNI `M`. These are
the constants that replace `O(log M)` / `O(M)` in the projection.

| M | classical commit_bytes | classical welcome_bytes | X-Wing commit_bytes | X-Wing welcome_bytes | X-Wing / classical (commit) |
|-----|-----|-----|-----|-----|-----|
| 2   | 472   | 1017  | 3931   | 8031   | 8.33× |
| 8   | 1034  | 2173  | 13397  | 18675  | 12.96× |
| 20  | 2088  | 4291  | 29891  | 36198  | 14.32× |
| 32  | 3072  | 6411  | 43945  | 53723  | 14.31× |
| 128 | 11014 | 22999 | 158805 | 186433 | 14.42× |

**The PQ cost is explicit: at the nominal `M = 20`, an X-Wing commit is 29891 B
vs 2088 B classical — a ~14.3× inflation** driven by the ML-KEM-768 ciphertexts
in the TreeKEM direct path. The ratio settles at ~14× for `M ≥ 20` and is the
single dominant fit input for the reflector-load verdict below.

> **Proxy note.** The projection feeds a single `bytes_per_commit` (the `Update`
> size above) for the *entire* `rekey + churn` commit stream, i.e. Update-commit
> bytes stand in for Add/Remove commits too. Measured spread at `M = 20` is
> small: X-Wing Add = 32539 B (+8.9%), Remove = 27507 B (−8%) vs Update 29891 B —
> and a VM migration is a leave+join (Remove+Add) whose **average (30023 B) is
> within 0.4% of the Update proxy**. The pure-rekey term is exact. So the
> single-constant simplification does not move the borderline X-Wing knee.

Representative CPU (from `make bench`, `-benchtime 5x`; machine-dependent,
reporting only):

| operation | suite | M=8 | M=32 | M=128 |
|-----|-----|-----|-----|-----|
| CommitUpdate (committer) | classical | 0.88 ms | 3.08 ms | 11.20 ms |
| CommitUpdate (committer) | X-Wing    | 1.78 ms | 5.79 ms | 20.61 ms |
| Apply (member)           | classical | 0.40 ms | 0.68 ms | 2.02 ms |
| Apply (member)           | X-Wing    | 0.89 ms | 1.89 ms | 4.44 ms |

CPU per event is sub-millisecond-to-low-millisecond at realistic `M`; the fit is
byte-bound at the reflector, not CPU-bound at the host (see Tier 2).

---

## Tier 2 — Datacenter projection (analytical, `S = 1`)

`make scalebench` sweeps `H ∈ {10³, 10⁴}` × `V ∈ {10³, 10⁴, 10⁵}` at the nominal
`M = 20`, rekey interval 3600 s, migration interval 600 s, and the **default
reflector forwarding budget of 100 MB/s** (single redundant reflector, `S = 1` —
metalbond does not shard today). The verdicts:

```
suite 0x0001 (classical):
VERDICT: single reflector stays under budget across the swept envelope — MLS fits at S=1

suite 0xF001 (X-Wing):
VERDICT: single reflector saturates at V=100000 VNIs (budget 100 MB/s) — trigger for deferred sharding
```

**Reflector-forwarding knee at the 100 MB/s budget:**

- **classical:** no knee in the swept envelope — at the worst corner
  (`V = 10⁵`) reflector fan-out is only **7.71 MB/s**, comfortably under budget.
- **X-Wing:** knee at **`V = 100000`** — the ~14× byte inflation pushes fan-out
  to **110.4 MB/s** at `V = 10⁵`, just over the 100 MB/s budget. This is the
  concrete `V` that would trigger the deferred sharding optimization.

Representative CSV row (the X-Wing saturating datacenter corner, `H = 10⁴`,
`V = 10⁵`):

```
H,V,M,density,reflector_fwd_bytes_per_s,reflector_order_ops_per_s,host_apply_per_s,host_cpu_frac_busy,reflector_saturated,ikev2_establish_handshakes,ikev2_steady_handshakes_per_s
10000,100000,20,200,1.104306388888889e+08,194.44444444444446,0.3888888888888889,0,true,1.9e+07,3166.666666666667
```

**Host load is flat in `V` (density-bounded).** At the datacenter corner
(`H = 10⁴`, `V = 10⁵`, `M = 20`) the per-host VNI density is

```
D = V·M / H = 10⁵ · 20 / 10⁴ = 200 VNIs/host
```

and `host_apply/s = D·(r_rekey + λ_move) ≈ 0.389 applies/s`, with
`host_cpu_frac_busy ≈ 0` (rounds to zero — negligible). Crucially, `D` is
identical for the `(H=10³, V=10³)` and `(H=10⁴, V=10⁴)` rows: **host load
depends only on density `D`, not on the total VNI count `V`.** Hosts are fine as
long as `D` is bounded, independent of how large the fabric grows.

**IKEv2 analytical overlay (contrast).** Over the same points the pairwise-IKEv2
baseline costs `Σ = V·M²/2` interactive `IKE_SA + CHILD_SA` handshakes to
*establish* — e.g. **1.9×10⁷ handshakes** at the `V = 10⁵` corner, versus MLS's
one fanned commit per VNI per rekey. Each MLS membership change is a single
`O(log M)` commit fanned to its group; each IKEv2 membership change is `O(M)`
re-handshakes with round trips + half-open state. MLS moves the cost off the
`O(M²)` interactive-mesh axis and onto reflector fan-out throughput — which is
exactly the axis the knee above quantifies.

---

## Tier 2b — Packets and CPU (the reflector's real limits)

On modern fabrics (100 G links) reflector **bytes** are a non-issue; the binding
resources are **packets/s** and **CPU**. The key structural fact:

> **The reflector runs no MLS crypto — it is a blind relay of ciphertext.** Its
> only cost is packet fan-out (`(M−1)` copies per commit) plus sequencing. All
> per-commit crypto lives on the hosts: the committer *generates* the commit, the
> members *apply* it, spread across the fleet.

`scalebench` projects this directly: `-mtu` fragments each commit into
`ceil(bytes/MTU)` packets and reports `reflector_fwd_pkts_per_s`; `-pkt-budget-pps`
adds a packet-rate knee (`VERDICT(pps)`); `-cpu-commit-ms` / `-cpu-apply-ms` (from
`make bench`, machine-dependent) project committer and host-apply CPU as a
fraction of one core.

**Extreme churn: 100 VM churns/s across the whole fabric** (`H = 1000`,
`V = 10 000`, `M = 20`). Counting each migration as leave+join = **200 commits/s**
fleet-wide (`-move-s 50`), measured CPU `cpu_commit = 2.05/3.97 ms`,
`cpu_apply ≈ 0.55/1.1 ms` (classical/X-Wing):

| resource (per reflector / per host) | classical | X-Wing |
|---|---|---|
| Reflector fan-out (3 800 msgs/s) | 7 600 pps @1500 · 3 800 @9000 | **80 908 pps @1500** · 15 411 @9000 |
| Host-apply CPU (4 applies/s/host) | 0.22 % of a core | 0.45 % of a core |
| Committer CPU (distributed) | 0.04 %/host | 0.08 %/host |

Everything is 2–3 orders of magnitude below any limit. Packets fragment worst for
X-Wing (30 KB commit → 21 packets at 1500 MTU), but 81 k pps is nothing for a NIC
that does millions.

**Where packets/CPU actually bind — ceilings (max commits/s):**

| binding resource | classical | X-Wing |
|---|---|---|
| **Reflector fan-out pps** (@1 Mpps, conservative SW) | 26 000 | **2 500 @1500 · 13 000 @9000** ← lowest |
| Host-apply CPU (@10 % core/host) | ~9 000 | ~4 500 |
| Committer CPU (@10 % core × 1000 hosts) | ~4 900 | ~2 500 |

The lowest ceiling is **X-Wing reflector fan-out pps at standard MTU: ~2 500
commits/s ≈ 1 250 migrations/s — still ~12× above the 100 VMs/s extreme.** It is
lowest because two factors stack: the `(M−1) = 19` fan-out multiplier *and*
X-Wing's 30 KB commits fragmenting into ~21 packets each. Three cheap levers, best
bang-for-buck first:

1. **Jumbo frames (9000 MTU)** — X-Wing packets 21 → 4, lifting the pps ceiling
   **5×** (2 500 → 13 000 commits/s). Nearly free; the biggest single win.
2. **A real reflector** — 1 Mpps is a conservative *software* figure;
   DPDK/kernel-bypass reflectors do 10–100 Mpps → 25 k–250 k commits/s.
3. **Sharding** (the deferred one) — linear in per-reflector commits/s.

**Watch item:** fan-out pps scales linearly with **M** (the `(M−1)` term). At
`M = 20` it is comfortable; a large tenant VNI (`M = 100+`) fans each commit to
~100 subscribers, so that VNI's reflector pps grows proportionally. The commit
*rate* stays tiny; the *fan-out multiplier* is what concentrates at the reflector.

---

## Tier 3 — Sim validation (real stack, tractable scale)

`make sim` / `metalsim -scenario migration_churn` runs the real MLS crypto under
a discrete-event model with leave+join VM-migration churn (5 clients, 2 VNIs,
dual-replica redundancy). Result:

```
=== scenario: migration_churn        [PASS] ===
  divergence  (inv.1):  0 failures
  packet-loss (inv.2):  0 events
  membership  (inv.3):  0 failures

commits-issued         132
commit-deliveries      1173
commits-applied         231
fanout-amplification    8.89
max-converge-ticks        8
horizon                 614
```

- **Packet-loss = 0** under leaves + joins (VM migration = leave(src) + join(dst)
  per VNI). Dual-group make-before-break holds zero tenant data-plane loss across
  membership churn, not just reflector failover.
- **max-converge-ticks = 8** vs a churn inter-arrival of ~51 ticks (horizon 614
  over the 12 membership-change ops in the plan) — convergence is ~6× under the
  churn cadence, so MLS does not fall behind.

**Realized fan-out grows with membership**, validating the `(M−1)` term in the
Tier-2 `reflector_fwd` formula. Re-confirmed by sweeping client count (via the
`TestReflectorForwardsScaleWithMembership` helper, which regenerates the join
plan for each client count — note `metalsim -clients N` does **not** reproduce
these, because that flag overrides `Clients` without regenerating `Churn`):

| clients | fanout-amplification |
|-----|-----|
| 3 | 8.20 |
| 5 | 13.39 |
| 8 | 22.08 |

The `metalsim -scenario nominal` baseline (5 clients) measures
**fanout-amplification = 13.39** with the same `max-converge-ticks = 8`,
`packet-loss = 0`, and `commits-issued = 127 / commits-applied = 432`. The
monotonic 8.20 → 13.39 → 22.08 growth is what the model's `(M−1)` reflector
fan-out multiplier predicts.

---

## The three fit-verdict numbers

1. **Host load is density-bounded / flat in `V`.** `host_apply/s = D·(r_rekey +
   λ_move)`. At the datacenter corner `D = 200` VNIs/host ⇒ ≈ 0.389 applies/s,
   `host_cpu_frac_busy ≈ 0`. Independent of `V`. **Hosts are fine.**
2. **Reflector load is linear in `V`, with its knee at `S = 1`.** Classical: no
   knee in-envelope (7.71 MB/s at `V = 10⁵`). X-Wing: knee at **`V = 100000`**
   (110.4 MB/s > 100 MB/s budget). This single number is the concrete trigger
   for the deferred sharding optimization.
3. **Convergence stays well under the churn inter-arrival.**
   `max-converge-ticks = 8` vs ~51-tick mean inter-arrival under migration churn
   — ~6× margin, with `packet-loss = 0`. **MLS does not fall behind.**

All three hold for **classical across the entire datacenter envelope**. For
**X-Wing**, (1) and (3) hold; (2) is the only one that bites, and only at the
extreme `V = 10⁵` corner.

---

## Tie-back to `comment.md`

`comment.md`'s scaling table asserted MLS moves cost off the `O(N²)` interactive
handshake axis onto "metalbond reflector ordering throughput
`≈ O(#VNIs × rotation_rate)`". These measurements put constants on that claim:

- The `O(log M)`/`O(M)` per-commit terms are now numbers:
  **bytes_per_commit(M=20) = 2088 B classical, 29891 B X-Wing (~14.3×)**, with
  sub-to-low-millisecond CPU per event.
- The reflector concentration `comment.md` flagged as "where the cost moves" has
  a measured saturation point: at the default 100 MB/s budget the single
  reflector **stays under budget for classical across the whole `H ≤ 10⁴`,
  `V ≤ 10⁵` envelope**, and for X-Wing sits **just above the knee only at the
  `V = 10⁵` extreme (110.4 MB/s)**.

So for the classical suite the datacenter envelope sits **below** the
single-reflector knee — MLS fits as-is and **sharding is not required**. For the
post-quantum X-Wing suite the envelope reaches the knee exactly at the top corner
(`V = 10⁵`), which is the precise, quantified trigger for the sharding
optimization that `comment.md` deferred as future work — not a reason to abandon
the design, but the number that tells you *when* to shard.
