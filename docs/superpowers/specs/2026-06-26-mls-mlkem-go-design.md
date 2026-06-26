# mls-mlkem-go — Design Spec

- **Status:** Draft for review
- **Date:** 2026-06-26
- **Repo:** `github.com/trevex/mls-mlkem-go`
- **Context:** IronCore underlay-encryption enhancement ([ironcore-dev/enhancements#38](https://github.com/ironcore-dev/enhancements/pull/38)). That proposal encrypts tenant traffic between dpservice instances with IPsec ESP over IPv6, and distributes **rotating ephemeral hybrid (X25519 + ML-KEM-768) public keys over metalbond**, deriving per-VNI keys via HKDF. This library replaces that ad-hoc per-VNI key agreement with **MLS (RFC 9420)** used as a group key-agreement protocol, where **one MLS group = one VNI**.

---

## 1. Goals and non-goals

### Goals
- A Go library providing an **RFC 9420-conformant MLS engine** with **post-quantum (hybrid-KEM) ciphersuite** support, in the spirit of OpenMLS.
- Enable **metalnet/metalbond** to run MLS for per-VNI key agreement: metalbond becomes the MLS **Delivery Service (DS)**; the existing identity layer becomes the **Authentication Service (AS)**; the MLS group **exporter secret** drives per-VNI ESP SA keys.
- A **provably correct** ordering/failover story for the DS running on redundant (paired) route reflectors.
- Clean, auditable separation between the domain-agnostic crypto core and IronCore-specific integration.

### Non-goals
- We do **not** implement metalbond's wire protocol changes here (they implement our `DeliveryService` port in their repo).
- We do **not** implement the ESP/XFRM data-plane programming here (dpservice/metalnet own it); we define the key-derivation contract that feeds it.
- We do **not** mandate SPIFFE — it is one supported `CredentialValidator` adapter among others.
- No PQ *signatures* in the default suite (see §7 for rationale).

---

## 2. Role mapping (MLS ⇄ IronCore)

| MLS concept | IronCore realization |
|---|---|
| **Group** | A **VNI**. Members = nodes (dpservice/metalnet hosts) that currently have a workload on that VNI. |
| **Group exporter secret** (per epoch) | Source material for the **per-VNI ESP SA keys + SPIs** (§10.4). |
| **Delivery Service (DS)** | **metalbond** — fans out MLS handshake messages (Proposals, Commits, Welcomes, KeyPackages, GroupInfo) per VNI, and acts as the **per-VNI commit sequencer** (§5). |
| **Authentication Service (AS)** | The identity layer (SPIFFE/SPIRE or PKI). Validates leaf-credential ↔ signature-key binding. The same identity authenticates the mTLS channel to metalbond (§8). |

**What MLS buys over the current proposal:** a true shared group secret (not pairwise), **forward secrecy** across epochs, **post-compromise security** (a leaked host key heals after the next commit), and **O(log N)** membership churn instead of re-announcing ephemeral keys to everyone.

---

## 3. Architecture — two layers in one repo (Approach C)

```
github.com/trevex/mls-mlkem-go
├── mls/        # domain-agnostic RFC 9420 engine + PQC. The auditable crypto heart.
│              # Knows nothing about VNIs, ESP, metalbond.
│              # Exposes four ports (interfaces): DeliveryService, CredentialValidator,
│              # StateStore, Clock — plus the Ordering/Sequencer contract (§5).
└── ironcore/   # thin integration layer; depends on mls/.
               # VNI<->GroupID, exporter->ESP-SA derivation, fork-detect/recovery helper,
               # SPIFFE + PKI CredentialValidator adapters, membership controller glue.
```

**metalbond** implements the `DeliveryService` + `Ordering` ports in *its own* repo, so this library never depends on metalbond's protobufs.

**Why this split:** the crypto core stays reusable and auditable in isolation; the subtle, dangerous-to-get-wrong IronCore glue (fork recovery, SA derivation, GCM nonce separation) is written and tested **once** here rather than reinvented in each consumer. The single true coupling — metalbond's wire format — stays behind the `DeliveryService` port.

---

## 4. Library ports (the four interfaces + sequencer)

Sketch (illustrative Go, not final signatures):

```go
// DeliveryService fans out handshake messages for a group and lets a member
// receive the ordered stream. It is UNTRUSTED for confidentiality — it sees
// only public handshake material and GroupInfo (RFC 9750 §5).
type DeliveryService interface {
    Send(ctx, groupID GroupID, msg MLSMessage) error
    Receive(ctx, groupID GroupID) (<-chan Incoming, error) // ordered per (group,epoch)
    PublishGroupInfo(ctx, groupID GroupID, gi GroupInfo) error
    FetchGroupInfo(ctx, groupID GroupID) (GroupInfo, error) // for external-commit join/recovery
}

// Ordering is the single-linearization-point contract (§5). One accepted
// Commit per (group, epoch). Implementations: B1 fenced single-writer (default),
// B2 consensus register.
type Ordering interface {
    // AcceptCommit returns ok=true iff this is the first valid commit for
    // (group, epoch). Idempotent: re-submitting the SAME commit returns ok=true.
    AcceptCommit(ctx, groupID GroupID, epoch uint64, commitRef CommitRef) (ok bool, err error)
}

type CredentialValidator interface {
    // Validate the identity<->signature-key binding (AS role). Returns the
    // verified identity (e.g. SPIFFE ID) for the authz hook.
    Validate(cred Credential, sigPub SignaturePublicKey) (Identity, error)
}

type StateStore interface { // default: in-memory ephemeral
    Save(groupID GroupID, state EpochState) error
    Load(groupID GroupID) (EpochState, bool, error)
    Wipe(groupID GroupID) error
}

type Clock interface { Now() time.Time } // for KeyPackage lifetimes; injectable for tests
```

---

## 5. DS ordering & failover correctness — the proof obligation

This is the section that "cannot be wrong." It is grounded in RFC 9420 §§6.1/8/8.2/8.7/12.4.3/14 and RFC 9750 §5.

### 5.1 The safety invariant
> For every `(group_id, epoch)`, **at most one Commit is ever accepted by any honest member.**
Equivalently: the map `(group_id, epoch) → accepted Commit` is a **single-valued, linearizable register** (a compare-and-set, "first valid writer per epoch wins").

### 5.2 What the cryptography gives us for free
Each Commit is hash-chained to exactly one predecessor state:
`interim_transcript_hash[n-1] → confirmed_transcript_hash[n]` (§8.2) → `confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)` (§6.1) → key schedule (§8) → `epoch_authenticator = DeriveSecret(epoch_secret, "authentication")` (§8.7).

Consequences:
- Two **different** Commits at epoch *n* produce **different, cryptographically incompatible** epoch *n+1* states.
- Members **reject** any Commit whose epoch ≠ their current epoch (§14), and a Commit only verifies against the one predecessor it was built on.
- Therefore forks are **always detectable and fail-closed** — branches can never silently merge; cross-branch messages fail AEAD/MAC.

### 5.3 The trap (why "active-active + local decision" is unsafe)
Detectability ≠ prevention. The invariant is a property of a **single** register. Two route reflectors each enforcing "accept one commit per epoch *locally*" implement **two** registers. Under split-brain (RR-A accepts X, RR-B accepts Y≠X for epoch *n* before reconciling), members behind A advance via X and behind B via Y → a **real fork**. The crypto does not prevent it; it only guarantees later detection — *after* the losing branch's data is orphaned (forward secrecy makes it unrecoverable, only abandonable).

This is CAP: per-group commit ordering is a **CP** problem; a BGP-style route reflector is an **AP** design. You cannot have both. **A bare pair of reflectors has no majority** and thus cannot be both safe and available on its own.

### 5.4 Why CP is affordable here (the key insight)
**MLS epoch advancement is not on the data path.** Established ESP SAs keep encrypting tenant traffic regardless of the ordering layer's availability. If the ordering register is briefly unavailable during failover, the *only* consequence is **delayed rekey/membership-change**, never dropped packets. So we choose **strict safety over availability** for the ordering layer at near-zero operational cost (bounded rekey latency, not packet loss).

### 5.5 The mechanism — a single linearization point per group
The library models ordering as the `Ordering` port (§4) with the §5.1 contract. Two implementations:

- **B1 — Fenced single-writer per VNI (default; "primary/secondary by config").** Each VNI is *owned* by exactly one RR at a time via an **epoch-numbered lease / fencing token**. The standby takes over a VNI only after the old lease **provably expires** (lease TTL ≤ commit-acceptance timeout), so the two RRs can never both believe they own the VNI. Lease backed by a strongly-consistent store (etcd / the Kubernetes control plane). Failover = bounded *rekey-only* unavailability window. Static primary/secondary assignment is the simplest valid fencing config; dynamic leasing is an allowed refinement.
- **B2 — Consensus-backed register.** Raft/Paxos compare-and-set over `(group,epoch)→Commit`. Seamless failover, but requires an **odd quorum** (3rd witness/arbiter) — a bare pair cannot form a safe quorum. Quorum write per commit.

Both are CP and provably satisfy §5.1. The library does not pick one; metalbond selects an implementation. **Default target: B1.**

### 5.6 Defense-in-depth (in the library, independent of B1/B2)
1. **Active fork detection:** expose `epoch_authenticator` (§8.7) for out-of-band comparison, so any residual fork is *actively detected*, not merely detectable.
2. **Deterministic recovery:** a stale/losing member re-converges via **external Commit + signed GroupInfo** (§12.4.3.1–2) under a fixed **tie-break rule = lowest `Hash(Commit)`**. The external Commit *also* passes through the single linearization point (§5.5) — otherwise the recovery itself forks. This is the same machinery used for restart-rejoin (§9).

### 5.7 Proof statement
> *Agreement* = (DS register linearizability, §5.5) ∘ (RFC 9420 cryptographic binding, §5.2). Remove linearizability and you retain only *detectability* (§5.3), not agreement. With a single linearization point per group, "accept at most one valid Commit per `(group, epoch)`" is **sufficient** to guarantee no two honest members ever permanently diverge. Residual partitions are bounded by §5.6 to detect-and-recover with at most losing-branch *rekey* loss (never data-plane loss, §5.4).

---

## 6. Conformance strategy — how we prove MLS-correctness

Mirrors OpenMLS / mls-rs practice. Source: [`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations).

1. **Vendor the official KAT vectors** as `go test` cases (verify-only), in priority order:
   `tree-math` → `crypto-basics` → `deserialization` → `psk_secret` → `key-schedule` → `secret-tree` → `transcript-hashes` → `message-protection` → `tree-operations` → `tree-validation` → `treekem` → `messages` → `welcome`.
2. **Pass the `passive-client` suite** (`welcome` / `handling-commit` / `random`) — the single highest-value end-to-end signal; it transitively exercises framing, TreeKEM, parent-hash, key schedule, secret tree, transcript hash, and PSK by matching `epoch_authenticator`.
3. **Negative/validation tests** (KATs do NOT cover these; easy to miss — mirror OpenMLS's `*_validation.rs`):
   leaf-node validation (§7.3, incl. signature-key/encryption-key uniqueness + lifetime), parent-hash verification (§7.9.2), proposal-list rules + application order (§12.2–12.3), content signature + membership-tag (§6.1–6.2), confirmation-tag (§8.1).
4. **gRPC `MLSClient` interop server** (`interop/proto/mls_client.proto`) run against OpenMLS + mls-rs in the official test-runner. Makes conformance *demonstrable*. Start with `Name`, `SupportedCiphersuites`, `CreateGroup`, `CreateKeyPackage`, `JoinGroup`, `Commit`, `HandleCommit`, `Protect`/`Unprotect`, `Export`, `StateAuth`; add external-join/reinit/branch incrementally.

**Ciphersuite coverage:** the two MUST-support suites `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001) and `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` (0x0002).

**PQC conformance split (important):** the hybrid-KEM ciphersuite is non-standard and **will not interop** with OpenMLS/mls-rs. Conformance therefore splits:
- **Classical suites** → full RFC-correctness + live interop (steps 1–4).
- **Hybrid suite** → our own generated vectors + cross-check against any PQ-MLS reference if available. The engine logic is identical across suites (only the HPKE KEM/primitives swap), so classical interop gives high assurance the hybrid suite is correct.

---

## 7. Cryptography & PQC

- **HPKE (RFC 9180)** via the **Go 1.26 standard library `crypto/hpke`** — no third-party crypto dependency. The library exposes a **ciphersuite registry** so classical, hybrid-KEM, and (future) fully-hybrid suites are all definable, each carrying its HPKE `KEM`/`KDF`/`AEAD` choice.
- **Default production suite = hybrid KEM via X-Wing** (`X25519 + ML-KEM-768`, HPKE KEM id `0x647a`, exposed as `hpke.MLKEM768X25519()` in stdlib) with **classical Ed25519 signatures**. **Note:** stdlib `MLKEM768X25519()` is **X-Wing** (draft-connolly-cfrg-xwing-kem, SHA3-256 combiner), which is *not* the TLS-draft concatenation hybrid also confusingly named `X25519MLKEM768`. We deliberately use **X-Wing**: it is the hybrid construction being standardized for post-quantum HPKE, ships in the stdlib, and no MLS PQ ciphersuite is IANA-registered yet (so there is nothing to interop with that would require the TLS-concat variant).
- **Why classical signatures:** the KEM protects confidentiality against *harvest-now-decrypt-later* (the real PQ threat). Signatures only matter for **live MITM**, which a future quantum computer cannot perform *retroactively*; forging a past signature is impossible. PQ signatures (ML-DSA ~3 KB keys+sigs) would bloat every KeyPackage, leaf, and Commit — multiplying metalbond fan-out cost — for no retroactive benefit. Upgradeable later via the registry.
- **Ciphersuite IDs:** classical suites use their IANA IDs (0x0001 = DHKEM-X25519/AES-128-GCM/SHA-256/Ed25519, 0x0002 = DHKEM-P256/...); the X-Wing hybrid suite uses a **private-use range ID** until/unless an IETF PQ-MLS suite is registered, at which point the registry makes swapping trivial.
- **EncryptWithLabel/DecryptWithLabel** (RFC 9420 §5.1.3) map to HPKE base-mode `SealBase`/`OpenBase` with `info = EncryptContext` (`opaque<V>("MLS 1.0 "+Label) || opaque<V>(Context)`) and empty `aad`, returning `(kem_output, ciphertext)`. The stateful `crypto/hpke` `NewSender`/`Seal` + `NewRecipient`/`Open` API gives the required `enc`/ciphertext split. The `crypto-basics` `encrypt_with_label` vector is verified by **decrypting** (HPKE is randomized), not re-encrypting.
- **PQC standardization risk** is tracked as an open item (§12) — the X-Wing vs TLS-concat outcome and IETF PQ-MLS registration may still move; the registry isolates this.

---

## 8. Identity / Authentication Service / authorization

- **`CredentialValidator` port** with **SPIFFE-SVID** and **generic-PKI** adapters shipped. Credentials are **x509** (MLS native).
- **One identity end-to-end:** the SPIFFE ID (or PKI subject) that authenticates the **mTLS channel to metalbond** is the **same cert used as the MLS leaf credential**. This binds "who may talk to metalbond for VNI X" to "who is a member of VNI X's group."
- **Authorization boundary:** the library validates the credential binding and **exposes the verified identity to an authz hook**; the policy decision *"is this identity entitled to VNI X?"* lives in **metalnet's control plane**, not in the library.
- The DS/sequencer enforces that only authorized identities can submit handshake messages for a VNI (rate-limited, §10.5).

---

## 9. State management

- **`StateStore` port**; **default = in-memory / ephemeral** (honors the proposal's "keys never persisted" posture).
- **On restart**, a node re-joins via **external commit** using the latest published GroupInfo — the *same* machinery as DS-fork recovery (§5.6).
- Operators may plug a **sealed/persistent store** (e.g., TPM-sealed) if rejoin storms become a concern; this is optional and off by default.

---

## 10. IronCore integration design (the `ironcore/` layer)

### 10.1 VNI ↔ Group
- `GroupID = encode(VNI)` (stable, collision-free encoding).
- The `ironcore/` layer owns this mapping; the `mls/` core treats `GroupID` opaquely.

### 10.2 Trust model for the sequencer
The RR/sequencer is a **pure ordering authority**: it is **not** an MLS group member and **holds no group secrets** — it sees only ciphertext handshake messages and public GroupInfo. This preserves "DS untrusted for confidentiality" (RFC 9750 §5). Members produce Commits; the sequencer only enforces accept-once-per-epoch (§5.1).

### 10.3 Group lifecycle & membership controller flow

**Source of truth:** metalnet's control plane knows which VNIs are present on which hosts. A workload scheduled on host *H* for VNI *V* ⇒ *H* must be a member of `group(V)`; the last workload for *V* leaving *H* ⇒ *H* leaves `group(V)`.

**Roles:**
- **Member agent** — runs on each host (inside the metalbond client / dpservice agent); holds the MLS leaf + group state for each VNI the host participates in.
- **Control plane = authorized external proposer** — uses the MLS `external_senders` extension to emit **Add/Remove** proposals based on VNI placement. (External senders may *propose* but not *commit*.)
- **Designated committer member** — the active leaf with the **lowest index** batches pending proposals into a Commit each round; if it leaves/dies, the next-lowest takes over **deterministically**, and the sequencer's single-commit-per-epoch rule (§5.1) makes any handover race safe.

**Flows:**
- **Join (new host on V):** *H* generates a KeyPackage bound to its SPIFFE/PKI x509 credential and performs an **external self-commit** (RFC 9420 §12.4.3.2) against the sequencer's latest signed GroupInfo. The sequencer authorizes (entitlement check via §8 authz hook) and **orders** the commit; existing members advance an epoch; *H* derives the new exporter and installs SAs. *(External self-join removes any dependency on a designated committer for joins.)*
- **Leave (graceful):** *H* issues a self-Remove/Update Commit, or the control plane external-proposes Remove; committed by the designated member.
- **Leave (crash/unreachable):** control plane external-proposes Remove (driven by placement signal / liveness TTL); the designated committer member commits it. Post-compromise: the departed host's key is no longer valid from the new epoch.
- **Periodic rekey (PCS):** the designated committer issues an **empty Update Commit** on a timer even without membership change, to heal any silent compromise.
- **GroupInfo publication:** the sequencer publishes a fresh **signed GroupInfo** each epoch (required for external-join and recovery, §5.6).

### 10.4 ESP SA lifecycle (exporter → data plane)
- Per epoch *e*: `K_group = MLS-Exporter("ironcore-esp", context = VNI‖epoch, L)`; `SPI = f(VNI, e)` (epoch encoded in the SPI so receivers disambiguate overlapping epochs).
- **GCM nonce safety (critical):** the design uses a **group key** in a connectionless/route-based model (à la WireGuard cryptokey routing), so **every sender must occupy a disjoint nonce space** — nonce reuse under AES-GCM is catastrophic. Per-sender nonce salt = `HKDF(K_group, "esp-sender" ‖ sender_leaf_index)`; the ESP IV continues to come from the per-SA sequence number. This guarantees no two senders ever share a `(key, nonce)`.
- **Make-before-break:** install epoch *e+1* SAs **before** tearing down epoch *e*; overlap window ≥ max propagation + clock skew. Aligns with the enhancement proposal's existing "new SPI per epoch + make-before-break" mechanics — MLS simply supplies the key material via the exporter instead of HKDF-over-announced-ephemeral-keys.
- **Rotation triggers:** any epoch change (membership churn) and the periodic-rekey timer (§10.3).

### 10.5 Scale envelope
- Group size = hosts with a workload on the VNI: typically 10s–100s, occasionally low thousands.
- TreeKEM updates are **O(log N)**; but a Commit's UpdatePath fan-out is **O(N)** delivered messages per VNI. Crucially, **metalbond already fans out routes per-VNI to the same subscriber set**, so handshake fan-out is the *same order* as existing route fan-out and rekey is human-rate (seconds–minutes), not per-packet.
- **Target envelope:** design for up to ~**1–2k members per VNI** comfortably. Beyond that, revisit (e.g., sub-grouping / partitioning) — flagged as an open item (§12).
- **DoS/abuse:** the sequencer rate-limits proposals/commits per identity and accepts handshake traffic only from authorized members (§8).

---

## 11. Threat model mapping (vs. enhancement #38)

| Threat (from #38) | Mitigation here |
|---|---|
| Passive eavesdropping | AEAD ESP keyed by per-epoch MLS exporter; **PQ-safe confidentiality** via hybrid KEM. |
| Active MITM / injection / replay | MLS content auth (§6.1) + ESP anti-replay; **mTLS + leaf-credential binding** (§8). |
| Malicious co-tenant | **Per-VNI group isolation** — distinct group, distinct exporter, distinct SAs. |
| Compromised host / rogue control plane | **PCS** via periodic + on-churn Commits (§10.3); DS is untrusted for confidentiality (§10.2); **provable ordering** (§5) prevents a rogue/partitioned DS from forking members undetectably. |

---

## 12. Open questions / future work
1. **Dynamic vs static VNI ownership** for B1 leasing — start static (primary/secondary by config), evaluate dynamic leasing.
2. **B2 witness topology** — if/when consensus ordering is wanted, where the 3rd arbiter lives.
3. **Very large VNIs** (>~2k members) — sub-grouping / partition strategy.
4. **PQC standardization** — track X-Wing vs X25519MLKEM768 and IETF PQ-MLS; migrate the registry default when settled.
5. **KeyPackage distribution & lifetime policy** — freshness/rotation of joiner KeyPackages.
6. **Persistent sealed StateStore** — whether/when to enable for rejoin-storm mitigation.
7. **Sealed-vs-ephemeral trade-off** interaction with crash-leave detection latency.

---

## 13. References
- **RFC 9420** — The Messaging Layer Security (MLS) Protocol. §§6.1, 7.3, 7.8, 7.9/7.9.2, 8, 8.1, 8.2, 8.7, 12.2–12.4, 12.4.3.1–2, 14, 17.1.
- **RFC 9750** — The MLS Architecture. §5, §5.2, §5.2.1–5.2.3, §5.3.
- **RFC 9180** — HPKE.
- **mlswg/mls-implementations** — test vectors, `test-vectors.md`, `interop/proto/mls_client.proto`, Go reference client.
- **OpenMLS**, **mls-rs (AWS)** — reference implementations / KAT structure.
- Alwen, Jost, Mularczyk — *On the Insider Security of MLS*, CRYPTO 2022 (eprint 2020/1327).
- Wallez et al. — *TreeSync*, USENIX Security 2023 (eprint 2022/1732).
- Brzuska, Cornelissen, Kohbrok — *Cryptographic Security of the MLS RFC, Draft 11*, IEEE S&P 2022 (eprint 2021/137).
- Alwen, Coretti, Dodis, Tselekounis — CRYPTO 2020 (eprint 2019/1189).
- IronCore enhancement #38 — underlay encryption proposal.
