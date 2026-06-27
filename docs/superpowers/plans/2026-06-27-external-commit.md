# External Commits + Fork Recovery — joining without a Welcome, deterministic re-convergence (Plan 12 of 12) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. **Depends on Plan 9** (`2026-06-27-active-operations.md` — the active `mls/group` engine: `NewGroup`, `Commit`, `ProcessCommit`, `JoinFromWelcome`, `GroupInfo`, `buildWelcome`, `applyProposals`, `installJoinerPriv`, `commonAncestor`), **Plan 10** (`2026-06-27-ironcore-integration.md` — `ironcore/` layer: `VNIGroup`, `GroupID`, `DeriveSAKeys`, the `buildVNIGroup`/`addMember` test helpers) and **Plan 11** (`2026-06-27-sequencer.md` — `mls/group/ports.go` `Ordering`/`CommitRef`, `ironcore/sequencer.MemorySequencer`, `EpochAuthenticatorRegistry`, `CanonicalCommit`). All three are merged; all 15 MLS KATs pass; multi-member convergence + split-brain/fork-detection proofs are green.
>
> **There is NO standalone official MLS KAT for external commits.** The vendored `mls/testdata/passive-client-random.json` is the closest official vector, but it does **not** exercise external-commit *processing* for the registered suite (the current `ProcessCommit` assumes a member sender, and the KAT passes today — i.e. its registered-suite cases contain no `new_member_commit` epoch). The gates of this plan are therefore **SELF-ROUND-TRIP convergence** property tests, plus a **cross-checked KAT** for the one genuinely new cryptographic primitive (the external-init secret), gated against the **RFC 9180 Appendix A.1 / A.3 DHKEM test vectors**.
>
> **Everything below was EMPIRICALLY VALIDATED during planning** with throwaway tests (now deleted; working tree left clean — only this plan file is new). Validation log (real runs, Go 1.26.4):
> - **DHKEM external-init secret pinned** (suite `0x0001` X25519 + `0x0002` P-256): a hand-rolled stdlib DHKEM Encap/Decap (`crypto/ecdh` + `crypto/hkdf`) reproduced the **RFC 9180 §A.1.1** (X25519) vector exactly — `enc = 37fda356…1bf4431`, `shared_secret = fe0e18c9…7d2ea1fc` — **and the §A.3.1 (P-256)** vector exactly — `enc = 04a92719…57222d18c4`, `shared_secret = c0d26aea…eabb8cb8` — and `Decap(enc, skR)` returned the same `shared_secret` in both cases. **The external init secret is the bare KEM shared secret (Nsecret = KDF.Nh = 32 bytes); there is NO extra "MLS 1.0 external init secret" KDF label** (an early web summary claimed one — it is wrong). The §A.3.1 P-256 vector below is therefore **VERIFIED-CORRECT — keep it** (do not drop the P-256 KAT case).
> - **X-Wing (`0xF001`) external-init secret pinned (NEW)**: a hand-rolled raw X-Wing KEM (`crypto/mlkem` + `crypto/ecdh` + `crypto/sha3`, draft-connolly-cfrg-xwing-kem combiner `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ \.//^\)`) **round-tripped over 100 random keys** — `Encap(external_pub)` then `Decap(external_priv, kem_output)` returned the identical 32-byte init_secret every time. **Option A confirmed by serialization probe** (see N1): stdlib X-Wing `PublicKey.Bytes()` is **1216 bytes = pk_M(1184) ‖ pk_X(32)**, and `PrivateKey.Bytes()` is a **32-byte X-Wing seed**; expanding that seed with `SHA3-256-SHAKE256(seed, 96)` → `dk_M = mlkem.NewDecapsulationKey768(exp[0:64])`, `sk_X = X25519.NewPrivateKey(exp[64:96])` reproduced the stdlib pub's pk_M and pk_X **byte-for-byte**. So the X-Wing external keypair stays **stdlib-derived** (`DeriveKeyPair(external_secret)`); only the raw Encap/Decap are hand-rolled.
> - **Fresh external join converges under 0xF001**: built a real 2-member group {alice, bob} at epoch 1 (EA `5d5a18a0…23719b4f`); a third party **carol** (not previously a member) external-committed using alice's published tree+`external_pub`; alice, bob, and carol all derived the **byte-identical** `epoch_authenticator` `3086888c…1835f1fd` at epoch 2 (carol added at leaf 2). (Classical `0x0001` likewise converged: `169d15bc…20ba25ba`.)
> - **Fork recovery converges under 0xF001 (anti-double-join)**: {alice, bob} at epoch 1 forked (alice and bob each empty-committed → divergent epoch-2 authenticators `ed8036fe…` vs `aa18df66…`); bob then **external-committed back onto alice's canonical branch**, including a **Remove of its own stale leaf 1** (anti-double-join, same Ed25519 identity / fresh HPKE keys), re-joining at leaf 1; alice and bob re-converged on `fc5fcd08…629dee07` at epoch 3, tree parent-hashes valid.

**Goal:** Let a non-member **join an existing group without a Welcome** (RFC 9420 §12.4.3.2 External Commits), and use the same machinery to let a **stale/losing member deterministically re-converge** onto the canonical branch after a fork (design spec §5.6). Deliverables: **(0)** a new `mls/cipher` primitive pair — `ExternalInitEncap`/`ExternalInitDecap` — implementing the RFC 9420 §8.3 external-init secret (= bare KEM shared secret) that **dispatches on the suite's KEM**: stdlib **DHKEM** (`crypto/ecdh`+`crypto/hkdf`) for `0x0001`/`0x0002`, KAT-gated against RFC 9180; and a hand-rolled raw **X-Wing** KEM (`crypto/mlkem`+`crypto/ecdh`+`crypto/sha3`) for the PQ suite `0xF001` (the suite IronCore actually deploys), round-trip- and convergence-gated; **(1)** GroupInfo carrying the `external_pub` extension + a `Group.PublishGroupInfo()` builder so members can publish a signed, joinable GroupInfo for the current epoch; **(2)** `group.ExternalCommit(...)` — a non-member builds the special Commit (exactly one `ExternalInit`, mandatory `UpdatePath`, optional anti-double-join `Remove`) from a published GroupInfo, advancing its own key schedule with the external-init secret and emerging as a member at epoch n+1; **(3)** `Group.ProcessExternalCommit(...)` (+ `ProcessCommit` dispatch on `new_member_commit`) so existing members apply the external commit and converge; **(4)** `ironcore.RecoverViaExternalCommit(...)` — the §5.6 fork-recovery flow that picks the canonical branch by the Plan-11 tie-break, builds the recovery external commit, and **routes it through the single `Ordering` linearization point** so the recovery itself cannot fork. **The gates are the self-round-trip convergence property tests** (fresh join → 3 converge; fork recovery → re-converge; anti-double-join keeps the tree valid) plus the DHKEM KAT.

**Architecture (design spec §3/§5.6/§10):** External-commit *generation and processing* are **core MLS protocol** and live in `mls/group` (next to `commit_gen.go`/`join.go`/`process.go`), reusing the proven engine internals verbatim — `tree.GenerateUpdatePath`/`ProcessUpdatePath`/`AddLeaf`/`Merge`, `applyProposals`, `installJoinerPriv`, `commonAncestor`, the two-GroupContext rule, and `keyschedule.DeriveEpochSecrets`. The **only new cryptography** is the external-init secret (DHKEM in `mls/cipher/extinit.go`; the raw X-Wing KEM in `mls/cipher/xwing.go`), which belongs in `mls/cipher` beside the other KEM/KDF primitives (§5.1.3 `EncryptWithLabel` lives there already). **We are NOT reimplementing ML-KEM** — `xwing.go` only *composes* stdlib `crypto/mlkem` (ML-KEM-768 Encapsulate/Decapsulate) + `crypto/ecdh` (X25519) + `crypto/sha3` (the X-Wing combiner & seed expansion) per draft-connolly-cfrg-xwing-kem. The **fork-recovery orchestration** is *deployment policy* (pick canonical branch, route through the sequencer) and lives in `ironcore/recovery.go` (design spec §3 places the "fork-detect/recovery helper" in `ironcore/`; §5.6 requires the recovery external Commit to pass through the §5.5 single linearization point). Layering is preserved: `ironcore` imports `mls/group`+`ironcore/sequencer`; `mls/group` imports `mls/cipher`/`mls/keyschedule`/`mls/tree`/`mls/framing`; no cycles, and the sequencer still holds **no group secrets** (it sees only the opaque `CommitRef` of the recovery commit).

**Tech Stack:** Go 1.26 standard library only (hard constraint). New code uses `crypto/ecdh`, `crypto/hkdf` (the external-init DHKEM), `crypto/mlkem` (ML-KEM-768 Encapsulate/Decapsulate for X-Wing), `crypto/sha3` (the X-Wing combiner `SHA3-256` + seed expansion `SHAKE256`), `crypto/rand`, `bytes`, `encoding/binary`, `errors`, `fmt` — all stdlib — plus the existing `mls/*` packages. No new third-party dependency. `crypto/hpke` (Go 1.26) is already the suite's HPKE backend but **exposes only `Seal`/`Open` and an opaque `KEM` whose `Encap`/`Decap` are unexported** (verified via `go doc crypto/hpke`: `KEM` has `ID()`, `GenerateKey`, `NewPublicKey`, `NewPrivateKey`, `DeriveKeyPair` only — and for `MLKEM768X25519()` no raw X-Wing Encap/Decap) — hence the external-init secret (a **bare KEM shared secret**, not an HPKE AEAD context) must be derived by hand: RFC 9180 §4.1 DHKEM for the classical suites, and a composed raw X-Wing KEM for `0xF001`. Both are exactly what Task 0 does and gates. Verified stdlib APIs: `crypto/mlkem` `NewDecapsulationKey768(seed []byte)` (`SeedSize=64`, `CiphertextSize768=1088`, `EncapsulationKeySize768=1184`, `SharedKeySize=32`), `EncapsulationKey768.Encapsulate() (sharedKey, ciphertext)`, `DecapsulationKey768.Decapsulate(ct)`, `NewEncapsulationKey768(ek)`; `crypto/sha3` `Sum256` / `SumSHAKE256(data, length)`; `crypto/ecdh` `X25519()` with `GenerateKey`/`NewPrivateKey`/`NewPublicKey`/`ECDH`/`PublicKey().Bytes()`.

**Spec reference:**
- **RFC 9420 §8.3 (External Initialization)** — the new epoch's `init_secret` for an external commit is injected via an `ExternalInit` proposal: the group derives `external_priv, external_pub = KEM.DeriveKeyPair(external_secret)` from the current epoch's `external_secret`; the joiner computes `kem_output, init_secret = KEM.Encap(external_pub)` and ships `kem_output` in the `ExternalInit` proposal; every existing member computes `init_secret = KEM.Decap(kem_output, external_priv)`. This `init_secret` **replaces** the previous epoch's `init_secret` as the salt fed to `joiner_secret = ExpandWithLabel(Extract(init_secret, commit_secret), "joiner", GroupContext, Nh)`. (`KEM.Encap`/`KEM.Decap` are the suite's KEM — RFC 9180 §4 DHKEM for `0x0001`/`0x0002`, **X-Wing** (draft-connolly-cfrg-xwing-kem) for `0xF001`; in all cases the shared secret is `Nsecret = 32` bytes and is used **verbatim** — no MLS label.)
- **RFC 9420 §12.4.3.2 (Joining via External Commits)** — an external Commit is sent as a `PublicMessage` with sender type **`new_member_commit`**; it **MUST** contain **exactly one `ExternalInit`** proposal; it **MUST** include a **`path`** (UpdatePath); aside from the `ExternalInit`, the only proposals it may carry are **`Remove`** (to remove a *prior appearance of the joiner* — anti-double-join — the removed leaf's identity must match the joiner) and **`PreSharedKey`**, and (per §12.4.3) `GroupContextExtensions` may also appear; it **MUST NOT** contain any proposal **by reference** (a non-member cannot validate group-internal proposals); its signature is verified with the **signature key in the LeafNode of the Commit's `path`** (§6.1, since the committer is not yet in the tree).
- **RFC 9420 §12.4.3.1 (GroupInfo)** + **§17.3** — the joiner gets the group state from a signed `GroupInfo`; the `ratchet_tree` extension (`0x0002`) carries the tree; the **`external_pub` extension (`0x0004`)** carries `external_pub` for the current epoch.
- **Design spec §5.6** (`docs/superpowers/specs/2026-06-26-mls-mlkem-go-design.md`): *"a stale/losing member re-converges via external Commit + signed GroupInfo (§12.4.3.1–2) under a fixed tie-break rule = lowest `Hash(Commit)`. The external Commit also passes through the single linearization point (§5.5) — otherwise the recovery itself forks."* Also §5.2 (transcript chaining ⇒ forks are detectable via distinct `epoch_authenticator`s), §5.5 (single linearization point), §10.2 (sequencer holds no secrets).

> **Go invocation convention:** Go is **not** on `PATH`. Every Go command runs through the nix devshell from the **repo root**, e.g. `nix develop -c go test github.com/trevex/mls-mlkem-go/mls/group`. Expect a harmless `Entered Go dev shell: …` banner (and possibly `warning: Git tree … is dirty`) on stderr. `cd` into a subdir is unnecessary and breaks relative `./...` after the devshell `cd` — always use the full module path. Format/vet/test gate: `nix develop -c sh -c 'gofmt -l mls ironcore && go vet ./... && go test ./...'`.

---

## Design notes (read before implementing)

Every claim below was reproduced during planning with throwaway tests (see header validation log). The novel/subtle parts are **N1 (external-init secret)** and **N4 (leaf placement symmetry)** — get those exactly right; everything else reuses the proven engine.

### N0. Shapes the engine already gives us (do not re-derive)

- `keyschedule.ExternalPub(suite, externalSecret) (priv, pub, err)` already exists (`= suite.DeriveKeyPair(externalSecret)`) — this is the §8.3 `KEM.DeriveKeyPair(external_secret)`. `EpochSecrets.ExternalSecret` is the per-epoch `external_secret` (label `"external"`). All members of an epoch share it ⇒ all derive the same `external_pub`/`external_priv`.
- `keyschedule.DeriveEpochSecrets(suite, initSecret, commitSecret, pskSecret, groupContext)` runs the full §8 schedule from an `init_secret` salt. **For an external commit we call it with `initSecret = <external-init secret>`** instead of a prior epoch's `init_secret`. Nothing else in the schedule changes.
- `tree.GenerateUpdatePath(senderLeaf, leafSecret, signer, groupID, newlyAdded, mkGC)` / `tree.ProcessUpdatePath(senderLeaf, up, priv, gcBytes, newlyAdded)` / `tree.Merge(senderLeaf, up)` / `tree.AddLeaf(ln)` are exactly the primitives a normal `Commit`/`ProcessCommit` uses; an external commit is a normal commit **authored by a freshly-added leaf** with the `init_secret` swapped.
- The **two-GroupContext rule (N0 of Plan 9)** is unchanged: `encGC` (HPKE context for the UpdatePath) uses the **OLD** `confirmed_transcript_hash` (the published epoch n's), `newGC` (key schedule + confirmation_tag) uses the **NEW** one; both are at epoch n+1 with the post-path tree hash and the provisional extensions.
- Framing already supports `SenderTypeNewMemberCommit = 4` (`mls/framing/framing.go`), and `PublicMessage.marshal`/`ProtectPublic`/`UnprotectPublic` already **omit the membership_tag for non-member senders** (`if fc.Sender.Type == SenderTypeMember` guards). `framing.SignCommit(suite, signer, &gc, fc)` returns the `confirmedInput` (`wire_format ‖ FramedContent ‖ signature<V>`) byte-identical to what `keyschedule.SplitAuthenticatedContent` recovers on the receiver — so the transcript binds across joiner and members.

### N1. The external-init secret = bare KEM shared secret (the one new primitive; DHKEM + X-Wing)

RFC 9420 §8.3 uses the suite's KEM directly: `kem_output, init_secret = KEM.Encap(external_pub)` (joiner) and `init_secret = KEM.Decap(kem_output, external_priv)` (members). `init_secret` is the KEM's `shared_secret` **used verbatim** — `Nsecret = 32` for all registered suites, **no MLS KDF label**. `ExternalInitEncap`/`ExternalInitDecap` **dispatch on the suite's KEM**: DHKEM for `0x0001`/`0x0002` (N1a), raw X-Wing for `0xF001` (N1b). Go's `crypto/hpke` does not expose the raw KEM (its `Encap`/`Decap` are unexported), so both are hand-rolled.

#### N1a. DHKEM (`0x0001` X25519 / `0x0002` P-256) — KAT-pinned

We implement DHKEM (RFC 9180 §4.1) on stdlib `crypto/ecdh`+`crypto/hkdf`:

```
DHKEM.Encap(pkR):                      DHKEM.Decap(enc, skR):
  skE, pkE = GenerateKeyPair()           pkE         = Deserialize(enc)
  dh  = DH(skE, pkR)                      dh          = DH(skR, pkE)
  enc = Serialize(pkE)                    kem_context = enc ‖ Serialize(pk(skR))
  kem_context = enc ‖ Serialize(pkR)      return ExtractAndExpand(dh, kem_context)
  return (enc, ExtractAndExpand(dh, kem_context))

ExtractAndExpand(dh, kem_context):
  eae_prk       = LabeledExtract("",  suite_id, "eae_prk",      dh)
  shared_secret = LabeledExpand(eae_prk, suite_id, "shared_secret", kem_context, Nsecret)

LabeledExtract(salt, suite_id, label, ikm) = HKDF-Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm)
LabeledExpand(prk, suite_id, label, info, L) = HKDF-Expand(prk, I2OSP(L,2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, L)
suite_id = "KEM" ‖ I2OSP(kem_id, 2)     // kem_id from suite.kem.ID(): X25519=0x0020, P256=0x0010
```

**Validated against RFC 9180 §A.1.1** (X25519): with the vector's `skE`, `pkR` this produced `enc = 37fda356…1bf4431` and `shared_secret = fe0e18c9…7d2ea1fc` exactly, and `Decap` round-tripped. **Also validated against §A.3.1** (P-256): `enc = 04a92719…57222d18c4`, `shared_secret = c0d26aea…eabb8cb8` — **the §A.3.1 vector bytes in `extinit_test.go` below are CORRECT; keep the P-256 KAT case.** `DH(...)` is `ecdh` shared-secret bytes (X25519: 32-byte u-coordinate; P256: 32-byte X-coordinate per SEC1) and `Serialize(pk)` is `ecdh.PublicKey.Bytes()` (X25519: 32 bytes; P256: 65-byte uncompressed point) — both already the suite's `HPKEPublicKey` encoding.

#### N1b. X-Wing (`0xF001` = X25519 + ML-KEM-768) — composed raw KEM; round-trip- + convergence-gated

The PQ suite's KEM is **X-Wing** (draft-connolly-cfrg-xwing-kem, HPKE KEM id `0x647a`). `crypto/hpke.MLKEM768X25519()` does not expose raw Encap/Decap, so we compose one from stdlib `crypto/mlkem` + `crypto/ecdh` + `crypto/sha3` (**NOT** reimplementing ML-KEM). The combiner (validated):

```
XWingLabel = 0x5c2e2f2f5e5c                       // the 6 ASCII bytes  \.//^\
ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)

Encap(pk = pk_M(1184) ‖ pk_X(32)):                Decap(sk_seed(32), ct = ct_M(1088) ‖ ct_X(32)):
  (ss_M, ct_M) = MLKEM768.Encaps(pk_M)              exp   = SHAKE256(sk_seed, 96)          // X-Wing expandDecapsulationKey
  ek           = X25519.GenerateKey()               dk_M  = mlkem.NewDecapsulationKey768(exp[0:64])
  ct_X         = X25519base(ek) = ek.Pub.Bytes()    sk_X  = X25519.NewPrivateKey(exp[64:96])
  ss_X         = X25519(ek, pk_X) = ek.ECDH(pk_X)    pk_X  = sk_X.Pub.Bytes()
  ss           = SHA3-256(ss_M‖ss_X‖ct_X‖pk_X‖L)    ss_M  = dk_M.Decapsulate(ct_M)
  return (ct_M ‖ ct_X, ss)                           ss_X  = sk_X.ECDH(X25519.NewPublicKey(ct_X))
                                                     return SHA3-256(ss_M‖ss_X‖ct_X‖pk_X‖L)
```

**THE A-vs-B DECISION → Option A (stdlib-derived external keypair).** Investigation (empirical serialization probe): stdlib X-Wing `PublicKey.Bytes()` = **1216 bytes = pk_M(1184) ‖ pk_X(32)** (directly splittable for Encap), and `PrivateKey.Bytes()` = a **32-byte X-Wing seed**. That seed is *not* directly an (dk_M, sk_X) pair, but it is **deterministically expandable**: `SHAKE256(seed, 96)` → `(d‖z)=exp[0:64]` feeds `mlkem.NewDecapsulationKey768` and `exp[64:96]` is `sk_X` — and this reconstruction reproduced the stdlib pub's pk_M **and** pk_X **byte-for-byte** (probe over fresh `DeriveKeyPair`/`GenerateKey` keys). So **the X-Wing external keypair stays exactly stdlib-derived** (`suite.DeriveKeyPair(external_secret)`, unchanged) — Decap simply expands the same 32-byte seed it is handed. This preserves full consistency with `keyschedule.ExternalPub` and means **no suite needs a divergent `external_pub` derivation** (Option B's self-keygen fallback is unnecessary — the stdlib X-Wing seed *is* parseable). **CRITICAL: DHKEM external_pub (`0x0001`/`0x0002`) is unchanged — the `key-schedule.json` KAT validates it.** The X-Wing `external_pub` is *not* exercised by any KAT (key-schedule.json only has suites 1&2), but Option A introduces **no divergence** anyway: all members run the same stdlib `DeriveKeyPair(external_secret)` and the same SHAKE-expansion in Decap, so they converge by construction.

**Validated:** raw X-Wing Encap→Decap round-tripped the identical 32-byte init_secret over 100 random stdlib-derived keypairs; and a full `0xF001` external join (3 members) + `0xF001` fork-recovery (anti-double-join) converged on byte-identical `epoch_authenticator`s (header log). No draft KAT vector was transcribed (the draft's deterministic encap needs ML-KEM encaps coins that `crypto/mlkem` doesn't expose); the round-trip + the byte-exact stdlib pk_M/pk_X reconstruction + the end-to-end convergence gate are the proof. `ExternalInitEncap`/`Decap` still return a typed `errExternalInitUnsupported` for any future KEM that is neither a DHKEM curve nor X-Wing.

### N2. GroupInfo must carry `external_pub`; members must be able to publish one

`buildWelcome` already builds a signed GroupInfo with the `ratchet_tree` (`0x0002`) extension. An external joiner additionally needs **`external_pub` (`0x0004`)** = `keyschedule.ExternalPub(suite, epoch.ExternalSecret).pub`. We add (a) `ExtensionTypeExternalPub = 0x0004` + an `ExternalPubExtension()` accessor on `GroupInfo`, and (b) a `(*Group).PublishGroupInfo()` method that builds a **signed GroupInfo for the current epoch** with both extensions (the committer = `g.ownLeaf`, `confirmation_tag` recomputed from `g.epoch.ConfirmationKey` + `g.groupContext.ConfirmedTranscriptHash`). This is the object a member hands to a would-be joiner (and the recovery flow fetches from the canonical member).

### N3. ExternalCommit construction (joiner side) — exact sequence

Given a parsed, signature-verified `GroupInfo gi` (epoch n):
1. `extPub = gi.ExternalPubExtension()`; `kemOutput, initSecret = suite.ExternalInitEncap(extPub)`.
2. `wt = tree.ParseRatchetTree(suite, gi.RatchetTreeExtension())`; verify parent hashes + leaf signatures + `RootTreeHash == gi.GroupContext.TreeHash` (same checks as `JoinFromWelcome` N1 steps 6–7).
3. **Anti-double-join (N5):** if the joiner's signature key already appears at some leaf `L` in `wt`, append a `Remove{Removed: L}` proposal and `wt.RemoveLeaf(L)`.
4. Build the joiner's `LeafNode` (fresh HPKE leaf key + fresh init key, `leaf_node_source = key_package`, signed under `gi.GroupContext.GroupID`) exactly as `NewKeyPackage` does; `liC, _ = wt.AddLeaf(joinerLeaf)` — **leftmost-blank-or-append**, deterministic.
5. Prepend the **`ExternalInit{KemOutput: kemOutput}`** proposal (exactly one, first). Final by-value proposal list = `[ExternalInit, (Remove?)]`. No by-reference proposals; no Add/Update.
6. `leafSecret = random(Nh)`; `up, commitSecret, pathByNode = wt.GenerateUpdatePath(liC, leafSecret, signer, groupID, nil, mkGC)` where `mkGC(treeHash)` = encGC bytes `{epoch n+1, treeHash, confirmed = gi.GroupContext.ConfirmedTranscriptHash (OLD), ext = gi.GroupContext.Extensions}`.
7. `cm = Commit{Proposals: [...], Path: up}`; `fc = FramedContent{GroupID, Epoch: n, Sender{Type: new_member_commit}, ContentType: commit, Content: cm.marshal()}`.
8. `confirmedInput, sig = framing.SignCommit(suite, signer, &gi.GroupContext, fc)` (signs `FramedContentTBS` under GroupContext n).
9. `interimN = InterimTranscriptHash(gi.GroupContext.ConfirmedTranscriptHash, gi.ConfirmationTag)`; `confirmed = ConfirmedTranscriptHash(interimN, confirmedInput)`.
10. `newGC = {epoch n+1, post-path treeHash, confirmed (NEW), ext}`; `es = DeriveEpochSecrets(suite, initSecret, commitSecret, pskSecret, newGC.marshal())` — **`initSecret` is the external-init secret from step 1.**
11. `confTag = ConfirmationTag(suite, es.ConfirmationKey, confirmed)`; assemble the `PublicMessage` **without** a membership_tag (`PublicMessage{Content: fc, Auth: {Signature: sig, ConfirmationTag: confTag}}`), wrap in `MLSMessage{WireFormatPublicMessage}`.
12. Build the joiner's own private TreeKEM state from `leafSecret` + `pathByNode` (same as `Commit` step 6: `DeriveSecret(leafSecret,"node")` → leaf key, then `AddPathSecret` for each ancestor) and the `interim = InterimTranscriptHash(confirmed, confTag)`, `SecretTree` from `es.EncryptionSecret`. Return the new `*Group` at epoch n+1 + the commit `MLSMessage` bytes.

### N4. ExternalCommit processing (existing-member side) — leaf placement symmetry (subtle)

The committer is **not** in the receiver's tree, and `new_member_commit` carries **no leaf index**. Both sides must independently agree on the joiner's leaf index `liC`. **They do, because `AddLeaf` is deterministic (leftmost blank slot, else append).** Receiver sequence (extends/parallels `ProcessCommit`):
1. Parse the commit `PublicMessage`; require `Sender.Type == new_member_commit`, `ContentType == commit`; parse `cm`; require **exactly one `ExternalInit`**, a non-nil `cm.Path`, **no by-reference proposals**, and only `{ExternalInit, Remove, PreSharedKey, GroupContextExtensions}` by value (reject Add/Update). The joiner's signature key = `cm.Path.LeafNode.SignatureKey`; verify the commit via `framing.UnprotectPublic(suite, thatKey, &g.groupContext, nil, *m.Public)` (no membership key — non-member sender).
2. `initSecret = suite.ExternalInitDecap(externalPriv, kemOutput)` where `externalPriv, _ = keyschedule.ExternalPub(suite, g.epoch.ExternalSecret)` and `kemOutput` = the `ExternalInit` proposal's payload.
3. `wt = g.tree.Clone()`; apply the `Remove` (if any) with `wt.RemoveLeaf`; then `liC, _ = wt.AddLeaf(cm.Path.LeafNode)` — **same leftmost-blank-or-append index as the joiner chose** (after the same Remove). `AddLeaf` appends/​fills without renumbering existing nodes, so `g.priv` (the receiver's own leaf+ancestor keys) stays valid.
4. Post-path tree hash from a `Clone()+Merge(liC, cm.Path)`; `encGC` with **OLD** confirmed; `_, commitSecret, _ = wt.ProcessUpdatePath(liC, cm.Path, g.priv, encGC, nil)` (the receiver decrypts the path secret at its copath slot — `liC`'s own leaf content is irrelevant to the copath resolutions, which is *why* step 3's placement is symmetric); `wt.Merge(liC, cm.Path)`.
5. `confirmed = ConfirmedTranscriptHash(g.interim, confirmedInput)` (from `SplitAuthenticatedContent`); `newGC` with NEW confirmed; `es = DeriveEpochSecrets(suite, initSecret, commitSecret, pskSecret, newGC.marshal())`.
6. **Verify `confTag`** against `cm`'s `confirmation_tag` (reject on mismatch — integrity backstop); chain `interim`; rebuild `g.priv` from the decrypted path secret via `installJoinerPriv(suite, …, decryptedPS, g.ownLeaf, liC, wt.LeafCount())`; rebuild `SecretTree`; commit all state atomically. **`g.ownLeaf` is unchanged** for an existing member (it keeps its own leaf; only the joiner's leaf is added).

**Validated:** alice+bob both ran this and matched carol's `epoch_authenticator` byte-for-byte.

### N5. Anti-double-join (§12.4.3.2) — joiner already present (the fork-recovery case)

When the joiner is **already** a member (e.g. a stale/losing-branch member re-joining the canonical branch, which shares pre-fork history and therefore the joiner's old leaf), it **MUST** `Remove` its prior leaf in the same external commit, and re-add itself via the UpdatePath. Construction: the joiner finds its old leaf `L` (by signature key) in the parsed canonical tree, emits `Remove{L}`, calls `wt.RemoveLeaf(L)`, then `wt.AddLeaf(newLeaf)` — which **fills the now-blank slot `L`** (leftmost blank), so the joiner re-enters at the same index with **fresh keys**. Receivers replicate (`RemoveLeaf(L)` then `AddLeaf(path.LeafNode)` → same `L`). The removed leaf's identity matches the joiner (its own old credential), satisfying the §12.4.3.2 identity check. **Validated:** bob removed its stale leaf 1 and re-joined alice's canonical branch at leaf 1; both converged.

### N6. Fork recovery flow (design spec §5.6) — route through the single linearization point

`ironcore.RecoverViaExternalCommit` is the orchestration: given the recovering member's `*VNIGroup`, the set of competing branch `CommitRef`s observed for the contested epoch, a fetched **signed GroupInfo of each candidate branch**, and the `Ordering` register:
1. `canonical = sequencer.CanonicalCommit(suite, candidates)` (Plan 11 tie-break = lowest `Hash(ref)`) — every losing member picks the **same** branch.
2. Fetch/select the canonical branch's signed GroupInfo (epoch n on that branch); verify its signature.
3. `newGroup, commitMsg = group.ExternalCommit(suite, canonicalGI, cred, signer, lifetime)` (with anti-double-join Remove, N5).
4. `ref = CommitRef(suite.Hash(commitMsg))`; `ok = ordering.AcceptCommit(ctx, gid, n, ref)`. **Only if `ok`** does the member adopt `newGroup` and broadcast `commitMsg`; if `!ok`, another recovery commit already won this `(group, epoch)` — re-fetch the now-decided GroupInfo and retry against the **next** epoch (the register guarantees a single winner, so recoveries serialize and cannot themselves fork — §5.5/§5.6). Replace the `*VNIGroup`'s `g` with `newGroup` on success.

This reuses Plan 11's `MemorySequencer`/`CanonicalCommit`/`EpochAuthenticatorRegistry` untouched; `ironcore/recovery.go` adds only the glue.

### N7. No official KAT — gates are self-round-trip (+ DHKEM KAT)

Confirmed: `mls/testdata/` has no external-commit vector; `passive-client-random.json` is vendored and green but its registered-suite cases drive only member commits through `ProcessCommit`. So: **(a)** the **DHKEM** external-init secret is KAT-gated against RFC 9180 §A.1.1 + §A.3.1 (the only place a wrong byte would silently break interop), and the **X-Wing** external-init secret is gated by encap/decap round-trip + byte-exact stdlib pk_M/pk_X reconstruction (no public X-Wing KEM KAT is transcribable since `crypto/mlkem` doesn't expose encaps coins — and X-Wing `external_pub` is in no MLS KAT anyway); **(b)** the end-to-end behavior is gated by **self-round-trip convergence under `0xF001` (primary) + `0x0001`** (byte-equal `epoch_authenticator` **and** `Exporter` across all members — reuse `assertConverged` from `active_test.go`). Optionally extend the passive-random driver to *assert it correctly rejects/handles* any `new_member_commit` epoch, but do not depend on such an epoch existing. Every KAT-style test keeps the project convention: skip unregistered suites and `t.Fatal` if **zero** cases executed.

---

## File Structure

| File | New/Edit | Purpose |
|---|---|---|
| `mls/cipher/suite.go` | Edit | Add `curve ecdh.Curve` field to `Suite`; set `curve: ecdh.X25519()` / `ecdh.P256()` in the two DHKEM registry entries (X-Wing entry leaves it nil). |
| `mls/cipher/suite_pq.go` | Edit (none / comment only) | X-Wing registry entry keeps `curve` nil; `ExternalInitEncap`/`Decap` recognize it by `kem.ID() == 0x647a`. |
| `mls/cipher/extinit.go` | **New** | `ExternalInitEncap`/`ExternalInitDecap` (KEM dispatch) + `DeriveExternalInitKeyPair` + RFC 9180 §4.1 DHKEM (`labeledExtract`/`labeledExpand`/`extractAndExpand`), `errExternalInitUnsupported`. |
| `mls/cipher/xwing.go` | **New** | Raw X-Wing KEM `xwingEncap`/`xwingDecap` + `xwingCombiner` (SHA3-256) + `xwingExpandSeed` (SHAKE256), composing `crypto/mlkem`+`crypto/ecdh`+`crypto/sha3`. Constants `xwingKEMID=0x647a`, `xWingLabel`, sizes from `crypto/mlkem`. |
| `mls/cipher/extinit_test.go` | **New** | DHKEM KAT gate (RFC 9180 §A.1.1 X25519 + §A.3.1 P256 vectors — both verified-correct) + encap/decap round-trip across **all** registered suites incl. `0xF001`; zero-executed guard. |
| `mls/cipher/xwing_test.go` | **New** | X-Wing-specific gate: stdlib pub splits 1184‖32; SHAKE256(seed,96) reconstruction reproduces stdlib pk_M/pk_X; `xwingEncap`→`xwingDecap` round-trip over many random keys; combiner label `\.//^\` pinned. |
| `mls/group/groupinfo.go` | Edit | `ExtensionTypeExternalPub = 0x0004`; `(GroupInfo).ExternalPubExtension()` accessor. |
| `mls/group/external_join.go` | **New** | `(*Group).PublishGroupInfo()` (signed GroupInfo w/ ratchet_tree + external_pub) and `(*Group).ProcessExternalCommit(commit []byte) error`; `ProcessCommit` dispatch on `new_member_commit`. |
| `mls/group/external_commit.go` | **New** | `ExternalCommit(suite, gi, cred, signer, lifetime) (*Group, []byte, error)` + internal helpers (`findLeafBySignatureKey`). |
| `mls/group/external_commit_test.go` | **New** | Gates: fresh node external-joins a 2-member group → 3 converge; anti-double-join (joiner already present) → tree valid + converge; reject malformed external commits (no path / two ExternalInit / by-reference proposal). |
| `mls/group/process.go` | Edit | `ProcessCommit`: peek `Sender.Type`; if `new_member_commit`, delegate to `processExternalCommit`. |
| `ironcore/recovery.go` | **New** | `RecoverViaExternalCommit(ctx, v *VNIGroup, suite, candidates []group.CommitRef, fetchGI func(group.CommitRef) (*group.GroupInfo, error), ordering group.Ordering, cred, signer, lifetime) error`. |
| `ironcore/recovery_test.go` | **New** | §5.6 gate: 2-member fork → losing member recovers onto canonical branch via the sequencer → re-converge; second concurrent recovery is rejected by the register (single winner). |

---

## Tasks

> TDD throughout: write the failing test first, then the minimum code to pass, then `gofmt`+`vet`+`go test`. One logical change per task; keep each task's diff small. After every task run the full gate: `nix develop -c sh -c 'gofmt -l mls ironcore && go vet ./... && go test ./...'`.

### Task 0 — `mls/cipher` external-init secret primitive (the one new crypto): DHKEM + X-Wing, gated

- [ ] **Add the curve field.** In `mls/cipher/suite.go`, add `curve ecdh.Curve` to `Suite` and set it in the two DHKEM registry entries (`X25519_AES128GCM_SHA256_Ed25519` → `ecdh.X25519()`, `P256_AES128GCM_SHA256_P256` → `ecdh.P256()`). Leave it unset (nil) for the X-Wing entry in `suite_pq.go`. (`crypto/ecdh` is already imported in `suite.go`.)
- [ ] **Implement `mls/cipher/xwing.go`** (the raw X-Wing KEM — see N1b skeleton below): `xwingEncap`/`xwingDecap`/`xwingCombiner`/`xwingExpandSeed`, composing `crypto/mlkem`+`crypto/ecdh`+`crypto/sha3`. **Write `mls/cipher/xwing_test.go` first** (red): SHAKE256(seed,96) reconstruction matches stdlib pk_M/pk_X; `xwingEncap`→`xwingDecap` round-trips the 32-byte secret over many random `DeriveKeyPair` keypairs.
- [ ] **Write `mls/cipher/extinit_test.go` first** (red): assert `ExternalInitEncap`/`ExternalInitDecap` reproduce the RFC 9180 §A.1.1 + §A.3.1 vectors (DHKEM) **and** round-trip across **all** registered suites including `0xF001` (X-Wing).
- [ ] **Implement `mls/cipher/extinit.go`** (green): `ExternalInitEncap`/`ExternalInitDecap` dispatch on the KEM (`s.curve != nil` → DHKEM; `s.kem.ID() == xwingKEMID` → X-Wing; else `errExternalInitUnsupported`), plus `DeriveExternalInitKeyPair` (Option A: just `s.DeriveKeyPair` for every suite — see note).
- [ ] Gate: `nix develop -c go test github.com/trevex/mls-mlkem-go/mls/cipher -run 'TestExternalInit|TestXWing' -v`.

> **`DeriveExternalInitKeyPair(externalSecret) (priv, pub, err)`** is, under **Option A**, byte-for-byte `s.DeriveKeyPair(externalSecret)` for **every** suite (DHKEM and X-Wing alike): DHKEM keeps today's behavior (KAT-validated by `key-schedule.json`); X-Wing's stdlib seed/pub are parseable by `xwingDecap`/`xwingEncap`, so no divergent keygen is needed. Add it as a thin, well-documented wrapper so the group/keyschedule layer has an intention-revealing name. **The external PRIV is already exposed** via the existing `keyschedule.ExternalPub(suite, externalSecret) (priv, pub, err)` — members call it to get the 32-byte X-Wing seed (or DHKEM priv) for `ExternalInitDecap`; no new keyschedule function is required (optionally add a `keyschedule.ExternalInitKeyPair` alias for symmetry).

```go
// mls/cipher/extinit.go
package cipher

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"encoding/binary"
	"errors"
	"fmt"
)

// errExternalInitUnsupported is returned for suites whose KEM is neither a
// DHKEM curve nor X-Wing (0x647a) — i.e. no external-init derivation is defined.
var errExternalInitUnsupported = errors.New("cipher: external init not supported for this KEM")

// kemSuiteID is the RFC 9180 §4.1 KEM suite_id = "KEM" || I2OSP(kem_id, 2).
func (s Suite) kemSuiteID() []byte {
	return binary.BigEndian.AppendUint16([]byte("KEM"), s.kem.ID())
}

// labeledExtract implements RFC 9180 §4: LabeledExtract(salt, label, ikm) =
// Extract(salt, "HPKE-v1" || suite_id || label || ikm).
func (s Suite) labeledExtract(salt []byte, label string, ikm []byte) ([]byte, error) {
	labeledIKM := append([]byte("HPKE-v1"), s.kemSuiteID()...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdf.Extract(s.NewHash, labeledIKM, salt) // (h, ikm, salt) per stdlib order
}

// labeledExpand implements RFC 9180 §4: LabeledExpand(prk, label, info, L) =
// Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L).
func (s Suite) labeledExpand(prk []byte, label string, info []byte, length int) ([]byte, error) {
	var li []byte
	li = binary.BigEndian.AppendUint16(li, uint16(length))
	li = append(li, "HPKE-v1"...)
	li = append(li, s.kemSuiteID()...)
	li = append(li, label...)
	li = append(li, info...)
	return s.kdfExpand(prk, li, length)
}

// extractAndExpand is RFC 9180 §4.1 ExtractAndExpand(dh, kem_context), producing
// the KEM shared_secret of length Nsecret (= KDF.Nh = HashLen for our suites).
func (s Suite) extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	eaePrk, err := s.labeledExtract(nil, "eae_prk", dh)
	if err != nil {
		return nil, err
	}
	return s.labeledExpand(eaePrk, "shared_secret", kemContext, s.HashLen())
}

// ExternalInitEncap performs RFC 9420 §8.3 / RFC 9180 §4.1 DHKEM encapsulation to
// the group's external_pub: it returns kem_output (the serialized ephemeral
// public key, to ship in an ExternalInit proposal) and init_secret (the bare KEM
// shared secret used VERBATIM — no MLS label — as the external commit's new-epoch
// init_secret salt). externalPub is the serialized HPKEPublicKey from the
// GroupInfo external_pub extension.
func (s Suite) ExternalInitEncap(externalPub []byte) (kemOutput, initSecret []byte, err error) {
	if s.curve == nil {
		if s.kem.ID() == xwingKEMID { // 0x647a — X-Wing (see xwing.go)
			return xwingEncap(externalPub)
		}
		return nil, nil, fmt.Errorf("%w (kem_id %#x)", errExternalInitUnsupported, s.kem.ID())
	}
	pkR, err := s.curve.NewPublicKey(externalPub)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: ExternalInitEncap: parse external_pub: %w", err)
	}
	skE, err := s.curve.GenerateKey(randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: ExternalInitEncap: ephemeral keygen: %w", err)
	}
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: ExternalInitEncap: ECDH: %w", err)
	}
	enc := skE.PublicKey().Bytes()
	kemContext := append(append([]byte{}, enc...), externalPub...)
	ss, err := s.extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return enc, ss, nil
}

// ExternalInitDecap performs the receiving side of RFC 9420 §8.3: existing
// members recover the same init_secret from kem_output and external_priv (the
// serialized HPKEPrivateKey from keyschedule.ExternalPub).
func (s Suite) ExternalInitDecap(externalPriv, kemOutput []byte) (initSecret []byte, err error) {
	if s.curve == nil {
		if s.kem.ID() == xwingKEMID { // 0x647a — X-Wing (see xwing.go)
			return xwingDecap(externalPriv, kemOutput)
		}
		return nil, fmt.Errorf("%w (kem_id %#x)", errExternalInitUnsupported, s.kem.ID())
	}
	skR, err := s.curve.NewPrivateKey(externalPriv)
	if err != nil {
		return nil, fmt.Errorf("cipher: ExternalInitDecap: parse external_priv: %w", err)
	}
	pkE, err := s.curve.NewPublicKey(kemOutput)
	if err != nil {
		return nil, fmt.Errorf("cipher: ExternalInitDecap: parse kem_output: %w", err)
	}
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, fmt.Errorf("cipher: ExternalInitDecap: ECDH: %w", err)
	}
	kemContext := append(append([]byte{}, kemOutput...), skR.PublicKey().Bytes()...)
	return s.extractAndExpand(dh, kemContext)
}

// DeriveExternalInitKeyPair derives the §8.3 external_priv/external_pub from the
// epoch's external_secret. Under Option A this is exactly DeriveKeyPair for every
// suite: DHKEM keeps its KAT-validated behavior, and the X-Wing stdlib seed/pub
// are parseable by xwingDecap/xwingEncap, so no divergent keygen is needed.
func (s Suite) DeriveExternalInitKeyPair(externalSecret []byte) (priv, pub []byte, err error) {
	return s.DeriveKeyPair(externalSecret)
}
```

```go
// mls/cipher/xwing.go
package cipher

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
)

// xwingKEMID is the HPKE KEM identifier for MLKEM768X25519 (X-Wing),
// draft-connolly-cfrg-xwing-kem. crypto/hpke.MLKEM768X25519().ID() == 0x647a.
const xwingKEMID = 0x647a

// xWingLabel is the X-Wing combiner domain separator: the 6 ASCII bytes "\.//^\".
var xWingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// xwingCombiner = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel).
func xwingCombiner(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
	h.Write(xWingLabel)
	return h.Sum(nil)
}

// xwingExpandSeed implements X-Wing expandDecapsulationKey: SHAKE256(seed, 96)
// → (ML-KEM 64-byte seed d||z) || (X25519 sk 32). VALIDATED to reproduce
// stdlib's pk_M and pk_X byte-for-byte.
func xwingExpandSeed(seed []byte) (dkM *mlkem.DecapsulationKey768, skX *ecdh.PrivateKey, err error) {
	exp := sha3.SumSHAKE256(seed, 96)
	dkM, err = mlkem.NewDecapsulationKey768(exp[0:64])
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: ML-KEM decap key: %w", err)
	}
	skX, err = ecdh.X25519().NewPrivateKey(exp[64:96])
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: X25519 sk: %w", err)
	}
	return dkM, skX, nil
}

// xwingEncap encapsulates to an X-Wing public key (the stdlib 1216-byte
// pk_M(1184)||pk_X(32)), returning kem_output = ct_M(1088)||ct_X(32) and the
// 32-byte shared secret. (RFC 9420 §8.3 init_secret for the external commit.)
func xwingEncap(externalPub []byte) (kemOutput, initSecret []byte, err error) {
	if len(externalPub) != mlkem.EncapsulationKeySize768+32 {
		return nil, nil, fmt.Errorf("cipher: xwing: external_pub len %d, want %d", len(externalPub), mlkem.EncapsulationKeySize768+32)
	}
	pkM, err := mlkem.NewEncapsulationKey768(externalPub[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: parse pk_M: %w", err)
	}
	pkXb := externalPub[mlkem.EncapsulationKeySize768:]
	pkX, err := ecdh.X25519().NewPublicKey(pkXb)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: parse pk_X: %w", err)
	}
	ssM, ctM := pkM.Encapsulate()
	ek, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: X25519 ephemeral: %w", err)
	}
	ctX := ek.PublicKey().Bytes()
	ssX, err := ek.ECDH(pkX)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: X25519 ECDH: %w", err)
	}
	ss := xwingCombiner(ssM, ssX, ctX, pkXb)
	return append(append([]byte{}, ctM...), ctX...), ss, nil
}

// xwingDecap recovers the same 32-byte shared secret from kem_output and the
// 32-byte X-Wing seed (the stdlib SerializePrivateKey form from DeriveKeyPair).
func xwingDecap(externalPriv, kemOutput []byte) (initSecret []byte, err error) {
	if len(kemOutput) != mlkem.CiphertextSize768+32 {
		return nil, fmt.Errorf("cipher: xwing: kem_output len %d, want %d", len(kemOutput), mlkem.CiphertextSize768+32)
	}
	dkM, skX, err := xwingExpandSeed(externalPriv)
	if err != nil {
		return nil, err
	}
	pkXb := skX.PublicKey().Bytes()
	ctM := kemOutput[:mlkem.CiphertextSize768]
	ctX := kemOutput[mlkem.CiphertextSize768:]
	ssM, err := dkM.Decapsulate(ctM)
	if err != nil {
		return nil, fmt.Errorf("cipher: xwing: ML-KEM decap: %w", err)
	}
	pkX, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, fmt.Errorf("cipher: xwing: parse ct_X: %w", err)
	}
	ssX, err := skX.ECDH(pkX)
	if err != nil {
		return nil, fmt.Errorf("cipher: xwing: X25519 ECDH: %w", err)
	}
	return xwingCombiner(ssM, ssX, ctX, pkXb), nil
}
```

> **Note — `randReader`:** if `mls/cipher` does not already have a package-level `rand.Reader` alias, use `crypto/rand`'s `rand.Reader` directly (`import "crypto/rand"` and call `s.curve.GenerateKey(rand.Reader)`). Pick whichever matches the package's existing convention (`GenerateHPKEKeyPair` in `suite.go` calls `s.kem.GenerateKey()`; for the curve we must pass a reader). Keep it stdlib.

```go
// mls/cipher/extinit_test.go
package cipher

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// RFC 9180 Appendix A.1.1 (DHKEM(X25519, HKDF-SHA256)) and A.3.1
// (DHKEM(P-256, HKDF-SHA256)) base-mode vectors: deterministic encap (fixed
// ephemeral) must reproduce enc + shared_secret exactly.
func TestExternalInitKAT(t *testing.T) {
	type vec struct {
		id              CipherSuite
		curve           ecdh.Curve
		skEm, pkRm      string
		wantEnc, wantSS string
	}
	vecs := []vec{
		{ // RFC 9180 §A.1.1
			id: X25519_AES128GCM_SHA256_Ed25519, curve: ecdh.X25519(),
			skEm:    "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
			pkRm:    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
			wantEnc: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
			wantSS:  "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
		},
		{ // RFC 9180 §A.3.1 (P-256). skEm/pkRm/enc are the SEC1 scalar / uncompressed points.
			id: P256_AES128GCM_SHA256_P256, curve: ecdh.P256(),
			skEm:    "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
			pkRm:    "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
			wantEnc: "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
			wantSS:  "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
		},
	}
	executed := 0
	for _, v := range vecs {
		suite, ok := Lookup(v.id)
		if !ok {
			t.Logf("suite %#x not registered, skipping", v.id)
			continue
		}
		executed++
		// Deterministic encap with the vector's fixed ephemeral key.
		skE, err := v.curve.NewPrivateKey(mustHexT(t, v.skEm))
		if err != nil {
			t.Fatalf("%#x: skE: %v", v.id, err)
		}
		pkR, err := v.curve.NewPublicKey(mustHexT(t, v.pkRm))
		if err != nil {
			t.Fatalf("%#x: pkR: %v", v.id, err)
		}
		dh, err := skE.ECDH(pkR)
		if err != nil {
			t.Fatalf("%#x: ECDH: %v", v.id, err)
		}
		enc := skE.PublicKey().Bytes()
		kemContext := append(append([]byte{}, enc...), mustHexT(t, v.pkRm)...)
		ss, err := suite.extractAndExpand(dh, kemContext)
		if err != nil {
			t.Fatalf("%#x: extractAndExpand: %v", v.id, err)
		}
		if got := hex.EncodeToString(enc); got != v.wantEnc {
			t.Errorf("%#x enc:\n got %s\nwant %s", v.id, got, v.wantEnc)
		}
		if got := hex.EncodeToString(ss); got != v.wantSS {
			t.Errorf("%#x shared_secret:\n got %s\nwant %s", v.id, got, v.wantSS)
		}
	}
	if executed == 0 {
		t.Fatal("no registered suites executed")
	}
}

func TestExternalInitRoundTrip(t *testing.T) {
	executed := 0
	// Includes the X-Wing PQ suite 0xF001 — round-trip exercises the hybrid KEM.
	for _, id := range []CipherSuite{X25519_AES128GCM_SHA256_Ed25519, P256_AES128GCM_SHA256_P256, XWING_AES256GCM_SHA256_Ed25519} {
		suite, ok := Lookup(id)
		if !ok {
			continue
		}
		executed++
		// external_pub/priv from a random external_secret (here: a random keypair).
		priv, pub, err := suite.DeriveKeyPair(randomBytes(t, suite.HashLen()))
		if err != nil {
			t.Fatalf("%#x DeriveKeyPair: %v", id, err)
		}
		kemOut, ssEnc, err := suite.ExternalInitEncap(pub)
		if err != nil {
			t.Fatalf("%#x Encap: %v", id, err)
		}
		ssDec, err := suite.ExternalInitDecap(priv, kemOut)
		if err != nil {
			t.Fatalf("%#x Decap: %v", id, err)
		}
		if !bytes.Equal(ssEnc, ssDec) {
			t.Fatalf("%#x round-trip mismatch:\n encap %x\n decap %x", id, ssEnc, ssDec)
		}
	}
	if executed == 0 {
		t.Fatal("no registered suites executed")
	}
}

func mustHexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
```

> If `mustHexT`/`randomBytes` clash with existing helpers in `mls/cipher` test files, rename or reuse the existing ones (e.g. `keyschedule_test.go` already has a `mustHex(*testing.T, string)` — prefer reusing it and drop `mustHexT`). **The P-256 §A.3.1 vector bytes above were EMPIRICALLY VERIFIED during planning** (a stdlib `crypto/ecdh.P256()` + `crypto/hkdf` ExtractAndExpand reproduced both `enc` and `shared_secret` exactly) — **keep the P-256 KAT case**; the X25519 §A.1.1 values were likewise validated.

### Task 1 — GroupInfo `external_pub` extension + publishable GroupInfo

- [ ] In `mls/group/groupinfo.go` add `ExtensionTypeExternalPub ExtensionType = 0x0004` and an `ExternalPubExtension() []byte` accessor mirroring `RatchetTreeExtension()`.
- [ ] **Test first:** a round-trip test — a `Group` (epoch ≥ 1) `PublishGroupInfo()` → marshal → `DecodeGroupInfoMessage` → `VerifySignature` passes, `RatchetTreeExtension()` non-nil, `ExternalPubExtension()` equals `keyschedule.ExternalPub(suite, g.epoch.ExternalSecret).pub`, and a fresh node can `JoinFromWelcome`-style parse the tree (tree hash matches `GroupContext.TreeHash`).
- [ ] Implement `(*Group).PublishGroupInfo()` in `mls/group/external_join.go`:

```go
// PublishGroupInfo builds a signed GroupInfo for the current epoch, carrying the
// ratchet_tree (0x0002) and external_pub (0x0004) extensions, so a non-member can
// join via an external Commit (RFC 9420 §12.4.3.1/§12.4.3.2). The signer is this
// member (g.ownLeaf); confirmation_tag is recomputed from the current epoch.
func (g *Group) PublishGroupInfo() (*GroupInfo, error) {
	if g.signer == nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: no signer (pure receiver)")
	}
	rtree, err := g.tree.MarshalMLS()
	if err != nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: marshal tree: %w", err)
	}
	_, extPub, err := keyschedule.ExternalPub(g.suite, g.epoch.ExternalSecret)
	if err != nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: ExternalPub: %w", err)
	}
	confTag := keyschedule.ConfirmationTag(g.suite, g.epoch.ConfirmationKey, g.groupContext.ConfirmedTranscriptHash)
	gi := &GroupInfo{
		GroupContext: g.groupContext,
		Extensions: []tree.Extension{
			{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: rtree},
			{ExtensionType: ExtensionTypeExternalPub, ExtensionData: extPub},
		},
		ConfirmationTag: confTag,
		Signer:          g.ownLeaf,
	}
	if err := gi.Sign(g.suite, g.signer); err != nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: Sign: %w", err)
	}
	return gi, nil
}
```

### Task 2 — `ExternalCommit` generation (joiner side) + fresh-join convergence gate

- [ ] **Test first** (`mls/group/external_commit_test.go`): build {alice, bob} at epoch 1 (reuse `active_test.go` helpers via `package group_test`); `gi, _ := alice.PublishGroupInfo()`; `carol, commitMsg, err := group.ExternalCommit(suite, *gi, makeCred("carol"), carolSigner, makeLifetime())`; `alice.ProcessCommit(nil, commitMsg)`; `bob.ProcessCommit(nil, commitMsg)`; `assertConverged(t, "ext", suite, alice, bob, carol)`. (Carol's leaf index = 2; epoch = 2.) This is **red** until Tasks 2–3 land. **Run the gate under `0xF001` (X-Wing) as the PRIMARY suite** (the suite IronCore deploys) — add it to the test's suite loop (e.g. `for _, id := range []cipher.CipherSuite{cipher.XWING_AES256GCM_SHA256_Ed25519, cipher.X25519_AES128GCM_SHA256_Ed25519}`) — plus `0x0001` if cheap; keep the skip-unregistered + zero-executed guard. **Validated during planning**: under `0xF001` all three converge on `epoch_authenticator 3086888c…1835f1fd` at epoch 2.
- [ ] Implement `mls/group/external_commit.go` per N3. Signature: `func ExternalCommit(suite cipher.Suite, gi GroupInfo, cred tree.Credential, signer crypto.Signer, lifetime tree.Lifetime) (*Group, []byte, error)`. Reuse `NewKeyPackage` to mint the joiner leaf, the `mkGC` closure pattern from `commit_gen.go`, `framing.SignCommit`, `keyschedule.{ConfirmedTranscriptHash,DeriveEpochSecrets,ConfirmationTag,InterimTranscriptHash,NewSecretTree}`, and the private-state rebuild from `commit_gen.go` step 6. Add internal helper `findLeafBySignatureKey(rt *tree.RatchetTree, sigKey []byte) (uint32, bool)` (iterate leaves; compare `LeafNode.SignatureKey`) for N5. **Validate the joiner's own GroupInfo signature** before trusting the tree/external_pub.

Key code skeleton (complete the bodies from N3; this is the spine):

```go
// mls/group/external_commit.go
package group

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/framing"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

func ExternalCommit(suite cipher.Suite, gi GroupInfo, cred tree.Credential, signer crypto.Signer, lifetime tree.Lifetime) (*Group, []byte, error) {
	// 1. external_pub → external-init secret.
	extPub := gi.ExternalPubExtension()
	if extPub == nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: GroupInfo has no external_pub extension")
	}
	kemOutput, initSecret, err := suite.ExternalInitEncap(extPub)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: ExternalInitEncap: %w", err)
	}

	// 2. Rebuild + validate the tree from the GroupInfo (mirror JoinFromWelcome N1.6–7).
	rtreeData := gi.RatchetTreeExtension()
	if rtreeData == nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: GroupInfo has no ratchet_tree extension")
	}
	wt, err := tree.ParseRatchetTree(suite, rtreeData)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: ParseRatchetTree: %w", err)
	}
	if ok, err := wt.VerifyParentHashes(); err != nil || !ok {
		return nil, nil, fmt.Errorf("group: ExternalCommit: parent hash verification failed (%v)", err)
	}
	if err := wt.VerifyLeafSignatures(gi.GroupContext.GroupID); err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: VerifyLeafSignatures: %w", err)
	}
	if th, err := wt.RootTreeHash(); err != nil || !bytes.Equal(th, gi.GroupContext.TreeHash) {
		return nil, nil, fmt.Errorf("group: ExternalCommit: tree hash mismatch")
	}
	// (Recommended) verify gi.Signature with the gi.Signer leaf's signature key here.

	gc := gi.GroupContext // GroupContext[n]

	// 3. Anti-double-join: Remove a prior appearance of this signer (N5).
	sigPub, err := suite.SignaturePublicKey(signer)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: SignaturePublicKey: %w", err)
	}
	var byValue []Proposal
	if oldLeaf, ok := findLeafBySignatureKey(wt, sigPub); ok {
		if err := wt.RemoveLeaf(oldLeaf); err != nil {
			return nil, nil, fmt.Errorf("group: ExternalCommit: RemoveLeaf(%d): %w", oldLeaf, err)
		}
		byValue = append(byValue, ProposeRemove(oldLeaf))
	}

	// 4. Mint the joiner leaf and add it (leftmost-blank-or-append → liC).
	kp, _, leafPriv, err := NewKeyPackage(suite, cred, signer, lifetime)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: NewKeyPackage: %w", err)
	}
	liC, err := wt.AddLeaf(kp.LeafNode)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: AddLeaf: %w", err)
	}

	// 5. Proposals: exactly one ExternalInit first, then optional Remove.
	cm := Commit{}
	cm.Proposals = append(cm.Proposals, ProposalOrRef{Type: ProposalOrRefTypeProposal,
		Proposal: &Proposal{Type: ProposalTypeExternalInit, ExternalInit: &ExternalInit{KemOutput: kemOutput}}})
	for i := range byValue {
		p := byValue[i]
		cm.Proposals = append(cm.Proposals, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: &p})
	}

	// 6. UpdatePath from liC; encGC uses the OLD confirmed_transcript_hash.
	leafSecret := make([]byte, suite.HashLen())
	if _, err := rand.Read(leafSecret); err != nil {
		return nil, nil, err
	}
	oldConfirmed := gc.ConfirmedTranscriptHash
	mkGC := func(treeHash []byte) ([]byte, error) {
		return (keyschedule.GroupContext{
			Version: gc.Version, CipherSuite: gc.CipherSuite, GroupID: gc.GroupID,
			Epoch: gc.Epoch + 1, TreeHash: treeHash, ConfirmedTranscriptHash: oldConfirmed,
			Extensions: gc.Extensions,
		}).MarshalMLS()
	}
	up, commitSecret, pathByNode, err := wt.GenerateUpdatePath(liC, leafSecret, signer, gc.GroupID, nil, mkGC)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: GenerateUpdatePath: %w", err)
	}
	cm.Path = up

	// 7–9. Frame + sign + transcript.
	commitBody, err := cm.MarshalMLS()
	if err != nil {
		return nil, nil, err
	}
	fc := framing.FramedContent{
		GroupID: gc.GroupID, Epoch: gc.Epoch,
		Sender:      framing.Sender{Type: framing.SenderTypeNewMemberCommit},
		ContentType: framing.ContentTypeCommit, Content: commitBody,
	}
	confirmedInput, sig, err := framing.SignCommit(suite, signer, &gc, fc)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: SignCommit: %w", err)
	}
	interimN, err := keyschedule.InterimTranscriptHash(suite, gc.ConfirmedTranscriptHash, gi.ConfirmationTag)
	if err != nil {
		return nil, nil, err
	}
	confirmed := keyschedule.ConfirmedTranscriptHash(suite, interimN, confirmedInput)

	// 10. New GroupContext + key schedule with the EXTERNAL-INIT secret as init_secret.
	newTreeHash, err := wt.RootTreeHash()
	if err != nil {
		return nil, nil, err
	}
	newGC := keyschedule.GroupContext{
		Version: gc.Version, CipherSuite: gc.CipherSuite, GroupID: gc.GroupID,
		Epoch: gc.Epoch + 1, TreeHash: newTreeHash, ConfirmedTranscriptHash: confirmed,
		Extensions: gc.Extensions,
	}
	newGCBytes, err := newGC.MarshalMLS()
	if err != nil {
		return nil, nil, err
	}
	es, err := keyschedule.DeriveEpochSecrets(suite, initSecret, commitSecret, nil, newGCBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: DeriveEpochSecrets: %w", err)
	}

	// 11. Assemble the PublicMessage WITHOUT a membership_tag (new_member_commit).
	confTag := keyschedule.ConfirmationTag(suite, es.ConfirmationKey, confirmed)
	pubMsg := framing.PublicMessage{
		Content: fc,
		Auth:    framing.FramedContentAuthData{Signature: sig, ConfirmationTag: confTag},
	}
	commitMLS := framing.MLSMessage{Version: tree.ProtocolVersionMLS10, WireFormat: framing.WireFormatPublicMessage, Public: &pubMsg}
	commitBytes, err := commitMLS.MarshalMLS()
	if err != nil {
		return nil, nil, err
	}

	// 12. Build the joiner's own Group state at epoch n+1 (mirror commit_gen step 6).
	interim, err := keyschedule.InterimTranscriptHash(suite, confirmed, confTag)
	if err != nil {
		return nil, nil, err
	}
	leafNodeSecret, err := suite.DeriveSecret(leafSecret, "node")
	if err != nil {
		return nil, nil, err
	}
	newLeafPriv, _, err := suite.DeriveKeyPair(leafNodeSecret)
	if err != nil {
		return nil, nil, err
	}
	priv := tree.NewTreeKEMPrivate(liC, newLeafPriv)
	for nodeIdx, ps := range pathByNode {
		if err := priv.AddPathSecret(suite, nodeIdx, ps); err != nil {
			return nil, nil, err
		}
	}
	st, err := keyschedule.NewSecretTree(suite, wt.LeafCount(), es.EncryptionSecret)
	if err != nil {
		return nil, nil, err
	}
	_ = leafPriv // the leaf encryption key is rederived above; init key unused post-join
	g := &Group{
		suite: suite, groupContext: newGC, tree: wt, priv: priv, epoch: es,
		secretTree: st, interim: interim, initSecret: es.InitSecret, ownLeaf: liC,
		signer: signer, externalPSKs: map[string][]byte{},
		resumptionPSKHistory: map[uint64][]byte{newGC.Epoch: es.ResumptionPSK},
		pendingUpdates:       map[string][]byte{},
	}
	return g, commitBytes, nil
}

func findLeafBySignatureKey(rt *tree.RatchetTree, sigKey []byte) (uint32, bool) {
	for i := uint32(0); i < rt.LeafCount(); i++ {
		ln, err := rt.LeafNodeAt(i)
		if err != nil {
			continue // blank leaf
		}
		if bytes.Equal(ln.SignatureKey, sigKey) {
			return i, true
		}
	}
	return 0, false
}
```

> The fresh-join gate stays red until Task 3 adds the receiver path; that's expected for the bite-sized TDD loop (commit Task 2 + Task 3 together if your reviewer prefers each commit green — they are one logical feature split for review clarity).

### Task 3 — `ProcessExternalCommit` (existing-member side) + `ProcessCommit` dispatch

- [ ] Implement `(*Group).ProcessExternalCommit(commit []byte) error` in `mls/group/external_join.go` per N4 (reuse the `process.go` body almost verbatim; the deltas are: sender-type check, signer key from `cm.Path.LeafNode.SignatureKey`, `ExternalInitDecap` for `init_secret`, and the `RemoveLeaf?+AddLeaf(cm.Path.LeafNode)` placement before `ProcessUpdatePath`). Enforce the §12.4.3.2 validity rules (exactly one `ExternalInit`; path present; no by-reference proposals; only `{ExternalInit, Remove, PreSharedKey, GroupContextExtensions}` by value).
- [ ] In `process.go`, after parsing the commit `PublicMessage`, dispatch: `if m.Public.Content.Sender.Type == framing.SenderTypeNewMemberCommit { return g.processExternalCommit(m) }` (share a parsed-message internal entry so both the public `ProcessExternalCommit` and `ProcessCommit` reach the same code).
- [ ] The Task-2 fresh-join gate now goes **green**. Also add negative tests: a commit with two `ExternalInit` proposals, a path-less external commit, and an external commit carrying a by-reference proposal each return an error and leave `g` unchanged.

### Task 4 — Anti-double-join gate

- [ ] **Test (under `0xF001` primary + `0x0001`):** {alice, bob} at epoch 1; bob external-commits back into alice's group using `alice.PublishGroupInfo()` (bob is already a member — reuse bob's SAME signature identity so anti-double-join finds the stale leaf; `NewKeyPackage` still mints fresh HPKE keys). Assert: the generated commit contains a `Remove` of bob's old leaf; `alice.ProcessExternalCommit(commitMsg)` succeeds; `bob`'s new Group and `alice` converge (`assertConverged`); the resulting tree has bob at exactly one leaf (no double-join); `VerifyParentHashes()` holds. (This is the N5 path; it is also exercised end-to-end by Task 5's fork-recovery test, but keep a focused unit gate here.) **Validated during planning under `0xF001`** (see Task 5 numbers).

### Task 5 — `ironcore.RecoverViaExternalCommit` (§5.6) routed through the sequencer

- [x] **Test first** (`ironcore/recovery_test.go`, `package ironcore_test`) — **run under `0xF001` (the deployed PQ suite) as the primary case**: build a 2-member VNI group via `buildVNIGroup(t, suite, vni, 2)` at epoch 1; fork it (member-0 and member-1 each empty-`Commit` → divergent epoch-2 authenticators); pick `candidates = {refMember0Branch, refMember1Branch}`; the losing member calls `RecoverViaExternalCommit(...)` with a shared `sequencer.NewMemorySequencer()`; assert the loser's new group **converges under `0xF001`** with the canonical member (byte-equal `EpochAuthenticator` + `DeriveSA` keys equal), and that a **second** competing recovery for the same `(group, epoch)` gets `ok=false` from the register (single winner — recovery cannot fork). **Validated during planning under `0xF001`**: fork EAs `ed8036fe…` vs `aa18df66…`; after the losing member's external-commit recovery (anti-double-join Remove of its stale leaf), both re-converged on `epoch_authenticator fc5fcd08…629dee07` at epoch 3 with valid parent hashes.
- [x] Implement `ironcore/recovery.go`:

```go
// ironcore/recovery.go
package ironcore

import (
	"context"
	"fmt"

	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// RecoverViaExternalCommit re-converges a stale/losing VNIGroup onto the
// canonical branch after a fork (design spec §5.6). It picks the canonical
// branch deterministically (lowest Hash(CommitRef), Plan 11 tie-break), builds an
// external Commit from that branch's signed GroupInfo (anti-double-join handled by
// group.ExternalCommit), and routes the recovery commit through the SINGLE
// Ordering linearization point so the recovery itself cannot fork. On success the
// VNIGroup adopts the new group state at the recovered epoch.
//
// fetchGI maps a candidate branch CommitRef to that branch's signed GroupInfo at
// the contested epoch (provided by the delivery service / out-of-band).
func RecoverViaExternalCommit(
	ctx context.Context,
	v *VNIGroup,
	suite cipher.Suite,
	candidates []group.CommitRef,
	fetchGI func(group.CommitRef) (*group.GroupInfo, error),
	ordering group.Ordering,
	cred tree.Credential,
	signer cryptoSigner,
	lifetime tree.Lifetime,
) error {
	canonical := sequencer.CanonicalCommit(suite, candidates)
	if canonical == nil {
		return fmt.Errorf("ironcore: RecoverViaExternalCommit: no candidate branches")
	}
	gi, err := fetchGI(canonical)
	if err != nil {
		return fmt.Errorf("ironcore: RecoverViaExternalCommit: fetch canonical GroupInfo: %w", err)
	}
	newGroup, commitMsg, err := group.ExternalCommit(suite, *gi, cred, signer, lifetime)
	if err != nil {
		return fmt.Errorf("ironcore: RecoverViaExternalCommit: ExternalCommit: %w", err)
	}
	ref := group.CommitRef(suite.Hash(commitMsg))
	ok, err := ordering.AcceptCommit(ctx, group.GroupID(v.GroupID()), gi.GroupContext.Epoch, ref)
	if err != nil {
		return fmt.Errorf("ironcore: RecoverViaExternalCommit: AcceptCommit: %w", err)
	}
	if !ok {
		// Another recovery already won this (group, epoch). Caller re-fetches the
		// now-decided GroupInfo and retries against the next epoch.
		return errRecoverySuperseded
	}
	v.g = newGroup // adopt the canonical-branch state; broadcast commitMsg out-of-band.
	return nil
}
```

> `cryptoSigner` = `crypto.Signer` (import `crypto`); name it directly. `errRecoverySuperseded` is a sentinel (`var errRecoverySuperseded = errors.New("ironcore: recovery superseded by a concurrent winner")`) the caller can `errors.Is`-check to drive the retry loop. `v.g` is settable from within `package ironcore` (same package as `VNIGroup`); if a setter is preferred, add `(*VNIGroup).adopt(g *group.Group)`.

### Task 6 — Full gate + docs sweep

- [x] Run the complete gate: `nix develop -c sh -c 'gofmt -l mls ironcore && go vet ./... && go test ./...'` — all green, all 15 existing KATs still pass, the new convergence + DHKEM gates pass.
- [x] (Optional) extend the passive-random driver to assert it correctly handles/rejects a `new_member_commit` epoch if one is ever present, guarded so it never fails on its absence — skipped: the registered-suite KAT cases contain no `new_member_commit` epoch; ProcessCommit already dispatches correctly, so adding a guarded assertion adds no safety.
- [x] Confirm the working tree contains only the intended new/edited files; no `zz_*`/`zzz_*` throwaways or temp-vendored KATs remain (`git status` clean except the feature diff).

---

## Definition of Done

- [x] `mls/cipher.ExternalInitEncap`/`ExternalInitDecap` reproduce the **RFC 9180 §A.1.1 (X25519)** and **§A.3.1 (P-256)** DHKEM vectors exactly, and the **X-Wing (`0xF001`)** raw KEM encap/decap round-trips the 32-byte secret (with byte-exact stdlib pk_M/pk_X reconstruction); the init secret is the **bare KEM shared secret** (no MLS label), `Nsecret = 32`. `DeriveExternalInitKeyPair == DeriveKeyPair` for every suite (Option A — DHKEM external_pub unchanged, X-Wing external keypair stays stdlib-derived).
- [x] A non-member `group.ExternalCommit` into a 2-member group yields a Commit that the two existing members process via `ProcessCommit`/`ProcessExternalCommit`, and **all three members share a byte-identical `epoch_authenticator` AND `Exporter` output** at epoch n+1 (`assertConverged`) — gated under **`0xF001` (primary)** and `0x0001`.
- [x] An already-present member external-committing includes a **`Remove` of its prior leaf** (anti-double-join, §12.4.3.2); the post-commit tree is valid (`VerifyParentHashes`), the member appears at exactly one leaf, and all members converge.
- [x] External commits are validated per §12.4.3.2: exactly one `ExternalInit`, mandatory `UpdatePath`, no by-reference proposals, only `{ExternalInit, Remove, PreSharedKey, GroupContextExtensions}` by value, signature verified with the path leaf's signature key; violations are rejected and leave the receiver unchanged.
- [x] `ironcore.RecoverViaExternalCommit` re-converges a losing-branch member onto the **canonical** branch (lowest `Hash(CommitRef)`) **under `0xF001`**, the recovery commit is accepted by the **single `Ordering` register**, a competing concurrent recovery is rejected (`ok=false`), and the recovered member's `DeriveSA` keys match the canonical member's (design spec §5.6).
- [x] `gofmt -l` empty, `go vet ./...` clean, `go test ./...` green (all prior KATs + new gates); stdlib-only; working tree clean apart from the feature diff.

---

## Notes for the remaining roadmap

- **PQ external-init (X-Wing `0xF001`) — DONE in this plan:** `ExternalInitEncap`/`Decap` dispatch to the composed X-Wing KEM (`mls/cipher/xwing.go`: `crypto/mlkem`+`crypto/ecdh`+`crypto/sha3`, combiner `SHA3-256(ss_M‖ss_X‖ct_X‖pk_X‖\.//^\)`), external joins + fork-recovery converge under `0xF001` (the deployed suite). Remaining PQ follow-up: if upstream publishes a deterministic X-Wing **KEM** test vector with exposed ML-KEM encaps coins, add it as a byte-exact KAT (today's gate is round-trip + byte-exact stdlib pk_M/pk_X reconstruction + end-to-end convergence). Note `crypto/hpke.MLKEM768X25519` AEAD path is still used for Welcome/UpdatePath; only the bare KEM is hand-composed for external-init.
- **gRPC interop runner:** wire `ExternalCommit`/`ProcessExternalCommit`/`PublishGroupInfo` into the interop harness's `external_join` / `external_commit` actions and (if the upstream test runner emits them) cross-check against another implementation; this is where real interop pressure on the §8.3 mechanism + `new_member_commit` framing will land.
- **Membership controller (`ironcore`):** designated-committer election should decide *when* a node joins via Welcome vs. external commit, and own the `RecoverViaExternalCommit` retry loop (re-fetch decided GroupInfo, advance epoch) on `errRecoverySuperseded`.
- **metalbond adapters:** the `Ordering`/`LeaseStore` adapters (etcd / k8s control plane) back the same register the recovery flow routes through; no `mls/`-side change needed — `RecoverViaExternalCommit` is written against the `group.Ordering` port.
- **GroupInfo distribution:** `DeliveryService.PublishGroupInfo`/`FetchGroupInfo` (already in `ports.go`) should carry `PublishGroupInfo()` output; define the freshness/epoch policy (a joiner must use a GroupInfo for the *current* decided epoch or its external commit will be rejected by the register).
```
