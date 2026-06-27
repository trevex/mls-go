# Active Group Operations — KeyPackage/Group/Proposal/Commit/Welcome generation + Application messages (Plan 9 of 11) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Depends on Plan 8** (`2026-06-26-group-engine.md`) — the passive `mls/group` engine (`JoinFromWelcome`, `ProcessCommit`, `applyProposals`, the `Group` struct, `ports.go`) and all of `framing`/`keyschedule`/`tree`/`cipher` must be merged first. Every fact in the **Design notes** below was empirically validated during planning with throwaway generators (a `tree.NewRatchetTree`/`SignLeafNode` helper, a `GenerateUpdatePath` variant honoring `newlyAdded`, two `framing` commit-assembly helpers, and a full `package group` round-trip test). The throwaways were deleted; the working tree was left clean.

**Goal:** Implement the **committer/creator (active) path** of MLS so this library can *originate* groups, not just observe them. Five capabilities: (1) **`NewKeyPackage`** — generate an init key + leaf HPKE key + signed LeafNode + signed KeyPackage a client publishes so others can Add it (RFC 9420 §10); (2) **`NewGroup`** — a single-member group at epoch 0 (RFC 9420 §11 / §8); (3) **proposal generation** — build Add/Update/Remove/GroupContextExtensions, framed as PublicMessage proposals or returned bare for by-value inclusion (RFC 9420 §12.1); (4) **`Commit`** — apply proposals to a cloned tree (§12.3 order), generate an UpdatePath via `tree.GenerateUpdatePath` (rekeying the committer's direct path, **omitting** path secrets for same-commit Adds per §7.5), advance the §8 key schedule, compute the confirmation_tag, frame the commit as a PublicMessage, build the **Welcome** + signed **GroupInfo** for newly-added members (§12.4 / §12.4.3.1), and advance the committer to epoch n+1; (5) **application messages** — `ProtectApplication`/`UnprotectApplication` over the §6.3 PrivateMessage path with a stateful per-epoch sender ratchet (§6.3.1 / §9). There is **no official KAT for generation**; the gates are **self-round-trip** and **interop with our own passive path** — after each `Commit` the committer's `epoch_authenticator` **and** `MLSExporter` output MUST be byte-equal to what a receiver gets via `ProcessCommit` and a newly-added member gets via `JoinFromWelcome`.

**Architecture:** Almost all new code lives in **`mls/group`** (`create.go`, `keypackage_gen.go`, `propose.go`, `commit_gen.go`, `welcome_gen.go`, `application.go`), with **three small justified helpers added to lower layers**: (a) `mls/tree` gains `NewRatchetTree` (build a single-leaf tree — the tree package today only *parses* trees) and `SignLeafNode` (sign a LeafNode's `LeafNodeTBS` — today only `GenerateUpdatePath` signs leaves, internally), and its `GenerateUpdatePath` is **extended** to (i) accept a `newlyAdded []uint32` list and skip those leaves when encrypting path secrets (RFC 9420 §7.5 — symmetric with the receiver's existing `ProcessUpdatePath` which *already* skips them) and (ii) return the per-node path secrets the Welcome needs; (b) `mls/cipher` gains `Suite.SignaturePublicKey(signer)` (serialize a `crypto.Signer`'s public key to the suite's `SignaturePublicKey` encoding — needed to fill `LeafNode.SignatureKey`); (c) `mls/framing` gains two commit-assembly helpers (`SignCommit`, `AssembleCommitPublic`) that expose the otherwise-private `FramedContentTBS` signing + membership-tag steps so the group layer can run the §6.1/§8.2 *circular* "sign → confirmed_transcript_hash → key schedule → confirmation_tag → assemble" dance. **No import cycle:** the dependency DAG is unchanged (`group` stays the leaf importer; the new helpers add no new edges). The active path **reuses the passive machinery verbatim** — `applyProposals`, `commonAncestor`/`installJoinerPriv`, `keyschedule.DeriveEpochSecrets`, `ConfirmedTranscriptHash`/`InterimTranscriptHash`/`ConfirmationTag`, `framing.ProtectPublic`/`ProtectPrivate`/`UnprotectPrivate` — which is precisely why the round-trip closes.

**Tech Stack:** Go 1.26 standard library only (`bytes`, `crypto`, `crypto/ed25519`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `errors`/`fmt`). No third-party dependencies (hard constraint). Builds on `mls/cipher` (`GenerateHPKEKeyPair`/`DeriveKeyPair`/`SignWithLabel`/`VerifyWithLabel`/`EncryptWithLabel`/`Seal`/`Extract`/`ExpandWithLabel`/`DeriveSecret`/`MAC`/`RefHash`), `mls/tree` (`RatchetTree`/`LeafNode`/`Capabilities`/`Credential`/`Clone`/`AddLeaf`/`RemoveLeaf`/`UpdateLeaf`/`Merge`/`ProcessUpdatePath`/`GenerateUpdatePath`/`RootTreeHash`/`TreeKEMPrivate`), `mls/keyschedule` (`GroupContext`/`DeriveEpochSecrets`/`EpochSecrets`/`WelcomeKeyNonce`/`PSKSecret`/`MLSExporter`/`NewSecretTree`/transcript helpers), `mls/framing` (`FramedContent`/`Sender`/`AuthenticatedContent`/`ProtectPublic`/`UnprotectPublic`/`ProtectPrivate`/`UnprotectPrivate`/`MLSMessage`), and the Plan 8 `group` objects (`KeyPackage`/`Proposal`/`Commit`/`GroupInfo`/`Welcome`/`GroupSecrets`/`EncryptedGroupSecrets`/`applyProposals`/`Group`).

**Spec reference:** RFC 9420 §5.2 (RefHash), §6.1 (FramedContent / FramedContentAuthData / FramedContentTBS / confirmation_tag), §6.2 (PublicMessage / membership_tag), §6.3 + §6.3.1 (PrivateMessage / application encryption + sender ratchet), §7.5 (UpdatePath generation + the same-commit-Add exclusion rule), §8 (key schedule), §8.2 (transcript hashes + their epoch-0 initialization), §9 (secret tree / ratchets), §10 (KeyPackage), §11 (group creation), §12.1 (proposals), §12.3 (proposal application order), §12.4 + §12.4.3.1 (Commit / Welcome / GroupInfo), §17.3 (extension types: `ratchet_tree`=0x0002, `external_pub`=0x0004).

> **Go invocation convention:** Go is **not** on `PATH`. Every Go command runs through the nix devshell, e.g. `nix develop -c go test ./mls/group/`. Use this form everywhere below.

---

## Design notes (read before implementing)

Every claim below was reproduced during planning by a throwaway `package group` test that: created a one-member group (Alice), committed an Add(Bob), had Bob `JoinFromWelcome`; committed an Add(Carol) that Bob processed via `ProcessCommit` and Carol joined; had Bob (a non-creator) commit a path-only update that Alice and Carol processed; had Alice commit a Remove(Carol) that Bob processed; and protected an application message from Alice that Bob unprotected. At **every** epoch all live members had **byte-equal `epoch_authenticator` and byte-equal `MLSExporter("zz", "ctx", 32)`**, and the application plaintext decrypted exactly. **These facts make or break the round-trip — get them exactly right.**

### N0. The two-GroupContext rule is the same as the passive path (do NOT re-derive it)
Plan 8's `ProcessCommit` already pins the #1 trap: the UpdatePath HPKE encryption context uses **`epoch=n+1` + OLD `confirmed_transcript_hash` + the post-path tree hash**, while the key-schedule + confirmation-tag context uses **`epoch=n+1` + NEW `confirmed_transcript_hash` + the post-path tree hash** — the two `GroupContext`s differ **only** in `confirmed_transcript_hash`. The generator must construct **the identical two contexts** (N4). Construct `encGC` (OLD confirmed) and pass its `MarshalMLS()` into `GenerateUpdatePath` via the `mkGroupContext` callback; construct `newGC` (NEW confirmed) for `DeriveEpochSecrets`. Validated: a receiver's `ProcessCommit` (which independently rebuilds both contexts) reproduces the committer's `epoch_authenticator` at every epoch.

### N1. Group creation / epoch 0 (RFC 9420 §11 / §8 / §8.2) — verified
- **Tree:** a single leaf at index 0 holding the creator's (key_package-source) LeafNode. `tree.NewRatchetTree(suite, leaf)` builds `nodes=[{Leaf:&leaf}]`.
- **GroupContext (epoch 0):** `{version=mls10, cipher_suite, group_id, epoch=0, tree_hash=RootTreeHash(), confirmed_transcript_hash="" (zero-length), extensions}`.
- **Transcript init (§8.2):** `interim_transcript_hash_[0]` and `confirmed_transcript_hash_[0]` are the **zero-length octet string** (`[]byte(nil)` → `WriteOpaqueV` emits length 0). Validated for self-consistency: the first commit chains `confirmed_[1]=Hash(interim_[0] ‖ input)` and a joiner trusts the transmitted `confirmed_[1]` in the signed GroupInfo, so the round-trip closes. **Interop caveat:** the *value* of `confirmed_[1]` is carried in the signed GroupInfo, so any consistent `interim_[0]` round-trips with our own passive path; the zero-length choice is the RFC-mandated value and is what cross-implementation interop (Plan 10) requires.
- **Epoch-0 secrets:** seed `init_secret_[-1] = Hash.Nh zero bytes`, then `es0 = keyschedule.DeriveEpochSecrets(suite, zeros, commit_secret=nil, psk_secret=nil, gc0Bytes)`. `nil` commit/psk are treated as the all-zero `Hash.Nh` vector by the existing key schedule. Store `init_secret = es0.InitSecret` (input to epoch 1). The exact epoch-0 seed is **invisible to joiners** (they receive `joiner_secret` directly), so any value round-trips; zeros is the RFC value.
- **Private state:** `priv = tree.NewTreeKEMPrivate(0, leafPriv)`; `secretTree = NewSecretTree(suite, 1, es0.EncryptionSecret)`; `ownLeaf=0`; `signer` = the creator's signing key.

### N2. KeyPackage generation (RFC 9420 §10) — verified
1. `initPriv, initPub = suite.GenerateHPKEKeyPair()` (the `init_key`).
2. `leafPriv, leafPub = suite.GenerateHPKEKeyPair()` (the leaf `encryption_key`).
3. Build `LeafNode{EncryptionKey: leafPub, SignatureKey: suite.SignaturePublicKey(signer), Credential, Capabilities, LeafNodeSource: key_package, Lifetime: {NotBefore, NotAfter}}`. **Sign its `LeafNodeTBS`** with `suite.SignWithLabel(signer, "LeafNodeTBS", tbs)` — for **key_package** source the TBS is `marshalContents` only (no `group_id`/`leaf_index` suffix). Expose this via `tree.SignLeafNode` (N6).
4. Build `KeyPackage{Version: mls10, CipherSuite, InitKey: initPub, LeafNode, Extensions: nil}`, then sign `KeyPackageTBS`: `sig = suite.SignWithLabel(signer, "KeyPackageTBS", kp.tbsBytes())`. (`KeyPackage.tbsBytes()` already exists.)
5. Return `(kp, initPriv, leafPriv)` and the MLSMessage envelope via `EncodeKeyPackageMessage(kp)`. Validated: `kp.VerifySignature(suite)` is true and the generated KP is accepted by `JoinFromWelcome` / `AddLeaf` end-to-end.

`Capabilities` minimum: `{Versions:[mls10], CipherSuites:[suite.ID], Credentials:[basic]}` (empty Extensions/Proposals lists). `Lifetime`: `{NotBefore:0, NotAfter: ^uint64(0)}` for tests; production uses `Clock.Now()`-derived bounds.

### N3. Proposal generation (RFC 9420 §12.1) — verified
- **Add:** `Proposal{Type: Add, Add: &Add{KeyPackage: kp}}` from a received KeyPackage.
- **Update:** generate a fresh leaf HPKE key, build an **update-source** LeafNode (`SignLeafNode` with `group_id`+`leaf_index` suffix — update/commit sources DO suffix the TBS), `Proposal{Type: Update, Update: &Update{LeafNode: ln}}`. The proposer must keep the new `leafPriv` to install after its proposal is committed (out of scope for the round-trip gate; tracked as a sender-side TODO).
- **Remove:** `Proposal{Type: Remove, Remove: &Remove{Removed: leafIndex}}`.
- **GroupContextExtensions:** `Proposal{Type: GroupContextExtensions, GroupContextExtensions: &GroupContextExtensions{Extensions: ext}}`.
- **Framing:** a stand-alone proposal is framed as a **PublicMessage** with `ContentType=proposal`, `Sender={member, ownLeaf}`, via `framing.ProtectPublic(suite, signer, &gc_n, membershipKey_n, fc, nil)` (no confirmation_tag for proposals). For inclusion **by value** inside a Commit, return the bare `Proposal`. `applyProposals` (Plan 8) consumes both. Validated: a generated PublicMessage proposal round-trips through `UnprotectPublic` and its `RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent)` matches what `ProcessCommit` caches.

### N4. Commit generation — the exact, verified sequence (RFC 9420 §12.4 / §7.5 / §8 / §8.2)
Given current `Group` state at epoch *n*, by-value `Proposal`s, and optional by-reference proposal messages:
1. **Clone + apply proposals.** `wt = g.tree.Clone()`; reuse Plan 8's `applyProposals(suite, wt, cm, cache, g.groupContext.Extensions, g.externalPSKs, resumptionPSKs, groupID, g.ownLeaf)` → `(provisionalExt, epochPSKs, _, newlyAdded, err)`. `cm.Proposals` is built from the by-value `Proposal`s (wrapped as `ProposalOrRef{Type: proposal}`) plus by-reference `ProposalOrRef{Type: reference, Reference: prop.Ref}` for cached ones. `newlyAdded` is the list of leaf indices added in this commit (drives the §7.5 skip).
2. **Generate the UpdatePath** on `wt` (which already has the proposals applied). `leafSecret = random(Hash.Nh)`. Build the OLD-confirmed encryption context via the callback:
   ```go
   oldConfirmed := g.groupContext.ConfirmedTranscriptHash
   mkGC := func(treeHash []byte) ([]byte, error) {
       encGC := keyschedule.GroupContext{
           Version: g.groupContext.Version, CipherSuite: g.groupContext.CipherSuite,
           GroupID: g.groupContext.GroupID, Epoch: g.groupContext.Epoch + 1,
           TreeHash: treeHash, ConfirmedTranscriptHash: oldConfirmed, // OLD — N0
           Extensions: provisionalExt,
       }
       return encGC.MarshalMLS()
   }
   up, commitSecret, pathSecretByNode, err := wt.GenerateUpdatePath(g.ownLeaf, leafSecret, g.signer, g.groupContext.GroupID, newlyAdded, mkGC)
   ```
   `GenerateUpdatePath` mutates `wt` in place (blanks+rekeys the committer's direct path, installs+signs the commit leaf, **skips `newlyAdded` leaves when encrypting** — N7) and returns `pathSecretByNode` (filtered-direct-path node index → path secret) for the Welcome.
3. **Frame the commit + compute the transcript (the circular dance — N5).** `commitBody = cm.MarshalMLS()`; `fc = FramedContent{GroupID, Epoch=n, Sender={member, ownLeaf}, ContentType=commit, Content: commitBody}`. Then:
   ```go
   confirmedInput, sig, _ := framing.SignCommit(suite, g.signer, &g.groupContext, fc) // signs FramedContentTBS over gc_n
   confirmed := keyschedule.ConfirmedTranscriptHash(suite, g.interim, confirmedInput)
   newTreeHash, _ := wt.RootTreeHash()
   newGC := keyschedule.GroupContext{ /* …like encGC… */ ConfirmedTranscriptHash: confirmed /* NEW — N0 */ , TreeHash: newTreeHash }
   pskSecret, _ := keyschedule.PSKSecret(suite, epochPSKs)
   es, _ := keyschedule.DeriveEpochSecrets(suite, g.initSecret, commitSecret, pskSecret, newGC.MarshalMLS())
   confTag := keyschedule.ConfirmationTag(suite, es.ConfirmationKey, confirmed)
   pubMsg, _ := framing.AssembleCommitPublic(suite, &g.groupContext, g.epoch.MembershipKey, fc, sig, confTag)
   ```
   `newGC` and `encGC` differ **only** in `confirmed_transcript_hash`. The membership_tag uses **gc_n + membership_key_[n]** (the *current* epoch), because the commit is framed in epoch n (N0/N6 of Plan 8). The commit MLSMessage is `{Version: mls10, WireFormat: public, Public: &pubMsg}.MarshalMLS()`.
4. **Build the Welcome** for `newlyAdded` (N5 below).
5. **Advance the committer to epoch n+1** — identical to `ProcessCommit`'s final state-commit (N8). Validated: the committer's post-commit `epoch_authenticator`/`Exporter` equal a receiver's.

### N5. Welcome + GroupInfo construction (RFC 9420 §12.4.3.1) — verified (trust the passing-KAT wire formats, NOT a paraphrase)
Done **after** the key schedule (needs `es.JoinerSecret`, `es.WelcomeSecret`, `confTag`, the final `wt`, and `newGC`):
1. **GroupInfo:** `GroupInfo{GroupContext: newGC, Extensions: [ratchet_tree], ConfirmationTag: confTag, Signer: g.ownLeaf}`, then `gi.Sign(suite, g.signer)` (label **`"GroupInfoTBS"`** — the existing `GroupInfo.Sign`). The **`ratchet_tree` extension (0x0002)** carries `wt.MarshalMLS()` (the **post-commit** tree). Optionally append an **`external_pub` extension (0x0004)** = the serialized `external_pub = ExternalPub(suite, es.ExternalSecret)` for external-commit joins (the precise extension-data encoding is validated in the deferred external-commit task; omit it for the core round-trip).
2. **Encrypt GroupInfo:** `wk, wn = keyschedule.WelcomeKeyNonce(suite, es.WelcomeSecret)`; `encGI = suite.Seal(wk, wn, aad=nil, gi.MarshalMLS())`. **AAD is empty** (mirrors `JoinFromWelcome`).
3. **Per added member** (`leaf` in `newlyAdded`, paired with its `KeyPackage` in proposal order):
   ```go
   node := commonAncestor(2*leaf, 2*g.ownLeaf, wt.LeafCount())     // §12.4.3.1 / N4 of Plan 8
   ps   := pathSecretByNode[node]                                  // ALWAYS present: the common ancestor is on the committer's filtered direct path
   gs   := GroupSecrets{JoinerSecret: es.JoinerSecret, PathSecret: &PathSecret{PathSecret: ps}}
   kem, ct := suite.EncryptWithLabel(addedKP.InitKey, "Welcome", encGI, gs.MarshalMLS()) // label "Welcome", context = encrypted_group_info
   egs  := EncryptedGroupSecrets{NewMember: addedKP.Ref(suite), EncryptedGroupSecrets: tree.HPKECiphertext{KemOutput: kem, Ciphertext: ct}}
   ```
   `GroupSecrets` is `{joiner_secret, optional path_secret, psks}` (the Plan 8 struct — **not** "epoch_secret"; the HPKE label is **`"Welcome"`** with **context = `encrypted_group_info`**, both confirmed by the passing `passive-client-welcome.json` KAT). `gs.PSKs` carries any external/resumption `PreSharedKeyID`s injected this commit (empty for the core gate).
4. **Welcome:** `Welcome{CipherSuite: suite.ID, Secrets: [egs…], EncryptedGroupInfo: encGI}` → `EncodeWelcomeMessage(w)`. Validated: `JoinFromWelcome` reproduces the committer's `epoch_authenticator`/`Exporter`, and the new member's installed `path_secret` matches the committer's tree (proven by the new member then committing a later epoch that all members process).

### N6. The §6.1/§8.2 circular dependency, resolved (the framing additions) — verified
`confirmed_transcript_hash_[n+1]` depends on the commit's **signature** (it is `Hash(interim_[n] ‖ wire_format ‖ FramedContent ‖ signature)`); the **confirmation_tag** depends on `confirmed_[n+1]` *and* the new epoch's `confirmation_key`; and the PublicMessage's **membership_tag** depends on both the signature **and** the confirmation_tag. The resolution is that **`FramedContentTBS` does NOT include the auth data** — so the signature is computable first, independent of the confirmation_tag. `framing` exposes exactly two helpers (the otherwise-private `sign`/`framedContentTBS`/`authenticatedContentTBM`/`FramedContent.marshal` are inaccessible to `group`):
```go
// SignCommit signs FramedContentTBS for a PublicMessage commit and returns the
// ConfirmedTranscriptHashInput (wire_format ‖ FramedContent ‖ signature<V>) plus the signature.
func SignCommit(suite cipher.Suite, signer crypto.Signer, gc *keyschedule.GroupContext, fc FramedContent) (confirmedInput, signature []byte, err error) {
    ac := AuthenticatedContent{WireFormat: WireFormatPublicMessage, Content: fc}
    if err := ac.sign(suite, signer, gc); err != nil { return nil, nil, err }
    b := syntax.NewBuilder()
    b.WriteUint16(uint16(WireFormatPublicMessage))
    if err := fc.marshal(b); err != nil { return nil, nil, err }
    if err := b.WriteOpaqueV(ac.Auth.Signature); err != nil { return nil, nil, err }
    return b.Bytes(), ac.Auth.Signature, nil
}

// AssembleCommitPublic builds the PublicMessage from a precomputed signature + confirmation_tag, adding the membership_tag.
func AssembleCommitPublic(suite cipher.Suite, gc *keyschedule.GroupContext, membershipKey []byte, fc FramedContent, signature, confTag []byte) (PublicMessage, error) {
    auth := FramedContentAuthData{Signature: signature, ConfirmationTag: confTag}
    m := PublicMessage{Content: fc, Auth: auth}
    tbm, err := authenticatedContentTBM(WireFormatPublicMessage, fc, auth, gc)
    if err != nil { return PublicMessage{}, err }
    m.MembershipTag = suite.MAC(membershipKey, tbm)
    return m, nil
}
```
`SignCommit`'s `confirmedInput` is **byte-identical** to `keyschedule.SplitAuthenticatedContent(ac.MarshalMLS())`'s `confirmedInput` (the passive path's input): both are `wire_format ‖ FramedContent ‖ signature<V>` (the marshaled AuthenticatedContent minus the trailing `confirmation_tag<V>` field). Validated by the receiver reproducing `confirmed_[n+1]` and accepting the confirmation_tag.

### N7. `GenerateUpdatePath` must skip `newlyAdded` — RFC 9420 §7.5 (verified mandate; receiver already does)
The receiver's `ProcessUpdatePath` (Plan 8, `treekem.go`) **already** skips `newlyAdded` leaves when indexing the ciphertext list (a sender "MAY omit encrypted path secrets for newly-added members"). The **committer's `GenerateUpdatePath` must apply the same skip** — otherwise the sender's ciphertext list and the receiver's index are asymmetric. Honest validation note: in the simple **grow-right** topologies the round-trip exercises (committer at leaf 0; Adds append new leaves to the right), newly-added members land in copath nodes that **no existing member decrypts at**, so convergence holds **with or without** the skip — the simple tests do not isolate it. The skip is nonetheless **load-bearing** in the **gap-fill** topology (a high-index committer whose Add fills a *blank* leaf — e.g. a previously-removed slot — that shares a copath resolution with an existing member ordered after the new leaf): there the index is off-by-one without the skip. **Task 5 includes an explicit gap-fill test.** The extension is purely additive for the existing `treekem.json` KAT (callers pass `newlyAdded=nil` → empty skip set → unchanged bytes). The new signature also returns the per-node path secrets (N5):
```go
func (t *RatchetTree) GenerateUpdatePath(senderLeaf uint32, leafSecret []byte, signer crypto.Signer, groupID []byte, newlyAdded []uint32, mkGroupContext func(treeHash []byte) ([]byte, error)) (*UpdatePath, []byte, map[uint32][]byte, error)
```

### N8. Committer state-commit + application sender ratchet (RFC 9420 §6.3.1 / §9) — verified
- **State-commit** (mirror `ProcessCommit`'s tail): `g.tree=wt`; `g.groupContext=newGC`; `g.epoch=es`; `g.initSecret=es.InitSecret`; `g.interim=InterimTranscriptHash(suite, confirmed, confTag)`; rebuild `g.priv = NewTreeKEMPrivate(ownLeaf, DeriveKeyPair(DeriveSecret(leafSecret,"node"))) + AddPathSecret(node, ps)` for each `pathSecretByNode` entry; `g.secretTree = NewSecretTree(suite, wt.LeafCount(), es.EncryptionSecret)`; record the resumption PSK history entry; **reset `g.appGeneration = 0`** (new epoch ⇒ fresh ratchet).
- **Application messages:** `ProtectApplication(plaintext)` builds `fc = {GroupID, Epoch=current, Sender={member, ownLeaf}, ContentType=application, Content: plaintext}`, samples a random 4-byte `reuse_guard`, and calls `framing.ProtectPrivate(suite, g.signer, &g.groupContext, g.secretTree, g.epoch.SenderDataSecret, fc, g.appGeneration, guard, paddingSize, nil)`, then **increments `g.appGeneration`** (the per-epoch, per-sender monotonic counter; §9.1). The result is wrapped as `{WireFormat: private, Private: &pm}`. `UnprotectApplication(msg)` parses the PrivateMessage and calls `framing.UnprotectPrivate(suite, sigPub, &g.groupContext, g.secretTree, g.epoch.SenderDataSecret, *m.Private)` where `sigPub(leaf)` reads `g.tree.LeafNodeAt(leaf).SignatureKey`; the **generation is read from the encrypted sender_data**, so the receiver is stateless w.r.t. generation (the existing `SecretTree.KeyNonce` re-derives from generation 0 — correct for now; forward-secrecy deletion of consumed keys is a documented production TODO, same caveat the `secrettree.go` comment already carries). Validated: Alice→Bob application plaintext decrypts exactly at a converged epoch.

### N9. Ordering & reuse facts
The commit is **always** a PublicMessage with `sender_type=member` (the passive `ProcessCommit` rejects non-public commits). `applyProposals` enforces §12.3 order (Update → Remove → Add → GroupContextExtensions). Build `cm.Proposals` in delivery order; bucketing is internal to `applyProposals`. By-reference inclusion uses `prop.Ref(suite)` = `RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent)` — the **AuthenticatedContent bytes**, matching the cache key `ProcessCommit` computes.

---

## File structure

| File | Action | Contents |
| --- | --- | --- |
| `mls/cipher/labeled.go` (or `suite.go`) | Edit | `Suite.SignaturePublicKey(signer crypto.Signer) ([]byte, error)` — ed25519 raw / ecdsa-P256 uncompressed. |
| `mls/cipher/labeled_test.go` | Edit | `SignaturePublicKey(signer)` verifies `SignWithLabel(signer,…)` for both registered suites. |
| `mls/tree/generate.go` | Create | `NewRatchetTree(suite, leaf)`, `SignLeafNode(suite, signer, *ln, groupID, leafIndex)`. |
| `mls/tree/treekem.go` | Edit | `GenerateUpdatePath` — add `newlyAdded []uint32` param (skip §7.5) + return `map[uint32][]byte` path secrets. |
| `mls/tree/treekem_test.go`, `treekem_kat_test.go` | Edit | Update the 2 `GenerateUpdatePath` call sites (`nil` newlyAdded, capture map with `_`). |
| `mls/tree/generate_test.go` | Create | `NewRatchetTree` single-leaf shape + tree-hash; `SignLeafNode` round-trips `VerifyLeafSignatures`; `GenerateUpdatePath` skip unit. |
| `mls/framing/generate.go` | Create | `SignCommit`, `AssembleCommitPublic` (N6). |
| `mls/framing/generate_test.go` | Create | `SignCommit` confirmedInput == `SplitAuthenticatedContent`; `AssembleCommitPublic` → `UnprotectPublic` round-trips. |
| `mls/group/keypackage_gen.go` | Create | `NewKeyPackage(suite, cred, signer) (KeyPackage, initPriv, leafPriv []byte, err)` + `EncodeKeyPackageMessage`. |
| `mls/group/create.go` | Create | `NewGroup(suite, groupID, cred, signer) (*Group, err)`. |
| `mls/group/propose.go` | Create | `ProposeAdd/ProposeUpdate/ProposeRemove/ProposeGroupContextExtensions` + `frameProposal` → PublicMessage. |
| `mls/group/commit_gen.go` | Create | `Commit(opt CommitOptions) (commit []byte, welcome []byte, err error)`. |
| `mls/group/welcome_gen.go` | Create | `buildWelcome(...)` helper used by `Commit`. |
| `mls/group/application.go` | Create | `ProtectApplication`/`UnprotectApplication` + `appGeneration` field + reset on epoch change. |
| `mls/group/group.go` | Edit | Add `appGeneration uint32` to `Group`; reset it in `ProcessCommit` and `JoinFromWelcome` (epoch change). |
| `mls/group/keypackage_gen_test.go` | Create | generated KP verifies + parses. |
| `mls/group/active_test.go` | Create | the full self-round-trip gate (create→commit(Add)→join; 3rd member; path-only by non-creator; Update; Remove; gap-fill; application). |

---

## Task 0: `cipher.Suite.SignaturePublicKey`

**TDD.** Generation needs `LeafNode.SignatureKey` bytes from a `crypto.Signer`; the suite knows the scheme.

- [ ] **`mls/cipher/labeled.go`** (or `suite.go`):
  ```go
  // SignaturePublicKey serializes signer's public key in the suite's
  // SignaturePublicKey encoding (RFC 9420 §5.1.2): Ed25519 raw 32 bytes;
  // ECDSA-P256 the uncompressed SEC1 point. The bytes are what VerifyWithLabel expects.
  func (s Suite) SignaturePublicKey(signer crypto.Signer) ([]byte, error) {
      switch s.Sig {
      case SigEd25519:
          pub, ok := signer.Public().(ed25519.PublicKey)
          if !ok { return nil, errUnsupportedScheme }
          return append([]byte(nil), pub...), nil
      case SigECDSAP256:
          pub, ok := signer.Public().(*ecdsa.PublicKey)
          if !ok { return nil, errUnsupportedScheme }
          return elliptic.Marshal(elliptic.P256(), pub.X, pub.Y), nil //nolint:staticcheck — matches ParseUncompressedPublicKey in verifyClassical
      default:
          return nil, errUnsupportedScheme
      }
  }
  ```
- [ ] **`labeled_test.go`:** for each registered suite, build a signer (ed25519 seed / ecdsa raw), `pub, _ := suite.SignaturePublicKey(signer)`, `sig, _ := suite.SignWithLabel(signer, "X", msg)`, assert `suite.VerifyWithLabel(pub, "X", msg, sig)`.
- [ ] `nix develop -c go test ./mls/cipher/`; `go vet`/`gofmt` clean.
- [ ] **Commit:** `feat(cipher): Suite.SignaturePublicKey — serialize a signer's public key for LeafNode.SignatureKey`.

---

## Task 1: `tree` generation primitives + `GenerateUpdatePath` newlyAdded skip

**TDD.** Add the two missing tree builders and make `GenerateUpdatePath` symmetric with `ProcessUpdatePath` (N7).

- [ ] **`mls/tree/generate.go`:**
  ```go
  // NewRatchetTree builds a single-leaf tree holding leaf at index 0 (group creation, RFC 9420 §11).
  func NewRatchetTree(suite cipher.Suite, leaf LeafNode) *RatchetTree {
      l := leaf
      return &RatchetTree{suite: suite, nodes: []*Node{{Leaf: &l}}}
  }

  // SignLeafNode signs ln in place under "LeafNodeTBS" (RFC 9420 §7.2). For
  // key_package source, groupID/leafIndex are ignored; for update/commit they are
  // appended to the TBS.
  func SignLeafNode(suite cipher.Suite, signer crypto.Signer, ln *LeafNode, groupID []byte, leafIndex uint32) error {
      tbs, err := ln.tbs(groupID, leafIndex)
      if err != nil { return err }
      sig, err := suite.SignWithLabel(signer, "LeafNodeTBS", tbs)
      if err != nil { return err }
      ln.Signature = sig
      return nil
  }
  ```
- [ ] **`mls/tree/treekem.go`** — change `GenerateUpdatePath` to the N7 signature. Concretely: add the `newlyAdded []uint32` parameter; build `newlyAddedSet := map[uint32]bool{}` keyed by `2*li`; when snapshotting each copath child's resolution into `resPubs[k]`, **skip** entries `d` where `newlyAddedSet[d]` (do not append their pubkey); accumulate `pathSecretByNode[fdp[k]] = pathSecrets[k]`; return `(*UpdatePath, commitSecret, pathSecretByNode, nil)`. (The validated full body is in the planning throwaway `GenerateUpdatePath2`; copy it verbatim, renaming to `GenerateUpdatePath`.)
- [ ] **Update the two existing callers** (`treekem_test.go:215`, `treekem_kat_test.go:183`): `newUP, newCommit, _, err := …GenerateUpdatePath(up.Sender, leafSecret, signer, groupID, nil, mkGC)`.
- [ ] **`mls/tree/generate_test.go`:** `NewRatchetTree` → `Width()==1`, `LeafNodeAt(0)` matches, `RootTreeHash` non-error; `SignLeafNode` a key_package leaf then `VerifyLeafSignatures(nil)` accepts a 1-leaf tree built from it; a focused **gap-fill skip** unit: build a 4-leaf tree, `RemoveLeaf(1)`, `AddLeaf(newLeaf)` (refills leaf 1), `GenerateUpdatePath(leaf3, …, newlyAdded=[1], …)`, and assert the produced `UpdatePath` omits the ciphertext for the refilled leaf at the shared copath node (its `EncryptedPathSecret` count == resolution size − 1).
- [ ] `nix develop -c go test ./mls/tree/` (existing `treekem.json` KAT must still pass); `go vet`/`gofmt` clean.
- [ ] **Commit:** `feat(tree): NewRatchetTree + SignLeafNode; GenerateUpdatePath honors newlyAdded (RFC 9420 §7.5) and returns path secrets`.

---

## Task 2: `framing` commit-assembly helpers

**TDD.** Expose the two helpers that let `group` run the §6.1/§8.2 circular dance (N6).

- [ ] **`mls/framing/generate.go`:** add `SignCommit` and `AssembleCommitPublic` exactly as in N6.
- [ ] **`mls/framing/generate_test.go`:**
  - Build a member `FramedContent` (commit) + a `GroupContext` + a signer; `confirmedInput, sig, _ := SignCommit(...)`. Independently construct `ac := AuthenticatedContent{public, fc, {Signature: sig, ConfirmationTag: make([]byte, suite.HashLen())}}`, `acBytes, _ := ac.MarshalMLS()`, `wantInput, _, _ := keyschedule.SplitAuthenticatedContent(suite, acBytes)`; assert `bytes.Equal(confirmedInput, wantInput)`.
  - `pm, _ := AssembleCommitPublic(suite, &gc, membershipKey, fc, sig, confTag)`; `ac2, err := UnprotectPublic(suite, sigPub, &gc, membershipKey, pm)`; assert no error and `ac2.Auth.ConfirmationTag == confTag`.
- [ ] `nix develop -c go test ./mls/framing/`; `go vet`/`gofmt` clean.
- [ ] **Commit:** `feat(framing): SignCommit + AssembleCommitPublic — expose FramedContentTBS signing + membership-tag assembly for commit generation`.

---

## Task 3: KeyPackage generation

**TDD.** A client publishes a KeyPackage so others can Add it (N2).

- [ ] **`mls/group/keypackage_gen.go`:**
  ```go
  // NewKeyPackage generates an init key, a leaf HPKE key, a signed key_package
  // LeafNode and a signed KeyPackage (RFC 9420 §10). It returns the KeyPackage and
  // the two private keys the holder keeps (init_priv for Welcome decryption,
  // leaf_priv for TreeKEM). caps defaults are filled if zero.
  func NewKeyPackage(suite cipher.Suite, cred tree.Credential, signer crypto.Signer, lifetime tree.Lifetime) (KeyPackage, []byte, []byte, error) {
      initPriv, initPub, err := suite.GenerateHPKEKeyPair()
      if err != nil { return KeyPackage{}, nil, nil, err }
      leafPriv, leafPub, err := suite.GenerateHPKEKeyPair()
      if err != nil { return KeyPackage{}, nil, nil, err }
      sigPub, err := suite.SignaturePublicKey(signer)
      if err != nil { return KeyPackage{}, nil, nil, err }
      ln := tree.LeafNode{
          EncryptionKey: leafPub, SignatureKey: sigPub, Credential: cred,
          Capabilities: defaultCapabilities(suite),
          LeafNodeSource: tree.LeafNodeSourceKeyPackage, Lifetime: &lifetime,
      }
      if err := tree.SignLeafNode(suite, signer, &ln, nil, 0); err != nil { return KeyPackage{}, nil, nil, err }
      kp := KeyPackage{Version: tree.ProtocolVersionMLS10, CipherSuite: suite.ID, InitKey: initPub, LeafNode: ln}
      tbs, err := kp.tbsBytes()
      if err != nil { return KeyPackage{}, nil, nil, err }
      sig, err := suite.SignWithLabel(signer, "KeyPackageTBS", tbs)
      if err != nil { return KeyPackage{}, nil, nil, err }
      kp.Signature = sig
      return kp, initPriv, leafPriv, nil
  }

  func defaultCapabilities(suite cipher.Suite) tree.Capabilities {
      return tree.Capabilities{
          Versions: []tree.ProtocolVersion{tree.ProtocolVersionMLS10},
          CipherSuites: []cipher.CipherSuite{suite.ID},
          Credentials: []tree.CredentialType{tree.CredentialTypeBasic},
      }
  }
  ```
  (`kp.tbsBytes()` is unexported but in-package.)
- [ ] **`keypackage_gen_test.go`:** `kp, _, _, _ := NewKeyPackage(...)`; assert `kp.VerifySignature(suite)` true and `kp.LeafNode` leaf-signature verifies; `EncodeKeyPackageMessage`→`DecodeKeyPackageMessage` round-trips equal.
- [ ] `nix develop -c go test ./mls/group/ -run KeyPackageGen`; `go vet`/`gofmt` clean.
- [ ] **Commit:** `feat(group): NewKeyPackage — generate + sign an init key, leaf node and KeyPackage (RFC 9420 §10)`.

---

## Task 4: Group creation

**TDD.** A single-member group at epoch 0 (N1).

- [ ] **`mls/group/group.go`** — add `appGeneration uint32` to `Group`; in `JoinFromWelcome` and `ProcessCommit` set `g.appGeneration = 0` at the epoch transition (it costs nothing for the passive path and is required by `application.go`).
- [ ] **`mls/group/create.go`:**
  ```go
  // NewGroup creates a one-member group at epoch 0 with creator at leaf 0 (RFC 9420 §11/§8).
  func NewGroup(suite cipher.Suite, groupID []byte, cred tree.Credential, signer crypto.Signer, lifetime tree.Lifetime) (*Group, error) {
      kp, _, leafPriv, err := NewKeyPackage(suite, cred, signer, lifetime)
      if err != nil { return nil, err }
      rt := tree.NewRatchetTree(suite, kp.LeafNode)
      treeHash, err := rt.RootTreeHash()
      if err != nil { return nil, err }
      gc0 := keyschedule.GroupContext{
          Version: tree.ProtocolVersionMLS10, CipherSuite: suite.ID, GroupID: groupID,
          Epoch: 0, TreeHash: treeHash, ConfirmedTranscriptHash: nil, // zero-length — N1/§8.2
      }
      gc0Bytes, err := gc0.MarshalMLS()
      if err != nil { return nil, err }
      es0, err := keyschedule.DeriveEpochSecrets(suite, make([]byte, suite.HashLen()), nil, nil, gc0Bytes)
      if err != nil { return nil, err }
      st, err := keyschedule.NewSecretTree(suite, 1, es0.EncryptionSecret)
      if err != nil { return nil, err }
      return &Group{
          suite: suite, groupContext: gc0, tree: rt,
          priv: tree.NewTreeKEMPrivate(0, leafPriv), epoch: es0, secretTree: st,
          interim: nil, initSecret: es0.InitSecret, ownLeaf: 0, signer: signer,
          externalPSKs: map[string][]byte{}, resumptionPSKHistory: map[uint64][]byte{0: es0.ResumptionPSK},
      }, nil
  }
  ```
  (NB: a real caller will usually keep the `init_priv` too — for symmetry expose a richer constructor later; the creator never uses its own Welcome path so dropping `init_priv` here is fine.)
- [ ] **`active_test.go`** (start of the gate): `g, _ := NewGroup(...)`; assert `g.Epoch()==0`, `len(g.EpochAuthenticator())==suite.HashLen()`, `Exporter` non-error. (Full validation arrives in Task 6.)
- [ ] `nix develop -c go test ./mls/group/ -run NewGroup`; `go vet`/`gofmt` clean.
- [ ] **Commit:** `feat(group): NewGroup — single-member group at epoch 0 (RFC 9420 §11/§8)`.

---

## Task 5: Proposal generation

**TDD.** Build the four proposal bodies and (optionally) frame them as PublicMessages (N3).

- [ ] **`mls/group/propose.go`:**
  ```go
  // ProposeAdd builds a bare Add proposal from a received KeyPackage (RFC 9420 §12.1.1).
  func ProposeAdd(kp KeyPackage) Proposal { return Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: kp}} }
  // ProposeRemove builds a bare Remove proposal (RFC 9420 §12.1.3).
  func ProposeRemove(leaf uint32) Proposal { return Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: leaf}} }
  // ProposeGroupContextExtensions builds a bare GCE proposal (RFC 9420 §12.1.7).
  func ProposeGroupContextExtensions(ext []tree.Extension) Proposal {
      return Proposal{Type: ProposalTypeGroupContextExtensions, GroupContextExtensions: &GroupContextExtensions{Extensions: ext}}
  }
  // ProposeUpdate generates a fresh leaf key and an update-source LeafNode for g's
  // own leaf, returning the proposal and the new leaf_priv the proposer must keep
  // until the proposal is committed (RFC 9420 §12.1.2).
  func (g *Group) ProposeUpdate() (Proposal, []byte, error) {
      leafPriv, leafPub, err := g.suite.GenerateHPKEKeyPair()
      if err != nil { return Proposal{}, nil, err }
      cur, err := g.tree.LeafNodeAt(g.ownLeaf)
      if err != nil { return Proposal{}, nil, err }
      ln := cur
      ln.EncryptionKey = leafPub
      ln.LeafNodeSource = tree.LeafNodeSourceUpdate
      ln.Lifetime = nil; ln.ParentHash = nil
      if err := tree.SignLeafNode(g.suite, g.signer, &ln, g.groupContext.GroupID, g.ownLeaf); err != nil { return Proposal{}, nil, err }
      return Proposal{Type: ProposalTypeUpdate, Update: &Update{LeafNode: ln}}, leafPriv, nil
  }

  // FrameProposal frames a bare Proposal as a member PublicMessage (RFC 9420 §6.2),
  // returning the MLSMessage bytes (for by-reference delivery).
  func (g *Group) FrameProposal(p Proposal) ([]byte, error) {
      body, err := p.MarshalMLS()
      if err != nil { return nil, err }
      fc := framing.FramedContent{GroupID: g.groupContext.GroupID, Epoch: g.groupContext.Epoch,
          Sender: framing.Sender{Type: framing.SenderTypeMember, LeafIndex: g.ownLeaf},
          ContentType: framing.ContentTypeProposal, Content: body}
      gc := g.groupContext
      pm, err := framing.ProtectPublic(g.suite, g.signer, &gc, g.epoch.MembershipKey, fc, nil)
      if err != nil { return nil, err }
      return (framing.MLSMessage{Version: tree.ProtocolVersionMLS10, WireFormat: framing.WireFormatPublicMessage, Public: &pm}).MarshalMLS()
  }
  ```
- [ ] **`active_test.go`** (add): generate a `ProposeAdd`, `FrameProposal`, parse it back via `MLSMessage.UnmarshalMLS`+`UnprotectPublic`, assert the recovered `Proposal` equals and `prop.Ref(suite)` is stable.
- [ ] `nix develop -c go test ./mls/group/ -run Propose`; `go vet`/`gofmt` clean.
- [ ] **Commit:** `feat(group): proposal generation (Add/Update/Remove/GCE) + PublicMessage framing (RFC 9420 §12.1/§6.2)`.

---

## Task 6: Commit + Welcome generation — the self-round-trip gate

**TDD.** The keystone. Write the gate first (it will not compile), then implement `Commit`/`buildWelcome` per N4/N5/N8.

- [ ] **`mls/group/commit_gen.go`:**
  ```go
  // CommitOptions selects the proposals to include in a Commit.
  type CommitOptions struct {
      ByValue     []Proposal // proposals to inline (e.g. Adds the committer originates)
      ByReference [][]byte    // previously-delivered PublicMessage proposals, included by reference
  }

  // Commit applies the options' proposals to a cloned tree (RFC 9420 §12.3 order),
  // generates an UpdatePath, advances the key schedule to epoch n+1, frames the
  // commit as a PublicMessage, builds a Welcome for newly-added members, and
  // advances g to epoch n+1. It returns the commit MLSMessage and (if any members
  // were added) the Welcome MLSMessage (RFC 9420 §12.4/§12.4.3.1).
  func (g *Group) Commit(opt CommitOptions) (commit []byte, welcome []byte, err error)
  ```
  Implementation (all verified):
  1. `wt, _ := g.tree.Clone()`. Build `cm Commit`: cache `opt.ByReference` exactly as `ProcessCommit` does (`UnmarshalMLS`→`UnprotectPublic` with current-epoch keys→`prop.Ref`), appending `ProposalOrRef{reference}`; append `opt.ByValue` as `ProposalOrRef{proposal}`. Keep the **added KeyPackages in commit order** for the Welcome.
  2. `resumptionPSKs` map (current epoch + history, like `ProcessCommit`); `provisionalExt, epochPSKs, _, newlyAdded, _ := applyProposals(g.suite, wt, cm, cache, g.groupContext.Extensions, g.externalPSKs, resumptionPSKs, g.groupContext.GroupID, g.ownLeaf)`.
  3. `leafSecret := make([]byte, suite.HashLen()); crypto/rand.Read(leafSecret)`. Build `encGC`/`mkGC` (OLD confirmed) and call the new `wt.GenerateUpdatePath(g.ownLeaf, leafSecret, g.signer, g.groupContext.GroupID, newlyAdded, mkGC)` → `up, commitSecret, pathSecretByNode`. `cm.Path = up`.
  4. The §6.1/§8.2 dance (N4 step 3): `SignCommit` → `confirmed` → `newGC` → `DeriveEpochSecrets` → `confTag` → `AssembleCommitPublic`; wrap as PublicMessage MLSMessage.
  5. If `len(newlyAdded) > 0`: `welcome = buildWelcome(...)` (Task: `welcome_gen.go`).
  6. State-commit per N8 (incl. `g.appGeneration = 0`).
- [ ] **`mls/group/welcome_gen.go`:** `buildWelcome(es, newGC, wt, committerLeaf, signer, newlyAdded, addedKPs, pathSecretByNode, epochPSKIDs)` → the N5 procedure, returning `EncodeWelcomeMessage(w)`. The `ratchet_tree` extension data is `wt.MarshalMLS()`; per-member `GroupSecrets` carry `es.JoinerSecret` + the common-ancestor path secret (+ the commit's PSK ids in `gs.PSKs`).
- [ ] **`mls/group/active_test.go`** — the strict gate (validated end-to-end during planning):
  - **T1 create+Add:** Alice `NewGroup`; `Commit({ByValue: [ProposeAdd(bobKP)]})` → Bob `JoinFromWelcome`. Assert `bytes.Equal(alice.EpochAuthenticator(), bob.EpochAuthenticator())` **and** `Exporter("x", ctx, 32)` byte-equal. Both at epoch 1.
  - **T2 third member:** Alice `Commit(Add(carolKP))`; Bob `ProcessCommit(nil, commit)`; Carol `JoinFromWelcome`. Assert all three byte-equal (epoch_authenticator + exporter) at epoch 2. (Exercises the `newlyAdded` path + Bob processing + Carol's installed path_secret.)
  - **T3 non-creator committer:** Bob `Commit({})` (path-only, no proposals); Alice + Carol `ProcessCommit`. Assert all three converge at epoch 3.
  - **T4 Remove:** Alice `Commit(Remove(carol.ownLeaf))`; Bob `ProcessCommit`. Assert Alice+Bob converge at epoch 4.
  - **T5 Update:** Bob `ProposeUpdate()`→`FrameProposal`; Alice `Commit({ByReference: [bobUpdateMsg]})`; Bob `ProcessCommit([bobUpdateMsg], commit)`. Assert convergence. (Bob installs his pending update leaf key on commit — track the proposer leaf_priv; if out of scope for this gate, use an Update generated by the committer's own path instead and note the proposer-key-install TODO.)
  - **T6 gap-fill skip (N7):** grow to ≥4 members, `Remove` a middle leaf, then `Commit(Add(newKP))` from a **high-index** committer so the Add refills the gap into a shared copath; a mid-index existing member `ProcessCommit`; assert convergence. (This is the topology that fails without the §7.5 skip.)
  - **Guard:** assert ≥1 suite executed; skip unregistered suites.
- [ ] `nix develop -c go test ./mls/group/ -run Active -v`; `go vet`/`gofmt` clean.
- [ ] **Commit:** `feat(group): Commit + Welcome/GroupInfo generation — self-round-trip with ProcessCommit/JoinFromWelcome (RFC 9420 §12.4/§12.4.3.1)`.

---

## Task 7: Application messages

**TDD.** PrivateMessage application encryption with a stateful per-epoch sender ratchet (N8).

- [ ] **`mls/group/application.go`:**
  ```go
  // ProtectApplication encrypts plaintext as an application PrivateMessage from g's
  // own leaf, advancing g's per-epoch sender ratchet (RFC 9420 §6.3/§9).
  func (g *Group) ProtectApplication(plaintext, authenticatedData []byte) ([]byte, error) {
      fc := framing.FramedContent{GroupID: g.groupContext.GroupID, Epoch: g.groupContext.Epoch,
          Sender: framing.Sender{Type: framing.SenderTypeMember, LeafIndex: g.ownLeaf},
          AuthenticatedData: authenticatedData, ContentType: framing.ContentTypeApplication, Content: plaintext}
      var guard [4]byte
      if _, err := rand.Read(guard[:]); err != nil { return nil, err }
      gc := g.groupContext
      pm, err := framing.ProtectPrivate(g.suite, g.signer, &gc, g.secretTree, g.epoch.SenderDataSecret, fc, g.appGeneration, guard, 0, nil)
      if err != nil { return nil, err }
      g.appGeneration++
      return (framing.MLSMessage{Version: tree.ProtocolVersionMLS10, WireFormat: framing.WireFormatPrivateMessage, Private: &pm}).MarshalMLS()
  }

  // UnprotectApplication decrypts an application PrivateMessage and returns the
  // plaintext + authenticated_data (RFC 9420 §6.3). The generation is read from the
  // encrypted sender_data, so no receiver ratchet state is needed here.
  func (g *Group) UnprotectApplication(msg []byte) (plaintext, authenticatedData []byte, err error) {
      var m framing.MLSMessage
      if err := m.UnmarshalMLS(msg); err != nil { return nil, nil, err }
      if m.WireFormat != framing.WireFormatPrivateMessage || m.Private == nil { return nil, nil, errors.New("group: not a PrivateMessage") }
      if m.Private.ContentType != framing.ContentTypeApplication { return nil, nil, errors.New("group: not an application message") }
      gc := g.groupContext
      sigPub := func(leaf uint32) ([]byte, error) {
          ln, err := g.tree.LeafNodeAt(leaf); if err != nil { return nil, err }; return ln.SignatureKey, nil
      }
      ac, err := framing.UnprotectPrivate(g.suite, sigPub, &gc, g.secretTree, g.epoch.SenderDataSecret, *m.Private)
      if err != nil { return nil, nil, err }
      return ac.Content.Content, ac.Content.AuthenticatedData, nil
  }
  ```
  Note in the doc comment: `SecretTree.KeyNonce` re-derives from generation 0 on each call (O(generation)); deleting consumed ratchet keys for forward secrecy is a production follow-up (same caveat as `keyschedule/secrettree.go`).
- [ ] **`active_test.go`** (add): at a converged multi-member epoch, Alice `ProtectApplication("hello", nil)` → Bob `UnprotectApplication` returns `"hello"`; send a 2nd message and assert it also decrypts (generation advanced); assert a tampered ciphertext fails to open.
- [ ] `nix develop -c go test ./mls/group/ -run Application`; full `nix develop -c go test ./mls/...`; `go vet`/`gofmt` clean.
- [ ] **Commit:** `feat(group): ProtectApplication/UnprotectApplication — application messages over the secret-tree ratchet (RFC 9420 §6.3/§9)`.

---

## Definition of Done

- [ ] `nix develop -c go test ./mls/...` passes, including **all 15 official KATs** (unchanged) **and** the new `active_test.go` self-round-trip gate (T1–T6 + application), each with executed-case guards and unregistered-suite skips.
- [ ] `nix develop -c go vet ./mls/...` clean; `nix develop -c gofmt -l mls/` empty; `go build ./...` clean (no import cycle — `group` remains the leaf importer).
- [ ] After every `Commit`, the committer's `epoch_authenticator` **and** `MLSExporter(label, context, length)` output are **byte-equal** to a receiver's via `ProcessCommit` and a newly-added member's via `JoinFromWelcome`, at every epoch (T1–T6).
- [ ] `Commit` builds the **two GroupContexts** identical to `ProcessCommit` — `encGC` (OLD `confirmed_transcript_hash`) for the UpdatePath HPKE context via `mkGroupContext`, `newGC` (NEW `confirmed_transcript_hash`) for `DeriveEpochSecrets`/confirmation_tag — both at `epoch=n+1` with the post-path tree hash; the membership_tag uses the **current** epoch's `gc_n` + `membership_key_[n]`.
- [ ] `GenerateUpdatePath` **omits** path-secret ciphertexts for `newlyAdded` leaves (§7.5), symmetric with `ProcessUpdatePath`; the gap-fill test (T6) exercises and locks this.
- [ ] The Welcome uses HPKE label **`"Welcome"`** with context = `encrypted_group_info` for `GroupSecrets`, `WelcomeKeyNonce` + **empty AAD** for the GroupInfo, the `ratchet_tree` (0x0002) extension carrying the post-commit tree, and a `"GroupInfoTBS"`-signed GroupInfo; each added member's `GroupSecrets.path_secret` is the secret at `commonAncestor(2·added, 2·committer)`.
- [ ] `NewKeyPackage`/`NewGroup` produce objects accepted by the existing passive path; epoch-0 transcript hashes are the zero-length octet string (§8.2).
- [ ] `ProtectApplication`/`UnprotectApplication` round-trip at a converged epoch; the sender ratchet advances per message and resets to generation 0 on every epoch change.
- [ ] One commit per task, each with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.

---

## Notes — downstream plans

This plan completes the `mls/` engine for both directions (active + passive). The remaining work is integration:

- **Plan 10 (IronCore integration):** VNI ↔ GroupID mapping (`GroupID = encode(VNI)`, opaque to `mls/`); **`Exporter` → ESP SA derivation** (`K_group = Group.Exporter("ironcore-esp", VNI‖epoch, L)`, `SPI = f(VNI, epoch)`, per-sender nonce-salt `HKDF(K_group, "esp-sender"‖leaf_index)` for disjoint AES-GCM nonce spaces, make-before-break SA install); credential adapters (SPIFFE-SVID + generic-PKI x509 `CredentialValidator`s binding the mTLS identity to the MLS leaf credential); the membership controller as an authorized **external proposer**; and **external-commit** generation/join (`NewMemberCommit` via the GroupInfo `external_pub` (0x0004) extension + an `ExternalInit` proposal) — deferred here because it needs the external_pub-extension byte format pinned and an `external_senders` policy, and would bloat this plan. The `external_pub` extension scaffolding (its serialization in `buildWelcome`) is the natural first step of Plan 10.
- **Plan 11 (Sequencer):** the `DeliveryService`/`Ordering` adapter enforcing one accepted Commit per `(group, epoch)` (single linearization point), exposing `epoch_authenticator` for active fork detection, with the B1 fenced single-writer default; the lowest-index member as designated committer driving `Commit` on VNI-placement events.
