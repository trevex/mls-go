# Group Engine — JoinFromWelcome, ProcessCommit & passive-client KAT (Plan 8b of 8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Depends on Plan 8a** (`2026-06-26-group.md`) — the `mls/group` protocol objects (KeyPackage/Proposal/Commit/GroupInfo/Welcome) and the keyschedule/framing/tree helpers it adds must be merged first.

**Goal:** Build the **MLS group state machine** that passes the gold-standard end-to-end KATs. Concretely, a `Group` value (suite, group context, ratchet tree, TreeKEM private state, epoch secrets, transcript hashes, own leaf index) with two operations: **`JoinFromWelcome`** — decrypt a `Welcome` (GroupSecrets via HPKE label `"Welcome"`; GroupInfo via the welcome key/nonce), install the ratchet tree (GroupInfo `ratchet_tree` extension or an externally supplied tree), verify the GroupInfo signature + `confirmation_tag`, derive the joined epoch's secrets, and reach the **`initial_epoch_authenticator`** (gated by `passive-client-welcome.json`); and **`ProcessCommit`** — cache by-reference proposals from a per-epoch handshake list, parse the `Commit`, resolve its `ProposalOrRef`s, apply Update/Remove/Add/GroupContextExtensions in RFC §12.3 order, process the `UpdatePath`, advance the §8 key schedule with `commit_secret`+`psk_secret`, verify the `confirmation_tag`, chain the transcript hashes, and reproduce each epoch's **`epoch_authenticator`** (gated by `passive-client-handling-commit.json` and the `passive-client-random.json` stress vector). It also lands the `tree` mutation helpers the engine needs and the library **ports** (`DeliveryService`/`CredentialValidator`/`StateStore`/`Clock` interfaces + an in-memory `StateStore` + a basic `CredentialValidator`).

**Architecture:** All new code lives in **`mls/group`** (begun in Plan 8a) plus a handful of justified helpers in `mls/tree`. The engine composes every lower layer: `framing` (`UnprotectPublic`/`UnprotectPrivate` to authenticate commits/proposals, `AuthenticatedContent.MarshalMLS` for the transcript), `keyschedule` (`EpochSecretsFromJoiner`/`DeriveEpochSecrets`, `WelcomeKeyNonce`, `PSKSecret`, transcript-hash + confirmation-tag helpers, `SplitAuthenticatedContent`), `tree` (`ParseRatchetTree`, `ProcessUpdatePath`, `Merge`, `RootTreeHash`, the new mutation helpers), `cipher` (HPKE/AEAD/Sign), and the Plan 8a objects. **No import cycle:** unchanged from Plan 8a (`group` is a leaf of the import DAG). The `Group` is a passive *receiver* for these KATs — commit/welcome *generation* is implemented opportunistically (it falls out of the same primitives) but is **not** required by any passive-client vector and may be deferred if it threatens scope.

This plan adds justified helpers to **`mls/tree`** (folded into Task 0): `Clone`, `NodeAt`, `LeafNodeAt`, `LeafCount`, `AddLeaf`, `RemoveLeaf`, `UpdateLeaf`, `FindLeafByEncryptionKey`, and `TreeKEMPrivate.PrivateKeyAt` — the engine must build a tree from the Welcome, apply Add/Remove/Update proposals, clone it to compute the *provisional* tree hash without mutating the live tree, read leaf signature keys for authentication, and rebuild its private path state after a commit. None of these exist yet (the tree package today only parses, hashes, validates, and merges a tree).

**Tech Stack:** Go 1.26 standard library only — `bytes`, `errors`/`fmt`, `crypto/ed25519`/`crypto/ecdsa`/`crypto/ecdh`/`crypto/elliptic` (test-only signer construction). Builds on everything in Plan 8a plus `mls/framing` (`MLSMessage`/`UnprotectPublic`/`UnprotectPrivate`/`AuthenticatedContent`), `mls/keyschedule` (`DeriveEpochSecrets`/`EpochSecretsFromJoiner`, `WelcomeKeyNonce`, `PSKSecret`, `ConfirmedTranscriptHash`/`InterimTranscriptHash`/`ConfirmationTag`/`SplitAuthenticatedContent`), `mls/tree` (`ProcessUpdatePath`/`Merge`/`RootTreeHash`/`ParseRatchetTree` + new helpers), and `mls/internal/katutil`.

**Spec reference:** RFC 9420 §7 (TreeKEM), §8 (key schedule + epoch), §8.2 (transcript hashes), §8.7 (`epoch_authenticator`), §11 (group creation/state), §12.3 (proposal application order), §12.4 (Commit processing), §12.4.3.1 (Welcome/GroupSecrets/GroupInfo). KAT format: <https://github.com/mlswg/mls-implementations/blob/main/test-vectors.md> ("Passive Client").

> **Go invocation convention:** Go is **not** on `PATH`. Every Go command runs through the nix devshell, e.g. `nix develop -c go test ./mls/group/`. Use this form everywhere below.

---

## Design notes (read before implementing)

Every fact below was **verified byte-for-byte during planning** against the live `passive-client-welcome.json` (all 16 registered-suite cases) and `passive-client-handling-commit.json` (suite-1 case 0, both epochs) with throwaway probes that reproduced `initial_epoch_authenticator`, both epochs' `epoch_authenticator`, and every intermediate `confirmation_tag`. The probes were deleted and the working tree left clean. **These are the facts that make or break the passive-client KAT — get them exactly right.**

### N0. `passive-client-*` vector schema (verified)
Top-level case keys: `cipher_suite`, `key_package` (joiner's KeyPackage MLSMessage), `signature_priv`, `encryption_priv`, `init_priv` (joiner private state), `welcome` (the Welcome MLSMessage to join with), `ratchet_tree` (**often `null`** → the tree comes from the GroupInfo `ratchet_tree` extension; non-null → use it directly), `external_psks` (`[{psk_id, psk}]`, hex), `initial_epoch_authenticator`, and `epochs[]`. Each `epochs[i]` has `proposals` (`[hex]` — handshake MLSMessages delivered **before** the commit, to be cached **by reference**), `commit` (the commit MLSMessage), and `epoch_authenticator` (the target after processing this epoch). `passive-client-welcome.json` has `epochs == []` (join only). Suites 1 & 2 are registered; 3–7 are skipped — **guard against zero executed cases**.

For `passive-client-handling-commit.json` case 0 (suite 1): 8-leaf group, joiner lands at **leaf 7**, the joined GroupContext is **epoch 2**, `ratchet_tree` is `null` (tree from GroupInfo ext), `external_psks` empty. Epoch 0's commit is an **empty path-only commit** by leaf 0 (no proposals). Epoch 1's commit carries a **by-value Add proposal** (a 9th member) inside `Commit.proposals` (its `epochs[1].proposals` list is empty). So the engine must handle *both* by-reference (other cases) and by-value (this case) proposals, and the **Add-grows-the-tree** path.

### N1. `JoinFromWelcome` — the exact, verified sequence (RFC 9420 §12.4.3.1 + §8)
1. Parse the `welcome` MLSMessage envelope → `group.Welcome` (`group.DecodeWelcomeMessage`).
2. Parse our `key_package` MLSMessage → `group.KeyPackage`; `ref = kp.Ref(suite)`. Select the `EncryptedGroupSecrets` whose `new_member == ref`.
3. `gsBytes = suite.DecryptWithLabel(init_priv, "Welcome", context = welcome.encrypted_group_info, kem_output, ciphertext)` → `group.GroupSecrets` (`joiner_secret`, optional `path_secret`, `psks`). **The HPKE context is `encrypted_group_info`** (verified).
4. `psk_secret = keyschedule.PSKSecret(suite, resolve(gs.PSKs))`, where each `PreSharedKeyID` (always `psktype=external` here) is resolved against the case's `external_psks` by `psk_id`. No PSKs ⇒ `pskSecret = nil`.
5. `member = suite.Extract(joiner_secret, pskSecret_or_zero)`; `welcomeSecret = DeriveSecret(member, "welcome")`; `wk,wn = keyschedule.WelcomeKeyNonce(suite, welcomeSecret)`; `giBytes = suite.Open(wk, wn, aad=nil, encrypted_group_info)` → **bare** `group.GroupInfo` (`gi.UnmarshalMLS`). **AAD is empty** (verified).
6. Install the ratchet tree: if the case `ratchet_tree` is non-null, `tree.ParseRatchetTree(suite, ratchet_tree)`; else `tree.ParseRatchetTree(suite, gi.RatchetTreeExtension())`.
7. Validate the tree (`VerifyParentHashes`, `VerifyLeafSignatures(gi.GroupContext.GroupID)`); recompute `RootTreeHash()` and require it equals `gi.GroupContext.TreeHash` (binds the tree to the signed GroupContext).
8. Verify the GroupInfo signature: the signer leaf is `tree.LeafNodeAt(gi.Signer)`; `gi.VerifySignature(suite, signerLeaf.SignatureKey)` must be true.
9. Find **own leaf**: `ownLeaf = tree.FindLeafByEncryptionKey(kp.LeafNode.EncryptionKey)`. Build `priv = tree.NewTreeKEMPrivate(ownLeaf, encryption_priv)`; if `gs.PathSecret != nil`, install ancestor keys from the common ancestor of `2*ownLeaf` and `2*gi.Signer` up to the root (`AddPathSecret` with `path_secret`, ratcheting `DeriveSecret(_, "path")` each level — see N4 for the common-ancestor walk).
10. Compute epoch secrets from the joiner secret: `es = keyschedule.EpochSecretsFromJoiner(suite, joiner_secret, pskSecret, gi.GroupContext.MarshalMLS())`.
11. **Verify `confirmation_tag`:** `keyschedule.ConfirmationTag(suite, es.ConfirmationKey, gi.GroupContext.ConfirmedTranscriptHash)` must equal `gi.ConfirmationTag` (verified across all 16 welcome cases).
12. Initialize transcript: `interim = keyschedule.InterimTranscriptHash(suite, gi.GroupContext.ConfirmedTranscriptHash, gi.ConfirmationTag)`.
13. The joined epoch's `epoch_authenticator = es.EpochAuthenticator` — **verified to equal `initial_epoch_authenticator`** for all 16 cases. Store `initSecret = es.InitSecret` (input to the next epoch's key schedule), build the `keyschedule.SecretTree` from `es.EncryptionSecret` (for future application/handshake decryption — unused by the public-message passive-client KAT but part of complete state).

### N2. `ProcessCommit` — the exact, verified sequence (RFC 9420 §12.3/§12.4 + §8.2)
Given the per-epoch `proposals` list and the `commit` MLSMessage, against the current `Group` state (epoch *n*):
1. **Cache by-reference proposals.** For each `proposals[j]`: `framing.MLSMessage.UnmarshalMLS` → `UnprotectPublic`/`UnprotectPrivate` (current epoch's signature keys/membership_key/group_context) → `ac`; parse `group.Proposal` from `ac.Content.Content`; `ref = proposal.Ref(suite)`; record `ref → (proposal, senderLeaf)`. (Validate the sender is an authorized member; for the KAT, accept any member.)
2. **Authenticate the commit.** `m = framing.MLSMessage.UnmarshalMLS(commit)`; require `m.WireFormat == public` (passive-client commits are PublicMessages). `committerLeaf = m.Public.Content.Sender.LeafIndex`; `committerPub = tree.LeafNodeAt(committerLeaf).SignatureKey`; `ac,_ = framing.UnprotectPublic(suite, committerPub, &g.groupContext, g.epoch.MembershipKey, *m.Public)` (verifies membership_tag + `"FramedContentTBS"` signature). Require `ac.Content.Epoch == g.groupContext.Epoch`.
3. **Parse the Commit.** `cm = group.DecodeCommit(ac.Content.Content)`.
4. **Resolve proposals in application order (§12.3).** For each `ProposalOrRef`: by-value → use `por.Proposal`; by-reference → look up `por.Reference` in the cache (error if missing). Then bucket by type and apply **in this order on a working clone** `wt = g.tree.Clone()`:
   1. **Update**: `wt.UpdateLeaf(senderLeaf_of_that_update, update.LeafNode)` (the proposer's own leaf; for a committer's own update the path supersedes — but Update proposals come from *other* members).
   2. **Remove**: `wt.RemoveLeaf(remove.Removed)` (blank the leaf + its direct path; truncate trailing blanks at the array tail per §7.x — `RemoveLeaf` handles both).
   3. **Add**: for each `add.KeyPackage`, `wt.AddLeaf(add.KeyPackage.LeafNode)` (fill the leftmost blank leaf or extend the tree by one leaf; new member's direct path is blanked, and the new leaf is added to each ancestor's `unmerged_leaves`). Collect added KeyPackages (a *real* group would Welcome them; the passive client only needs the tree shape).
   4. **GroupContextExtensions**: replace `provisionalExtensions = gce.Extensions` (else carry `g.groupContext.Extensions` forward).
   5. **PSK**: collect each `PreSharedKey.PSK` id into the epoch's PSK list (resolved via `external_psks`/resumption).
   Track whether any proposal forbids a path-less commit (Add/Update/Remove require a path; the KAT always supplies one when needed).
5. **Process the UpdatePath (if `cm.Path != nil`).** This is the byte-accuracy crux (N3):
   - Compute the **provisional confirmed transcript hash** first (needed for step 6 but NOT for path encryption): `acBytes = ac.MarshalMLS()`; `confirmedInput, confTag = keyschedule.SplitAuthenticatedContent(suite, acBytes)`; `confirmed = keyschedule.ConfirmedTranscriptHash(suite, g.interim, confirmedInput)`. (`confTag` also equals `ac.Auth.ConfirmationTag`.)
   - Build the **encryption GroupContext** `encGC` = current GroupContext with `Epoch = n+1`, `Extensions = provisionalExtensions`, `TreeHash = ` *(post-path tree hash)*, and **`ConfirmedTranscriptHash = g.groupContext.ConfirmedTranscriptHash` (the OLD one)**. To get the post-path tree hash without disturbing the live decrypt state, **clone**: `ct = wt.Clone(); ct.Merge(committerLeaf, cm.Path); newTreeHash = ct.RootTreeHash()`.
   - `decryptedPS, commitSecret = wt.ProcessUpdatePath(committerLeaf, cm.Path, g.priv, encGC.MarshalMLS())` (decrypts against the **pre-merge** `wt` resolutions).
   - `wt.Merge(committerLeaf, cm.Path)` (advance the working tree).
   - Rebuild private state: `g.priv` for the next epoch holds the leaf key + ancestor keys from `commonAncestor(2*ownLeaf, 2*committerLeaf)` up to root, ratcheted from `decryptedPS` (N4).
   - If `cm.Path == nil`: `commitSecret = nil` (zero), `newTreeHash = wt.RootTreeHash()`, `g.priv` unchanged. (Not exercised by the verified case, but spec-required for proposal-only commits.)
6. **Advance the key schedule under the NEW-epoch GroupContext.** `newGC` = `encGC` but with **`ConfirmedTranscriptHash = confirmed` (the NEW one)** — i.e. `newGC` and `encGC` **differ only in `confirmed_transcript_hash` (new vs old)**; both use `Epoch = n+1`, the new tree hash, and `provisionalExtensions`. `pskSecret = keyschedule.PSKSecret(suite, epochPSKs)`. `es = keyschedule.DeriveEpochSecrets(suite, g.initSecret, commitSecret, pskSecret, newGC.MarshalMLS())`.
7. **Verify `confirmation_tag`.** `keyschedule.ConfirmationTag(suite, es.ConfirmationKey, confirmed)` must equal `confTag` (== `ac.Auth.ConfirmationTag`). Reject the commit on mismatch (§12.4).
8. **Chain the transcript + commit state.** `interim' = keyschedule.InterimTranscriptHash(suite, confirmed, confTag)`. Commit: `g.tree = wt`, `g.groupContext = newGC`, `g.epoch = es`, `g.initSecret = es.InitSecret`, `g.interim = interim'`, `g.priv = rebuilt`, rebuild `g.secretTree` from `es.EncryptionSecret`.
9. **`epoch_authenticator = es.EpochAuthenticator`** — **verified to equal `epochs[i].epoch_authenticator`** for epoch 0 of the handling-commit case (and the same machinery reproduces every subsequent epoch).

### N3. The two GroupContexts differ ONLY in `confirmed_transcript_hash` (verified — the #1 trap)
The UpdatePath HPKE encryption (`EncryptWithLabel/"UpdatePathNode"`) uses a GroupContext with the **OLD** `confirmed_transcript_hash`; the key-schedule + confirmation-tag derivation uses the **NEW** `confirmed_transcript_hash`. Both use `epoch = n+1` and the **new** (post-path) `tree_hash`. This resolves the circularity (the new confirmed hash depends on the commit's signature, which is computed after the path is encrypted). **Verified by brute-forcing all four (epoch ∈ {n, n+1}) × (confirmed ∈ {old, new}) combinations** against the live vector: only `{epoch=n+1, confirmed=old, tree=new}` decrypts the path, and only `{epoch=n+1, confirmed=new, tree=new}` reproduces the `epoch_authenticator`. (This matches the `treekem.json` KAT, which encrypts with the current `confirmed_transcript_hash` + the post-update tree hash.) **Do not collapse these two contexts into one.**

### N4. Joiner / receiver private TreeKEM state (verified)
The `path_secret` in `GroupSecrets` (and the `decryptedPS` from `ProcessUpdatePath`) is the path secret at the **common ancestor** of the receiver's leaf node `2*ownLeaf` and the committer/signer leaf node `2*senderLeaf`. Install it and ratchet up to the root:
```go
func levelOf(x uint32) uint32 { // trailing-ones count; leaves (even) are level 0
	if x&1 == 0 { return 0 }
	k := uint32(0); for (x>>k)&1 == 1 { k++ }; return k
}
func commonAncestor(x, y, nLeaves uint32) uint32 {
	for levelOf(x) < levelOf(y) { x, _ = tree.Parent(x, nLeaves) }
	for levelOf(y) < levelOf(x) { y, _ = tree.Parent(y, nLeaves) }
	for x != y { x, _ = tree.Parent(x, nLeaves); y, _ = tree.Parent(y, nLeaves) }
	return x
}
// install: node=commonAncestor(2*own,2*sender,nLeaves); sec=pathSecret;
//   loop: priv.AddPathSecret(suite,node,sec); if node==Root break;
//         sec=DeriveSecret(sec,"path"); node=Parent(node).
```
For handling-commit case 0, `gs.PathSecret == nil` (joiner at leaf 7 decrypts the first commit directly with its **leaf** key at the root copath), so the install is skipped at join; it runs in `ProcessCommit` to seed `g.priv` for the *next* epoch. (`tree.NodeWidth`/`Root`/`Parent` are already exported; `nLeaves = (Width()+1)/2`, exposed as `tree.LeafCount()`.)

### N5. `confirmed_transcript_hash` input is `wire_format || FramedContent || signature` (verified)
`keyschedule.SplitAuthenticatedContent(suite, ac.MarshalMLS())` peels the trailing `confirmation_tag<V>` (a fixed-length MAC field) off the serialized `AuthenticatedContent` (= `wire_format || FramedContent || FramedContentAuthData`), leaving exactly the `ConfirmedTranscriptHashInput` (`= wire_format || FramedContent || signature`). `confirmed[n] = Hash(interim[n-1] || that)`. `framing.AuthenticatedContent.MarshalMLS` (Plan 8a) produces the input bytes; the join's `interim` (N1 step 12) seeds `interim[n-1]` for the first commit.

### N6. Ordering & framing facts
Passive-client `proposals[]` and `commit` are **PublicMessages** (`wire_format = 0x0001`) with `sender_type = member`. `UnprotectPublic` needs the **current** epoch's `group_context` (for the `"FramedContentTBS"` GroupContext block + membership tag) and `membership_key`. The committer's signature key is read from the **pre-commit** tree (Adds don't change existing leaves' keys). After a Remove of the committer or own leaf the engine would stop — the passive-client vectors keep the observer present throughout.

---

## File structure

| File | Action | Contents |
| --- | --- | --- |
| `mls/tree/treesync.go` (or new `mutate.go`) | Edit/Create | `Clone`, `NodeAt`, `LeafNodeAt`, `LeafCount`, `AddLeaf`, `RemoveLeaf`, `UpdateLeaf`, `FindLeafByEncryptionKey`. |
| `mls/tree/treekem.go` | Edit | `TreeKEMPrivate.PrivateKeyAt(node) ([]byte, bool)`. |
| `mls/tree/mutate_test.go` | Create | unit tests for add/remove/update/clone/find. |
| `mls/group/ports.go` | Create | `DeliveryService`, `CredentialValidator`, `StateStore`, `Clock` interfaces; `InMemoryStateStore`; `BasicCredentialValidator`. |
| `mls/group/ports_test.go` | Create | `InMemoryStateStore` save/load/wipe; `BasicCredentialValidator` accept/reject. |
| `mls/group/group.go` | Create | `Group` struct, accessors (`Epoch`, `EpochAuthenticator`, `Exporter`, `GroupContext`), `commonAncestor`/`levelOf`, `installJoinerPriv`. |
| `mls/group/join.go` | Create | `JoinFromWelcome`. |
| `mls/group/process.go` | Create | proposal resolution + application order; `ProcessCommit`. |
| `mls/group/group_test.go` | Create | `package group` — internal unit tests (commonAncestor, proposal application order). |
| `mls/group/passive_welcome_kat_test.go` | Create | `package group_test` — `passive-client-welcome.json` KAT (gate). |
| `mls/group/passive_commit_kat_test.go` | Create | `package group_test` — `passive-client-handling-commit.json` + `passive-client-random.json` KATs (gate). |
| `mls/testdata/passive-client-welcome.json` | Vendor (curl) | Official KAT. |
| `mls/testdata/passive-client-handling-commit.json` | Vendor (curl) | Official KAT. |
| `mls/testdata/passive-client-random.json` | Vendor (curl) | Official KAT. |

---

## Task 0: `tree` mutation helpers + `TreeKEMPrivate.PrivateKeyAt`

**TDD.** Add the tree operations the engine needs, each with a focused unit test. These mirror the existing internal style (operate on the unexported `nodes`/`privs`).

- [ ] **`mls/tree/treekem.go`** — expose a held private key (used to rebuild path state after a commit):
  ```go
  // PrivateKeyAt returns the HPKE private key held for the given array node index.
  func (p *TreeKEMPrivate) PrivateKeyAt(node uint32) ([]byte, bool) {
  	k, ok := p.privs[node]
  	return k, ok
  }
  ```

- [ ] **`mls/tree/mutate.go`** (new) — tree shape operations:
  ```go
  // LeafCount returns the number of leaves: (width + 1) / 2.
  func (t *RatchetTree) LeafCount() uint32 { return t.leafCount() }

  // NodeAt returns the node at array index i (nil if blank or out of range).
  func (t *RatchetTree) NodeAt(i uint32) *Node {
  	if i >= uint32(len(t.nodes)) { return nil }
  	return t.nodes[i]
  }

  // LeafNodeAt returns the LeafNode at leaf index L (node 2L), or an error if blank.
  func (t *RatchetTree) LeafNodeAt(leaf uint32) (LeafNode, error) {
  	n := t.NodeAt(2 * leaf)
  	if n == nil || n.Leaf == nil { return LeafNode{}, fmt.Errorf("tree: leaf %d is blank", leaf) }
  	return *n.Leaf, nil
  }

  // FindLeafByEncryptionKey returns the leaf index whose LeafNode.EncryptionKey
  // matches key, and ok=false if none.
  func (t *RatchetTree) FindLeafByEncryptionKey(key []byte) (uint32, bool) {
  	for i := uint32(0); i < t.Width(); i += 2 {
  		n := t.nodes[i]
  		if n != nil && n.Leaf != nil && bytes.Equal(n.Leaf.EncryptionKey, key) { return i / 2, true }
  	}
  	return 0, false
  }

  // Clone returns a deep copy via marshal/parse round-trip (used to compute the
  // provisional tree hash without mutating the live tree).
  func (t *RatchetTree) Clone() (*RatchetTree, error) {
  	data, err := t.MarshalMLS()
  	if err != nil { return nil, err }
  	return ParseRatchetTree(t.suite, data)
  }

  // UpdateLeaf replaces the LeafNode at leaf index L and blanks L's direct path
  // (RFC 9420 §12.3 — Update). The new leaf's encryption/signature keys come from ln.
  func (t *RatchetTree) UpdateLeaf(leaf uint32, ln LeafNode) error { /* set nodes[2L]=&{Leaf:&ln}; blank direct path */ }

  // RemoveLeaf blanks leaf index L and its direct path, then truncates trailing
  // blank nodes so the array ends on a non-blank node (RFC 9420 §12.3 — Remove).
  func (t *RatchetTree) RemoveLeaf(leaf uint32) error { /* blank 2L + direct path; shrink tail */ }

  // AddLeaf inserts ln at the leftmost blank leaf (extending the tree by one leaf
  // and a parent if full), adds the new leaf to each populated ancestor's
  // unmerged_leaves, and returns the new leaf index (RFC 9420 §12.3 — Add / §7.x).
  func (t *RatchetTree) AddLeaf(ln LeafNode) (uint32, error) { /* find blank leaf or grow; set leaf; append to ancestors' unmerged_leaves */ }
  ```
  Implementation notes: `blank direct path` walks `Parent(2L, leafCount)` to the root setting `nodes[p]=nil`. `RemoveLeaf` then truncates: `for len(nodes)>1 && nodes[len-1]==nil { nodes=nodes[:len-1] }` and re-pads to `fullWidth` (reuse the helper) so the array stays a complete-tree width. `AddLeaf`: scan even indices for the first nil leaf; if none, append `make([]*Node, 2)` (new parent + new leaf) and re-pad to `fullWidth`; set the leaf; for each ancestor `p` on the new leaf's direct path that is **populated** (`nodes[p]!=nil && Parent!=nil`), append the new leaf index to `UnmergedLeaves` (kept sorted). These match the §7.x semantics that TreeKEM `Resolution`/`treeHashExcept` already rely on.

- [ ] **`mls/tree/mutate_test.go`:** build a 2-leaf tree (parse a small `ratchet_tree`), then: `AddLeaf` → leaf 2 appears + ancestors carry unmerged leaf 2; `UpdateLeaf` swaps keys + blanks path; `RemoveLeaf` blanks + shrinks; `Clone` is independent (mutating the clone leaves the original unchanged); `FindLeafByEncryptionKey` round-trips; `LeafNodeAt` errors on blank.
- [ ] `nix develop -c go test ./mls/tree/`; vet+gofmt clean.
- [ ] **Commit:** `feat(tree): ratchet-tree mutation helpers (add/remove/update/clone/find) + TreeKEMPrivate.PrivateKeyAt for the group engine`.

---

## Task 1: library ports (`ports.go`)

**TDD.** Define the four interfaces from design spec §4 and ship the two minimal defaults; full wiring is the IronCore plan.

- [ ] **`mls/group/ports.go`:**
  ```go
  // GroupID identifies a group on the delivery service (opaque to mls/).
  type GroupID []byte

  // Incoming is one ordered handshake message from the delivery service.
  type Incoming struct {
  	Epoch   uint64
  	Message *framing.MLSMessage
  }

  // DeliveryService fans out handshake messages and delivers the ordered stream
  // (design spec §4; UNTRUSTED for confidentiality — RFC 9750 §5).
  type DeliveryService interface {
  	Send(ctx context.Context, group GroupID, msg *framing.MLSMessage) error
  	Receive(ctx context.Context, group GroupID) (<-chan Incoming, error)
  	PublishGroupInfo(ctx context.Context, group GroupID, gi *GroupInfo) error
  	FetchGroupInfo(ctx context.Context, group GroupID) (*GroupInfo, error)
  }

  // CredentialValidator validates an identity<->signature-key binding (AS role,
  // design spec §4/§8) and returns the verified identity for the authz hook.
  type CredentialValidator interface {
  	Validate(cred tree.Credential, sigPub []byte) (identity []byte, err error)
  }

  // EpochState is the persistable snapshot of a group at one epoch.
  type EpochState struct {
  	Epoch       uint64
  	GroupID     []byte
  	Serialized  []byte // opaque engine-defined encoding (see Group.Export/Import — optional)
  }

  // StateStore persists per-group epoch state (design spec §4/§9; default = in-memory).
  type StateStore interface {
  	Save(group GroupID, st EpochState) error
  	Load(group GroupID) (EpochState, bool, error)
  	Wipe(group GroupID) error
  }

  // Clock supplies the current time for KeyPackage lifetime checks (injectable).
  type Clock interface{ Now() time.Time }

  // --- defaults ---

  // InMemoryStateStore is the default ephemeral StateStore (keys never persisted).
  type InMemoryStateStore struct {
  	mu sync.Mutex
  	m  map[string]EpochState
  }
  func NewInMemoryStateStore() *InMemoryStateStore { return &InMemoryStateStore{m: map[string]EpochState{}} }
  // Save/Load/Wipe ... (keyed by string(group)).

  // BasicCredentialValidator accepts basic credentials whose identity is non-empty
  // and returns that identity. It performs NO PKI/SPIFFE checks — adapters live in ironcore/.
  type BasicCredentialValidator struct{}
  func (BasicCredentialValidator) Validate(cred tree.Credential, sigPub []byte) ([]byte, error) {
  	if cred.CredentialType != tree.CredentialTypeBasic || len(cred.Identity) == 0 {
  		return nil, errors.New("group: BasicCredentialValidator requires a non-empty basic credential")
  	}
  	return cred.Identity, nil
  }

  // SystemClock implements Clock via time.Now.
  type SystemClock struct{}
  func (SystemClock) Now() time.Time { return time.Now() }
  ```
  (Imports: `context`, `errors`, `sync`, `time`, `framing`, `tree`. Keep this minimal — the passive-client KAT is the real gate and does not use the ports.)

- [ ] **`mls/group/ports_test.go`:** `InMemoryStateStore` save→load→wipe; `BasicCredentialValidator` accepts a non-empty basic credential and rejects empty/x509.
- [ ] `nix develop -c go test ./mls/group/ -run Ports`; vet+gofmt clean.
- [ ] **Commit:** `feat(group): library ports (DeliveryService/CredentialValidator/StateStore/Clock) + in-memory + basic defaults (design spec §4)`.

---

## Task 2: `Group` struct + `JoinFromWelcome` → `passive-client-welcome.json` KAT

**TDD.** Vendor the welcome KAT, write the gate test first (it will fail to compile), then implement `Group` + `JoinFromWelcome`.

- [ ] **Vendor:**
  ```bash
  curl -fsSL -o mls/testdata/passive-client-welcome.json \
    https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/passive-client-welcome.json
  ```

- [ ] **`mls/group/group.go`:**
  ```go
  // Group is a member's view of one MLS group at the current epoch (RFC 9420 §8/§11).
  type Group struct {
  	suite        cipher.Suite
  	groupContext keyschedule.GroupContext
  	tree         *tree.RatchetTree
  	priv         *tree.TreeKEMPrivate
  	epoch        keyschedule.EpochSecrets
  	secretTree   *keyschedule.SecretTree
  	interim      []byte // interim_transcript_hash[current epoch]
  	initSecret   []byte // init_secret for the NEXT epoch's key schedule
  	ownLeaf      uint32
  	signer       crypto.Signer // own signing key (for generating; nil for pure receiver)
  }

  func (g *Group) Epoch() uint64               { return g.groupContext.Epoch }
  func (g *Group) EpochAuthenticator() []byte  { return g.epoch.EpochAuthenticator }
  func (g *Group) GroupContext() keyschedule.GroupContext { return g.groupContext }
  // Exporter derives an application secret (RFC 9420 §8.5) — feeds IronCore ESP SAs.
  func (g *Group) Exporter(label string, context []byte, length int) ([]byte, error) {
  	return keyschedule.MLSExporter(g.suite, g.epoch.ExporterSecret, label, context, length)
  }
  ```
  Plus the `levelOf`/`commonAncestor` helpers (N4) and a `installJoinerPriv(priv, pathSecret, ownLeaf, signer)` that runs the ratchet-up loop.

- [ ] **`mls/group/join.go`** — implement `JoinFromWelcome` exactly per N1:
  ```go
  // JoinOptions carries the joiner's private material and optional inputs.
  type JoinOptions struct {
  	KeyPackage     []byte                 // our KeyPackage MLSMessage
  	InitPriv       []byte                 // HPKE init private key
  	EncryptionPriv []byte                 // HPKE leaf encryption private key
  	Signer         crypto.Signer          // our leaf signing key (may be nil for a pure receiver)
  	RatchetTree    []byte                 // external ratchet_tree wire form (nil ⇒ use GroupInfo ext)
  	ExternalPSKs   map[string][]byte      // psk_id (string) -> psk secret
  }

  // JoinFromWelcome processes a Welcome MLSMessage and returns the joined Group at
  // its initial epoch (RFC 9420 §12.4.3.1).
  func JoinFromWelcome(suite cipher.Suite, welcome []byte, opt JoinOptions) (*Group, error) { /* N1 steps 1-13 */ }
  ```
  Resolve PSKs: for each `gs.PSKs` entry (external), look up `opt.ExternalPSKs[string(id.PSKID)]`; build `[]keyschedule.PSK`; `PSKSecret`. (Resumption PSKs are out of passive-client scope — return an explicit error if encountered.)

- [ ] **`mls/group/passive_welcome_kat_test.go`** (`package group_test`):
  ```go
  type pcCase struct {
  	CipherSuite               uint16             `json:"cipher_suite"`
  	KeyPackage                katutil.HexBytes   `json:"key_package"`
  	SignaturePriv             katutil.HexBytes   `json:"signature_priv"`
  	EncryptionPriv            katutil.HexBytes   `json:"encryption_priv"`
  	InitPriv                  katutil.HexBytes   `json:"init_priv"`
  	Welcome                   katutil.HexBytes   `json:"welcome"`
  	RatchetTree               katutil.HexBytes   `json:"ratchet_tree"`
  	InitialEpochAuthenticator katutil.HexBytes   `json:"initial_epoch_authenticator"`
  	ExternalPSKs              []struct{ PSKID, PSK katutil.HexBytes } `json:"external_psks"`
  	Epochs                    []pcEpoch          `json:"epochs"` // unused here
  }
  ```
  Per case: skip unregistered suites (`executed++`); build `JoinOptions` (signer from `buildSigner(cs, signature_priv)`, `ExternalPSKs` map keyed by `string(psk_id)`); `g, err := group.JoinFromWelcome(suite, tc.Welcome, opt)`; require `bytes.Equal(g.EpochAuthenticator(), tc.InitialEpochAuthenticator)`. **Fail if zero executed.** (Verified: all 16 registered-suite cases reproduce `initial_epoch_authenticator`.)

- [ ] `nix develop -c go test ./mls/group/ -run PassiveWelcome -v`; vet+gofmt clean.
- [ ] **Commit:** `feat(group): Group + JoinFromWelcome — passive-client-welcome.json KAT (RFC 9420 §12.4.3.1)`.

---

## Task 3: proposal resolution + application order (RFC 9420 §12.3)

**TDD.** Internal unit test for the §12.3 ordering on a synthetic tree, before wiring into `ProcessCommit`.

- [ ] **`mls/group/process.go`** (part 1) — a pure helper that resolves `ProposalOrRef`s against a cache and applies them to a working tree in §12.3 order, returning `(provisionalExtensions, epochPSKs, pathRequired)`:
  ```go
  type cachedProposal struct {
  	proposal Proposal
  	sender   uint32
  }
  // applyProposals resolves cm.Proposals (by-value/by-reference via cache),
  // applies Update, then Remove, then Add, then GroupContextExtensions to wt
  // (RFC 9420 §12.3), and collects PSK ids. committerLeaf identifies the Update
  // proposer fallback (proposals carry their own sender).
  func applyProposals(suite cipher.Suite, wt *tree.RatchetTree, cm Commit,
  	cache map[string]cachedProposal, currentExt []tree.Extension,
  	externalPSKs map[string][]byte) (provisionalExt []tree.Extension, psks []keyschedule.PSK, pathRequired bool, err error)
  ```
  Buckets: gather resolved `(proposal, sender)` in commit order; then iterate Updates (`wt.UpdateLeaf(sender, upd.LeafNode)`), Removes (`wt.RemoveLeaf(rem.Removed)`), Adds (`wt.AddLeaf(add.KeyPackage.LeafNode)`), then a single GroupContextExtensions (last wins), collecting PSKs throughout. `pathRequired = any Add|Update|Remove`. Reject unknown/duplicate per §12.2 minimally (KAT inputs are well-formed; full validation is the negative-test plan).

- [ ] **`mls/group/group_test.go`:** construct a small tree + a `Commit` mixing a by-value Remove and a by-value Add; assert the resulting tree shape matches applying Remove-then-Add (order matters: Remove blanks before Add fills).
- [ ] `nix develop -c go test ./mls/group/ -run ApplyProposals`; vet+gofmt clean.
- [ ] **Commit:** `feat(group): proposal resolution + RFC §12.3 application order (Update,Remove,Add,GCE)`.

---

## Task 4: `ProcessCommit` → `passive-client-handling-commit.json` KAT

**TDD.** Vendor the KAT, write the gate test (join then process each epoch), then implement `ProcessCommit` per N2/N3.

- [ ] **Vendor:**
  ```bash
  curl -fsSL -o mls/testdata/passive-client-handling-commit.json \
    https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/passive-client-handling-commit.json
  ```

- [ ] **`mls/group/process.go`** (part 2) — implement exactly per N2/N3/N5:
  ```go
  // ProcessCommit advances the group by one epoch, given the proposals delivered
  // before the commit (cached by reference) and the commit MLSMessage. It verifies
  // the commit's authentication and confirmation_tag and returns an error (leaving
  // g unchanged) on any failure (RFC 9420 §12.4).
  func (g *Group) ProcessCommit(proposals [][]byte, commit []byte) error { /* N2 steps 1-9 */ }
  ```
  Critical implementation points (all verified):
  - Build the proposal cache from `proposals` via `framing.UnprotectPublic` (current epoch keys); `ref = prop.Ref(suite)`.
  - Authenticate the commit with `framing.UnprotectPublic(suite, committerPub, &g.groupContext, g.epoch.MembershipKey, *m.Public)`; require `ac.Content.Epoch == g.groupContext.Epoch`.
  - `confirmedInput, confTag = keyschedule.SplitAuthenticatedContent(suite, ac.MarshalMLS())`; `confirmed = ConfirmedTranscriptHash(g.interim, confirmedInput)`.
  - `wt = g.tree.Clone()`; `applyProposals(...)` on `wt`.
  - Path: `ct = wt.Clone(); ct.Merge(committerLeaf, cm.Path); newTreeHash = ct.RootTreeHash()`. Build `encGC` (`Epoch=n+1, TreeHash=newTreeHash, ConfirmedTranscriptHash=g.groupContext.ConfirmedTranscriptHash (OLD), Extensions=provisionalExt`). `decryptedPS, commitSecret = wt.ProcessUpdatePath(committerLeaf, cm.Path, g.priv, encGC.MarshalMLS())`; `wt.Merge(...)`. **Two distinct contexts — N3.**
  - `newGC = encGC` with `ConfirmedTranscriptHash = confirmed` (NEW). `pskSecret = PSKSecret(epochPSKs)`. `es = DeriveEpochSecrets(g.initSecret, commitSecret, pskSecret, newGC.MarshalMLS())`.
  - Require `ConfirmationTag(es.ConfirmationKey, confirmed) == confTag`.
  - On success: `g.tree=wt; g.priv = rebuild(decryptedPS, committerLeaf); g.groupContext=newGC; g.epoch=es; g.initSecret=es.InitSecret; g.interim=InterimTranscriptHash(confirmed, confTag); g.secretTree=NewSecretTree(es.EncryptionSecret, wt.LeafCount())`.
  - Path-absent branch: `commitSecret=nil`, `newTreeHash=wt.RootTreeHash()`, `g.priv` unchanged.

- [ ] **`mls/group/passive_commit_kat_test.go`** (`package group_test`): reuse `pcCase` (now using `Epochs`):
  ```go
  type pcEpoch struct {
  	Proposals          []katutil.HexBytes `json:"proposals"`
  	Commit             katutil.HexBytes   `json:"commit"`
  	EpochAuthenticator katutil.HexBytes   `json:"epoch_authenticator"`
  }
  ```
  Per registered-suite case: `g = JoinFromWelcome(...)`; require `g.EpochAuthenticator() == initial_epoch_authenticator`; for each `ep`: `props = [][]byte(ep.Proposals)`; `g.ProcessCommit(props, ep.Commit)`; require `g.EpochAuthenticator() == ep.EpochAuthenticator`. **Fail if zero executed.** (Verified: epoch 0 of suite-1 case 0 reproduces `epoch_authenticator`; the same machinery drives every epoch — epoch 1 exercises a by-value Add, processed via `applyProposals`+`AddLeaf` from Task 3.)

- [ ] `nix develop -c go test ./mls/group/ -run PassiveCommit -v`; vet+gofmt clean.
- [ ] **Commit:** `feat(group): ProcessCommit (proposals + UpdatePath + key schedule) — passive-client-handling-commit.json KAT (RFC 9420 §12.4)`.

---

## Task 5: `passive-client-random.json` stress KAT

**TDD.** The random vector exercises long, mixed epoch sequences (Adds, Removes, Updates, PSKs, by-value + by-reference proposals, and path-less commits). It uses the *same* `Group` API with no new schema — pointing the Task 4 harness at the random file is the test.

- [ ] **Vendor:**
  ```bash
  curl -fsSL -o mls/testdata/passive-client-random.json \
    https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/passive-client-random.json
  ```

- [ ] **`passive_commit_kat_test.go`** — parameterize the per-file driver and add a `passive-client-random.json` subtest (same `pcCase`/`pcEpoch` decoding, same assertions). Expect this to surface any gaps in: path-less commits (`commitSecret=nil`), Remove-then-Add tree reshaping + truncation, PSK proposals in commits (resolved via `external_psks` → non-nil `pskSecret`), and resumption/external edge cases. Fix `applyProposals`/`RemoveLeaf`/`AddLeaf` as the vector demands; **the random KAT passing is the definitive end-to-end signal** (it transitively exercises framing, TreeKEM, parent-hash, key schedule, secret tree, transcript hash, and PSK).
- [ ] **Guard:** assert ≥1 case executed and ≥1 epoch processed across the registered suites.
- [ ] `nix develop -c go test ./mls/group/ -run PassiveRandom -v`; full `nix develop -c go test ./mls/...`; vet+gofmt clean.
- [ ] **Commit:** `test(group): passive-client-random.json stress KAT — full end-to-end MLS receiver`.

---

## Definition of Done

- [ ] `nix develop -c go test ./mls/...` passes, including **all three** passive-client KATs (`welcome` reproduces `initial_epoch_authenticator`; `handling-commit` and `random` reproduce every per-epoch `epoch_authenticator`) plus the Plan 8a `messages.json`/`welcome.json` gates, each with executed-case + zero-epoch guards and unregistered-suite skips.
- [ ] `nix develop -c go vet ./mls/...` clean; `nix develop -c gofmt -l mls/` empty; `go build ./...` clean (no import cycle — `group` remains a leaf importer).
- [ ] The two GroupContexts in `ProcessCommit` differ **only** in `confirmed_transcript_hash` (encryption=old, key-schedule=new), both at `epoch=n+1` with the post-path tree hash (N3); the confirmation_tag is verified before state is committed; failures leave `g` unchanged.
- [ ] `JoinFromWelcome` uses HPKE label `"Welcome"` with `context = encrypted_group_info` for GroupSecrets and `WelcomeKeyNonce` + empty AAD for GroupInfo; verifies the GroupInfo signature and confirmation tag; installs the tree from the GroupInfo `ratchet_tree` (0x0002) extension or the external `ratchet_tree`.
- [ ] `tree` mutation helpers + `TreeKEMPrivate.PrivateKeyAt` are unit-tested; `ports.go` ships the four interfaces + `InMemoryStateStore` + `BasicCredentialValidator`, unit-tested.
- [ ] One commit per task; each with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.

---

## Notes — post-Plan-8 IronCore integration roadmap

With the `mls/` engine passing the passive-client suite, the remaining work is the **`ironcore/`** integration layer (design spec §3/§5/§10), out of scope for Plan 8:

1. **VNI ↔ GroupID** — `GroupID = encode(VNI)` (stable, collision-free); `ironcore/` owns the mapping, `mls/` treats `GroupID` opaquely (§10.1).
2. **Exporter → ESP SA derivation** — `K_group = Group.Exporter("ironcore-esp", VNI‖epoch, L)`; `SPI = f(VNI, epoch)`; **per-sender nonce salt** `HKDF(K_group, "esp-sender"‖leaf_index)` to guarantee disjoint AES-GCM nonce spaces; make-before-break SA install (§10.4).
3. **Membership controller** — control plane as an authorized **external proposer** (`external_senders` extension) emitting Add/Remove on VNI placement; the lowest-index member as **designated committer**; external self-commit join/recovery (§10.3).
4. **DeliveryService / Sequencer adapters** — metalbond implements `DeliveryService` + the `Ordering` single-linearization-point contract (one accepted Commit per `(group, epoch)`, §5.1/§5.5); `epoch_authenticator` exposed for active fork detection (§5.6); B1 fenced single-writer default.
5. **CredentialValidator adapters** — SPIFFE-SVID + generic-PKI x509 validators binding the mTLS identity to the MLS leaf credential (§8).
6. **Commit/Welcome generation** — if not implemented opportunistically in Plan 8, the committer side (`Commit`, `GenerateUpdatePath` is already in `tree`, `Welcome` assembly, GroupInfo signing/publication) is needed for active membership; the interop `MLSClient` gRPC server (design spec §6) then demonstrates conformance against OpenMLS/mls-rs.
