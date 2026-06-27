# Membership Controller — operational VNI lifecycle orchestration: designated committer, Reconcile, rekey, make-before-break SA, auto-recovery (Plan 13 of 13) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. **Depends on Plan 10** (`2026-06-27-ironcore-integration.md` — `ironcore/`: `GroupID`/`VNIOfGroupID`, `VNIGroup`, `DeriveSAKeys`/`SA`/`SenderSalt`, the `buildVNIGroup`/`addMember`/`makeSigner`/`makeCred`/`makeLifetime`/`makeTestCA` test helpers, `BasicCredentialValidator`), **Plan 11** (`2026-06-27-sequencer.md` — `ironcore/sequencer`: `MemorySequencer`, `FencedSequencer`, `EpochAuthenticatorRegistry`, `CanonicalCommit`; and `mls/group/ports.go`'s `Ordering`/`CommitRef`/`Clock`/`CredentialValidator`), and **Plan 12** (`2026-06-27-external-commit.md` — `group.ExternalCommit`/`ProcessExternalCommit`/`PublishGroupInfo`, `ironcore.RecoverViaExternalCommit`/`ErrRecoverySuperseded`) must be merged first. Plan 9's active engine (`group.NewGroup`, `Commit(CommitOptions)→(commit, welcome, error)`, `ProcessCommit`, `JoinFromWelcome`, `ProposeAdd`/`ProposeRemove`, `EpochAuthenticator`/`Epoch`/`OwnLeaf`/`GroupContext`) is the substrate. **There is no MLS KAT for this layer** — the gates are SELF-ROUND-TRIP multi-node simulations that *demonstrate* the design spec's §10.3 operational claims. Every behaviour below was **empirically validated during planning** with throwaway `package ironcore_test` sims (and throwaway `Group.ActiveLeaves`/`Group.LeafCredential` accessors) run with `nix develop -c go test ./ironcore/`. **The throwaways were deleted; the working tree was left clean (only this plan file is new — no `zz_*`/`zzz_*`/`throwaway_*` stragglers).** Validation log (real run, X-Wing suite 0xF001): **(gate 1)** founder + 3 joiners → `Reconcile` add → 4 nodes converge at epoch 1 (`EA=29f67c9f…`); `Reconcile` remove node-2 → node-2 self-removes, 3 survivors converge at epoch 2 (`EA=d5866ad2…`). **(gate 2)** 3-member group, `Reconcile` removing sitting committer node-0 → node-0's own `Reconcile` is a no-op (cannot self-remove, §12.1.3), the committer-elect node-1 (lowest *surviving* leaf) commits the removal, node-0 self-removes on delivery, `IsCommitter()` flips to node-1, which then drives a rekey → both converge (epochs 2, 3). **(gate 3)** committer `Rekey()` (empty path-only commit) → epoch advances, `SA.Key` rotates, all converge, `PreviousSA()` still exposes the pre-rekey SA (make-before-break); a removed node's stale SA ≠ the post-removal SA (PCS). **(gate 4)** 2-member group, induced fork (node-0 wins the linearization slot, node-1's competing commit gets `ok=false`), node-1 `AutoRecover` via external commit onto the canonical branch (`CanonicalCommit` = lowest `Hash(ref)`), founder processes the recovery external commit → both re-converge at epoch 3 (`EA=b3571afb…`).

**Goal:** Build the **membership controller** (design spec §10.3) — the operational orchestration layer that ties the existing MLS+IronCore primitives into the VNI lifecycle that metalnet's control plane drives. Deliverables: **(0)** two minimal **read-only `Group` accessors** in `mls/group/members.go` — `ActiveLeaves() []uint32` (ascending non-blank leaf indices) and `LeafCredential(leaf) (tree.Credential, []byte, error)` — the only new MLS-core surface, justified below; **(1)** an `ironcore.Controller` (`ironcore/controller.go`) wrapping one VNI's `*group.Group` with: **designated-committer election** (`IsCommitter()` = lowest active leaf; deterministic handover when the committer leaves), **control-plane-driven membership** (`Reconcile(desired)` diffs desired-vs-current identities → batched Add/Remove commit routed through the `Ordering` sequencer; non-committers are no-ops), **periodic PCS rekey** (`Rekey()` = empty path-only commit), **inbound processing + make-before-break ESP SA** (`HandleCommit`, `CurrentSA()`/`PreviousSA()`), **join** (`JoinViaWelcome`, `JoinViaExternalCommit`), and **fork detection + auto-recovery** (`AutoRecover` composing Plan 11's sequencer + Plan 12's `RecoverViaExternalCommit`). **The four multi-node convergence sims are the gates** (under suite 0xF001): lifecycle convergence, committer handover, periodic rekey + PCS, and auto-recovery. The controller is **pure orchestration over existing primitives** — it adds no new MLS-core logic beyond the two read-only accessors, spawns **no goroutines**, and reads **no wall-clock directly** (all timing via the injectable `Clock` port; the controller exposes *triggers*, the scheduler is the caller's).

**Architecture (design spec §3/§10.2/§10.3):** The controller is **deployment glue** and lives in the `ironcore/` root package (design spec §3: "membership controller glue" belongs in `ironcore/`), alongside `VNIGroup`, `DeriveSAKeys`, and `RecoverViaExternalCommit` which it composes. It is **not** a new MLS engine: it holds a `*group.Group` and calls only existing exported engine methods plus the two new read-only accessors. The **designated-committer-MEMBER model** is used (design spec §10.3): the committer is an ordinary group member (the lowest active leaf) that directly creates Add/Remove commits from control-plane events — we do **not** use the MLS `external_senders` extension (noted as a deferred alternative in the roadmap). The single `Ordering` linearization point (§5.5) makes every commit — membership, rekey, external-join, and recovery — pass through the same accept-once-per-`(group,epoch)` register, so handover races and concurrent committers fail closed (one winner; losers auto-recover). The §10.2 trust model is preserved: the controller manipulates only its own member's group state and routes opaque `CommitRef`s through the sequencer; the sequencer holds no secrets. The controller is **VNI-scoped** (one `Controller` per VNI per host); a host on many VNIs holds many independent `Controller`s. `Group` is documented not-concurrency-safe, and the controller adds **no internal locking** — callers serialize calls per `Controller` (matching the engine's contract); concurrency across different VNIs is independent.

**Tech Stack:** Go 1.26 standard library only (hard constraint). `mls/group/members.go` uses only `mls/tree` (already a `group` dependency). `ironcore/controller.go` uses `context`, `crypto`, `errors`, `fmt`, `sort` (all stdlib) + `mls/cipher`, `mls/framing`, `mls/group`, `mls/tree`, `ironcore/sequencer`. The gate sims live in `package ironcore_test` (external) and reuse the Plan-10 helpers (`makeSigner`, `makeCred`, `makeLifetime`, `group.NewKeyPackage`, `group.EncodeKeyPackageMessage`) plus `sequencer.MemorySequencer`. No new dependencies, no goroutines, no `time.Now()` in library code.

**Spec reference:** Design spec `docs/superpowers/specs/2026-06-26-mls-mlkem-go-design.md` **§10.3 in full** (group lifecycle & membership-controller flow): *source of truth* = metalnet's control plane (workload placement ⇒ membership); *member agent* per host holding the MLS leaf + group state; *designated committer member* = "the active leaf with the **lowest index** batches pending proposals into a Commit each round; if it leaves/dies, the next-lowest takes over **deterministically**, and the sequencer's single-commit-per-epoch rule (§5.1) makes any handover race safe"; *Join* via external self-commit against the sequencer's latest signed GroupInfo (or via Welcome when Added); *Leave* (graceful self-Remove or control-plane-proposed Remove committed by the designated member; crash-leave driven by placement/liveness); *Periodic rekey (PCS)* = "the designated committer issues an **empty Update Commit** on a timer even without membership change, to heal any silent compromise"; *GroupInfo publication* each epoch. Also **§10.4** (exporter→ESP-SA: per-epoch `K_group`, epoch-encoded SPI, per-sender nonce salt, **make-before-break** "install epoch *e+1* SAs **before** tearing down epoch *e*"), **§10.5** (scale: 10s–low-thousands members; rekey is human-rate), **§5.1/§5.5/§5.6** (single linearizable register; deterministic recovery via external Commit under tie-break = lowest `Hash(Commit)`, the recovery itself passing through the linearization point), **§10.2** (sequencer is a pure ordering authority, holds no secrets). RFC 9420 §§12.1.3 (a Commit MUST NOT remove the committer), 12.3 (proposal application order), 12.4 / 12.4.3.1–2 (Commit / Welcome / external Commit), 8.7 (epoch_authenticator).

> **Go invocation convention:** Go is **not** on `PATH`. Every Go command runs through the nix devshell, e.g. `nix develop -c go test ./ironcore/`. Use this form everywhere below. Expect a harmless `Entered Go dev shell: …` banner (and possibly a `warning: Git tree … is dirty`) on stderr. Format and vet after every task: `nix develop -c gofmt -l ironcore/ mls/group/` (must print nothing) and `nix develop -c go vet ./ironcore/...`.

---

## Design notes (read before implementing)

Every claim below was reproduced during planning by throwaway sims (see the header validation log). They map directly onto the §10.3 operational obligations — get them exactly right; the sims ARE the deliverable.

### N0. The two new read-only `Group` accessors — minimal, justified MLS-core surface

Plan 10 deliberately did **not** add a `Members()`/leaf-iteration accessor to `Group` (its private `tree` field stayed encapsulated). The controller needs exactly two read-only facts that no existing exported method provides:

1. **Committer election** needs to enumerate the *active* (non-blank) leaves and find the lowest — `IsCommitter()` = `OwnLeaf() == lowest-active-leaf`, and the deterministic handover needs the lowest *surviving* leaf.
2. **The Reconcile diff** needs to map each current member's **verified identity → leaf index**, which requires reading each leaf's `Credential` + `SignatureKey` and running them through the `CredentialValidator` (AS).

Both are **read-only, expose no tree-node handles, and leak no secrets** (only public leaf material already visible in any published `GroupInfo`). They are the smallest surface that satisfies the controller; they are added to `mls/group` (a new file `members.go`) rather than `ironcore` because they require the private `tree` field. *Validated: with these two methods the controller drives all four gates; nothing else was needed from the engine.* Exact code (`mls/group/members.go`):

```go
package group

import "github.com/trevex/mls-mlkem-go/mls/tree"

// ActiveLeaves returns the ascending list of non-blank leaf indices in the
// current ratchet tree. The first element (if any) is the lowest active leaf —
// the designated committer (design spec §10.3). Read-only; the slice is freshly
// allocated and safe for the caller to mutate.
func (g *Group) ActiveLeaves() []uint32 {
	var out []uint32
	for i := uint32(0); i < g.tree.LeafCount(); i++ {
		if _, err := g.tree.LeafNodeAt(i); err == nil { // err ⇒ blank leaf, skip
			out = append(out, i)
		}
	}
	return out
}

// LeafCredential returns the Credential and signature public key of the member
// at the given non-blank leaf, for mapping verified identity → leaf in the
// membership controller's reconcile diff (design spec §10.3). It returns an
// error for a blank or out-of-range leaf. Read-only; exposes only public leaf
// material (no group secrets).
func (g *Group) LeafCredential(leaf uint32) (tree.Credential, []byte, error) {
	ln, err := g.tree.LeafNodeAt(leaf)
	if err != nil {
		return tree.Credential{}, nil, err
	}
	return ln.Credential, ln.SignatureKey, nil
}
```

`g.tree.LeafCount()` returns `(width+1)/2` and shrinks after `RemoveLeaf` truncates trailing blanks; the loop yields ascending indices, so `ActiveLeaves()[0]` is the lowest active leaf. `LeafNodeAt` already returns an error for a blank leaf (`tree/mutate.go`), which the loop uses as the blank test.

### N1. Designated committer + deterministic handover (§10.3) — the determinism argument

`IsCommitter()` is a **pure function of the shared tree**: every honest member computes `ActiveLeaves()` identically (the ratchet tree is byte-identical across members at a given epoch — that is exactly what convergence means), so all members agree on the lowest active leaf without communicating. The committer is therefore unambiguous and changes only when the tree changes (a member added below the current lowest is impossible — `AddLeaf` fills the *leftmost* blank, which after removals can be below the current committer; see N3 caveat).

**Handover when the committer leaves.** RFC 9420 §12.1.3 forbids a Commit from removing its own committer, so the sitting committer C0 **cannot** evict itself. Handover is driven by the **committer-elect = the lowest active leaf that is NOT being removed**:

- If a `Reconcile` removes the current lowest leaf (C0), then C0's own `Reconcile` is a **no-op** (it filters its own leaf out of the remove set and finds itself not the committer-elect — see N2), and the **next-lowest surviving leaf** (C1) is entitled to commit `Remove(C0)` (plus any other diff). This is legal MLS: any member may commit, and removing *another* member is allowed.
- On delivery, C0's `HandleCommit` detects the self-removal and returns `ErrSelfRemoved` (N4); C1 (and other survivors) advance. After the commit, `ActiveLeaves()[0]` is now C1 → `IsCommitter()` flips to C1.
- **Race safety:** if two members both believe they are the committer-elect (e.g. transiently differing `desired` views), both commit at the same epoch; the single `Ordering` register accepts exactly one; the loser auto-recovers (N6). This is precisely the §10.3 claim that "the sequencer's single-commit-per-epoch rule makes any handover race safe."

*Validated (gate 2): removing committer node-0 → node-0 `Reconcile` no-op, node-1 commits the removal, node-0 self-removes, `IsCommitter()` flips to node-1, node-1 drives the next rekey; both converge.*

### N2. `Reconcile` — diff desired-vs-current, entitlement, and proposal batching (§10.3)

`Reconcile(ctx, desired [][]byte)` takes the control plane's desired **identity set** (the verified identities — SPIFFE IDs / PKI subjects — that should be on this VNI). Algorithm:

1. **Current map:** for each `leaf ∈ ActiveLeaves()`, run `validator.Validate(LeafCredential(leaf))` → `identity`; build `identity → leaf`.
2. **Removes:** every current member whose identity ∉ `desired` → its leaf into `removeSet`.
3. **Adds:** every `desired` identity ∉ current → into `addIdents`.
4. **Entitlement (deterministic):** `committer = ActiveLeaves()[0]`; **if `committer ∈ removeSet`** (handover case, N1), `committer = ` the lowest surviving leaf (first `ActiveLeaves()` element not in `removeSet`). Then **delete this node's own leaf from `removeSet`** (a member never self-removes in its own commit, §12.1.3). If `OwnLeaf() != committer` → return a **no-op** result (`Committed=false`); the non-committer will instead `HandleCommit` the inbound commit.
5. **Build proposals (by-value):** `ProposeRemove(leaf)` for each removed leaf (ascending, deterministic), then `ProposeAdd(kp)` for each addable identity. New-member KeyPackages are resolved via the injectable `KeyPackageResolver` (control-plane-published, out-of-band, design spec §10.3 Join + open item §12.5); a desired identity with no published KeyPackage goes into `Pending` (cannot add yet) and is reported, not an error.
6. **Commit + order:** if there is ≥1 proposal, call `commitAndOrder` (N5). The §12.3 application order (Update→Remove→Add) is enforced **inside** the engine's `applyProposals`, so the by-value slice order is not load-bearing; we emit removes-then-adds for readability.

Membership churn lands in **one Commit per round** (RFC §12.3 batching) routed through one `AcceptCommit`. Non-committers calling `Reconcile` are pure no-ops — they own no membership authority and only process inbound commits.

*Validated (gate 1): `Reconcile([node-0,1,2,3])` adds 3 in one commit (one Welcome to all joiners); `Reconcile([node-0,1,3])` removes node-2; all converge with byte-equal EA + SA.Key.*

> **N2 caveat — leaf-reuse after removals.** `AddLeaf` fills the leftmost blank, so after removing a low leaf a later Add can occupy an index *below* the current committer, making the new member the committer next round. This is still deterministic (all members see the same tree) and safe (the sequencer arbitrates), but means committer identity can move on Add, not only on the committer's own removal. The gates exercise the common cases; this caveat is documented for operators and is not a correctness bug. (Deferred refinement: a stickier election keyed on a stable per-member token rather than raw leaf index — roadmap.)

### N3. Make-before-break ESP SA exposure (§10.4)

The data plane must install epoch *e+1* SAs **before** tearing down epoch *e* (design spec §10.4). Because the engine mutates `Group` in place on each epoch change (the old epoch's secrets are gone after `Commit`/`ProcessCommit`), the controller **caches the derived `SA` value** (which holds frozen key bytes, not a live reference). On every successful epoch advance, `rotateSA()` shifts `curSA → prevSA` then re-derives `curSA = DeriveSAKeys(g, vni)` at the new epoch. The controller exposes:

- `CurrentSA() (SA, error)` — the current-epoch SA (the one the data plane rotates *to*).
- `PreviousSA() (SA, bool)` — the immediately-prior epoch's SA, still valid during the make-before-break overlap window (`ok=false` only at the very first epoch).

The data plane keeps both installed until the overlap window (≥ max propagation + clock skew, §10.4) elapses, then drops `PreviousSA`. The SPI is epoch-encoded (Plan 10 `deriveSPI`), so overlapping epochs disambiguate. *Validated (gate 3): after `Rekey`, `CurrentSA().Key` rotated and `PreviousSA()` still returned the pre-rekey key.*

### N4. `HandleCommit` — inbound processing + self-removal detection

`HandleCommit(commitMsg)` processes an inbound commit (member or external — `group.ProcessCommit` dispatches to `processExternalCommit` automatically on a `new_member_commit` sender) and then `rotateSA()`. Two subtleties:

- **Pure by-value commits:** the controller always inlines its Add/Remove proposals (by-value), so inbound commits carry no by-reference proposals → `HandleCommit` calls `ProcessCommit(nil, commitMsg)`. No proposal cache is needed.
- **Self-removal:** a member whose own leaf is removed by the commit cannot decrypt the new path (it is no longer in the tree), so `ProcessCommit` would fail with a `confirmation_tag mismatch`. The controller **pre-scans** the framed commit for a by-value `Remove` of its own leaf and returns the sentinel `ErrSelfRemoved` *before* attempting to process, giving the caller a clean "you have left the group" signal. The scan parses the `PublicMessage` → `Commit` body via exported APIs (`framing.MLSMessage`, `group.Commit.UnmarshalMLS`) — no new engine surface.

```go
// commitRemovesSelf reports whether the framed member commit contains a by-value
// Remove of this node's own leaf (a self-removal we cannot process — §12.1.3
// allows another member to remove us, but we can no longer derive the new epoch).
func (c *Controller) commitRemovesSelf(commitMsg []byte) bool {
	body, ok := memberCommitBody(commitMsg)
	if !ok {
		return false
	}
	var cm group.Commit
	if err := cm.UnmarshalMLS(body); err != nil {
		return false
	}
	own := c.g.OwnLeaf()
	for _, por := range cm.Proposals {
		if por.Type == group.ProposalOrRefTypeProposal && por.Proposal != nil &&
			por.Proposal.Type == group.ProposalTypeRemove && por.Proposal.Remove != nil &&
			por.Proposal.Remove.Removed == own {
			return true
		}
	}
	return false
}
```

*Validated: in gates 1–2 the removed node's `HandleCommit` returned `ErrSelfRemoved` and the survivors converged.*

### N5. `commitAndOrder` — optimistic commit + linearization, and "how a committer detects it lost"

The engine mutates `Group` in place and has **no snapshot/rollback**, so the controller commits **optimistically** then reserves the slot:

1. Capture `epoch := g.Epoch()` (the **pre-commit** epoch *n* — `AcceptCommit` keys on the epoch the commit advances *from*).
2. `commitMsg, welcomeMsg = g.Commit(CommitOptions{ByValue: byValue})` (advances `g` to *n+1* in place).
3. `ref := CommitRef(suite.Hash(commitMsg))`; `ok = ordering.AcceptCommit(ctx, groupID, epoch, ref)`.
4. **Won (`ok=true`):** `rotateSA()`; broadcast `commitMsg` (and `welcomeMsg` to added members). Other members `HandleCommit`.
5. **Lost (`ok=false`):** **this is the "I lost" signal.** Our in-place epoch *n+1* is now a dead fork branch. The caller must `AutoRecover` (N6) onto whichever branch won — recovery does not need our pre-commit state (it rebuilds from the canonical `GroupInfo`), so the lost optimistic advance is simply discarded.

`Reconcile`/`Rekey` surface the loss as `ErrLostRace` (and still return `commitMsg`/`won=false`) so the caller drives recovery. This composes Plan 11 (the register decides) + Plan 12 (external-commit recovery). The `EpochAuthenticatorRegistry` (Plan 11) is the **defense-in-depth** out-of-band detector — `AcceptCommit`'s `ok=false` is the **primary, synchronous** detector. *Validated (gate 4): node-1's competing commit got `ok=false`; node-1 then auto-recovered.*

```go
func (c *Controller) commitAndOrder(ctx context.Context, byValue []group.Proposal) (commitMsg, welcomeMsg []byte, won bool, err error) {
	epoch := c.g.Epoch() // pre-commit epoch n
	commitMsg, welcomeMsg, err = c.g.Commit(group.CommitOptions{ByValue: byValue})
	if err != nil {
		return nil, nil, false, err
	}
	ref := group.CommitRef(c.suite.Hash(commitMsg))
	ok, err := c.ordering.AcceptCommit(ctx, c.groupID, epoch, ref)
	if err != nil {
		return commitMsg, welcomeMsg, false, err
	}
	if !ok {
		return commitMsg, welcomeMsg, false, nil // lost — c.g is a dead fork branch; caller AutoRecovers
	}
	if err := c.rotateSA(); err != nil {
		return commitMsg, welcomeMsg, true, err
	}
	return commitMsg, welcomeMsg, true, nil
}
```

### N6. Join + auto-recovery (§10.3 Join / §5.6 recovery)

- **`JoinViaWelcome(welcomeMsg, kpMsg, initPriv, leafPriv)`** — a node Added by the committer joins from the Welcome (`group.JoinFromWelcome`). No `AcceptCommit` needed: the Welcome is a product of the committer's already-ordered commit.
- **`JoinViaExternalCommit(ctx, gi)`** — a new host joins without a Welcome via `group.ExternalCommit` against the sequencer's latest signed `GroupInfo`, then reserves the slot with `AcceptCommit(ctx, groupID, gi.GroupContext.Epoch, ref)`. On `ok=false` it returns `ErrJoinSuperseded` (the caller re-fetches the now-decided `GroupInfo` and retries). On success the controller adopts the new group and derives the SA.
- **`AutoRecover(ctx, candidates, fetchGI)`** — wraps the controller's group in a transient `VNIGroup` and delegates to Plan 12's `RecoverViaExternalCommit` (canonical branch = `CanonicalCommit` = lowest `Hash(ref)`; routed through `Ordering` so recovery itself cannot fork; anti-double-join Remove of the loser's stale leaf handled inside `group.ExternalCommit`). It adopts the recovered group, re-derives the SA, and returns the recovery commit for broadcast to canonical-branch members (who apply it via `HandleCommit` → `ProcessExternalCommit`). Returns `ErrRecoverySuperseded` (re-exported behaviour from Plan 12) if another recovery won; the caller retries against the new canonical epoch.

*Validated (gate 4): induced fork, node-1 `AutoRecover` → founder `HandleCommit(recoveryMsg)` → both converge at epoch 3 with byte-equal EA + SA.Key.*

### N7. Clock, goroutines, and triggers (hard constraints)

The controller stores the injectable `Clock` (for future KeyPackage-freshness checks and to satisfy "no wall-clock directly") but **never calls `time.Now()`** and **never spawns a goroutine**. `Rekey()`/`Reconcile()` are *triggers* the caller invokes on its own schedule (a timer in metalnet's agent, the PCS interval). The library exposes the trigger; the scheduler is the caller's. This is a verifiable invariant: `grep -n 'time.Now\|go func\|go c\.' ironcore/controller.go` must print nothing.

---

## File structure

| File | Status | Purpose |
|---|---|---|
| `mls/group/members.go` | **new** | Read-only `Group.ActiveLeaves()` + `Group.LeafCredential()` accessors (N0). |
| `mls/group/members_test.go` | **new** | Unit tests for the two accessors (active vs blank leaves; credential at leaf; error on blank/out-of-range). |
| `ironcore/controller.go` | **new** | `Controller`, `ControllerConfig`, `NewController`, `KeyPackageResolver`, `ReconcileResult`, the `Err*` sentinels, `IsCommitter`/`Reconcile`/`Rekey`/`HandleCommit`/`CurrentSA`/`PreviousSA`/`JoinViaWelcome`/`JoinViaExternalCommit`/`AutoRecover`/`PublishGroupInfo` + the `memberCommitBody`/`commitRemovesSelf`/`commitAndOrder`/`rotateSA`/`identityToLeaf` helpers. |
| `ironcore/controller_test.go` | **new** | The four multi-node convergence GATE sims (lifecycle, handover, rekey+PCS, auto-recovery) under suite 0xF001, plus the node/harness helpers (`mkNode`, `founderNode`, `assertConverged`, `broadcast`). |

No changes to any other file. The two `Group` accessors are the only `mls/` edit.

---

## Public API (final shapes — produce exactly these)

```go
// ─── ironcore/controller.go ──────────────────────────────────────────────────

// KeyPackageResolver resolves a desired member identity to its published
// KeyPackage MLSMessage bytes (control-plane published out-of-band, §10.3).
// ok=false ⇒ no KeyPackage available yet; the identity is reported Pending.
type KeyPackageResolver func(identity []byte) (kpMsg []byte, ok bool)

// ControllerConfig configures one VNI's membership controller.
type ControllerConfig struct {
	VNI       uint32
	Suite     cipher.Suite
	Ordering  group.Ordering              // the single linearization point (Plan 11)
	Clock     group.Clock                 // injectable; the controller never reads wall-clock
	Validator group.CredentialValidator   // AS: maps a leaf credential → verified identity
	Cred      tree.Credential             // this node's own credential
	Signer    crypto.Signer               // this node's own signing key
	Lifetime  tree.Lifetime               // KeyPackage lifetime for our external-commit/join leaves
	Resolve   KeyPackageResolver          // resolves desired identities → published KeyPackages
}

// Controller orchestrates one VNI's MLS group over the operational lifecycle
// (design spec §10.3). It is NOT safe for concurrent use; serialize calls per
// Controller (mirrors *group.Group). It spawns no goroutines and reads no
// wall-clock — Rekey/Reconcile are triggers the caller schedules.
type Controller struct { /* unexported fields */ }

func NewController(cfg ControllerConfig, g *group.Group) (*Controller, error) // g may be nil (joiner)

func (c *Controller) Group() *group.Group
func (c *Controller) Epoch() uint64
func (c *Controller) IsCommitter() bool

// ReconcileResult reports what one Reconcile did.
type ReconcileResult struct {
	Committed  bool      // this node issued a commit
	Won        bool      // the sequencer accepted it (false ⇒ ErrLostRace; AutoRecover)
	Added      [][]byte  // identities Added
	Removed    []uint32  // leaves Removed
	Pending    [][]byte  // desired identities with no published KeyPackage yet
	CommitMsg  []byte    // broadcast to members when Committed
	WelcomeMsg []byte    // send to Added members when len(Added) > 0
}

func (c *Controller) Reconcile(ctx context.Context, desired [][]byte) (ReconcileResult, error)
func (c *Controller) Rekey(ctx context.Context) (commitMsg []byte, won bool, err error)
func (c *Controller) HandleCommit(commitMsg []byte) error // ErrSelfRemoved if it removes us
func (c *Controller) CurrentSA() (SA, error)
func (c *Controller) PreviousSA() (SA, bool)              // make-before-break overlap
func (c *Controller) JoinViaWelcome(welcomeMsg, kpMsg, initPriv, leafPriv []byte) error
func (c *Controller) JoinViaExternalCommit(ctx context.Context, gi *group.GroupInfo) (commitMsg []byte, err error)
func (c *Controller) AutoRecover(ctx context.Context, candidates []group.CommitRef, fetchGI func(group.CommitRef) (*group.GroupInfo, error)) (commitMsg []byte, err error)
func (c *Controller) PublishGroupInfo() (*group.GroupInfo, error)

var (
	ErrSelfRemoved    = errors.New("ironcore: controller self-removed from group")
	ErrLostRace       = errors.New("ironcore: commit lost the linearization race; AutoRecover")
	ErrJoinSuperseded = errors.New("ironcore: external-commit join superseded; refetch GroupInfo")
	ErrNoGroup        = errors.New("ironcore: controller has no group state")
)
```

`NewController` derives the initial `curSA` when `g != nil` (founder); a joiner passes `g=nil` and the SA is derived inside `JoinViaWelcome`/`JoinViaExternalCommit`. `rotateSA`/`deriveCur`/`commitAndOrder`/`identityToLeaf`/`commitRemovesSelf`/`memberCommitBody` are unexported (full code given in N0/N4/N5 above and the validated reference implementation).

---

## Tasks (strict TDD, bite-sized, one commit each)

> Each task: write the failing test first (RED), implement minimally (GREEN), `gofmt -l` clean + `go vet` clean, then commit. Use `superpowers:test-driven-development`. Branch off `main` (do not commit on `main`).

### Task 1 — Read-only `Group` accessors (N0)
- [ ] RED: `mls/group/members_test.go` — build a small group (reuse Plan-9 test helpers in `package group`), assert `ActiveLeaves()` is ascending and excludes a blanked leaf (after a Remove commit), and `LeafCredential(leaf)` returns the expected basic-credential identity for a live leaf and an error for a blank/out-of-range leaf.
- [ ] GREEN: add `mls/group/members.go` exactly as N0.
- [ ] `nix develop -c go test ./mls/group/ -run 'ActiveLeaves|LeafCredential'`; gofmt+vet.
- [ ] Commit: `feat(group): read-only ActiveLeaves + LeafCredential accessors for the membership controller`.

### Task 2 — Controller scaffold: config, constructor, SA exposure, IsCommitter (N0/N1/N3/N7)
- [ ] RED: `ironcore/controller_test.go` — `founderNode` builds a 1-member founder `Controller`; assert `IsCommitter()` is true, `CurrentSA()` returns a 32-byte key, `PreviousSA()` `ok=false`, `Epoch()==0`. Add the `mkNode`/`founderNode`/`assertConverged`/`broadcast` harness helpers in this file (reuse Plan-10 `makeSigner`/`makeCred`/`makeLifetime`).
- [ ] GREEN: `ironcore/controller.go` — `ControllerConfig`, `Controller`, `NewController`, `Group`/`Epoch`/`IsCommitter`/`CurrentSA`/`PreviousSA`, the `Err*` sentinels, `deriveCur`/`rotateSA`. No `time.Now`, no goroutines.
- [ ] gofmt+vet; commit: `feat(ironcore): membership Controller scaffold (config, SA exposure, committer election)`.

### Task 3 — `commitAndOrder` + `HandleCommit` + self-removal scan (N4/N5)
- [ ] RED: a 2-member group (founder + one Welcome-joined node via the harness); founder issues a single-Add `Reconcile`-less raw `commitAndOrder` path is exercised indirectly — instead test `HandleCommit` round-trips a committer's commit and both converge (byte-equal EA), and that a commit removing a member makes that member's `HandleCommit` return `ErrSelfRemoved`.
- [ ] GREEN: `memberCommitBody`, `commitRemovesSelf`, `commitAndOrder`, `HandleCommit`.
- [ ] gofmt+vet; commit: `feat(ironcore): inbound HandleCommit + optimistic commit-and-order with self-removal detection`.

### Task 4 — `Reconcile` diff + entitlement + GATE 1 (lifecycle convergence) (N2)
- [ ] RED: **Gate 1 sim** `TestControllerLifecycle` — founder + 3 prospects (KeyPackages published via a `KeyPackageResolver` over a test directory); `Reconcile([0,1,2,3])` → broadcast → 3 joiners `JoinViaWelcome`; `assertConverged` (byte-equal EA + SA.Key + epoch). Then `Reconcile([0,1,3])` removes node-2 (it `HandleCommit`→`ErrSelfRemoved`); survivors converge. Assert a non-committer's `Reconcile` is a no-op (`Committed=false`).
- [ ] GREEN: `KeyPackageResolver`, `ReconcileResult`, `identityToLeaf`, `Reconcile` (diff, entitlement, handover-elect branch, by-value batching).
- [ ] gofmt+vet; commit: `feat(ironcore): control-plane-driven Reconcile (Add/Remove diff) + lifecycle convergence gate`.

### Task 5 — `Rekey` + GATE 3 (periodic rekey, PCS, make-before-break) (N3)
- [ ] RED: **Gate 3 sim** `TestControllerRekeyPCS` — converged 3-member group; committer `Rekey()` → broadcast → converge; assert `CurrentSA().Key` rotated, `PreviousSA()` exposes the pre-rekey key. Separately: remove a member, capture its stale SA, rekey/remove, assert the removed node's stale `SA.Key` ≠ the post-removal `SA.Key` (PCS). Assert a non-committer `Rekey()` returns `won=false, nil` (no-op).
- [ ] GREEN: `Rekey` (empty `commitAndOrder`, committer-gated).
- [ ] gofmt+vet; commit: `feat(ironcore): periodic PCS Rekey + make-before-break SA exposure gate`.

### Task 6 — GATE 2 (committer handover) (N1)
- [ ] RED: **Gate 2 sim** `TestControllerHandover` — 3-member group; `Reconcile` removing sitting committer node-0: assert node-0's own `Reconcile` is a no-op (cannot self-remove), the committer-elect node-1 commits the removal, node-0 `HandleCommit`→`ErrSelfRemoved`, `IsCommitter()` flips to node-1, node-1 drives a follow-on `Rekey` → converge.
- [ ] GREEN: confirm the N2 handover-elect branch already implemented in Task 4 satisfies this (no new code expected; add code only if the sim reveals a gap).
- [ ] gofmt+vet; commit: `test(ironcore): deterministic committer-handover convergence gate`.

### Task 7 — Join paths (`JoinViaWelcome` already used; `JoinViaExternalCommit`) (N6)
- [ ] RED: a node joins an existing converged group via `JoinViaExternalCommit` against the committer's `PublishGroupInfo()`, routed through a shared `MemorySequencer`; existing members `HandleCommit` the external commit; all converge. Assert a superseded external join (slot already decided by a different ref) returns `ErrJoinSuperseded`.
- [ ] GREEN: `JoinViaWelcome` (if not already from Task 4 harness), `JoinViaExternalCommit`, `PublishGroupInfo`.
- [ ] gofmt+vet; commit: `feat(ironcore): external-commit + Welcome join paths through the sequencer`.

### Task 8 — `AutoRecover` + GATE 4 (fork → auto-recovery) (N5/N6)
- [ ] RED: **Gate 4 sim** `TestControllerAutoRecovery` — 2-member group over a shared `MemorySequencer`; induce a fork (committer `Rekey` wins the slot; a second member's competing commit at the same epoch gets `ok=false`); the loser detects `ErrLostRace` and `AutoRecover(candidates, fetchGI)` onto `CanonicalCommit`; the canonical member `HandleCommit`s the recovery external commit; both converge (byte-equal EA + SA.Key) at the recovered epoch.
- [ ] GREEN: `AutoRecover` (wrap `c.g` in a transient `VNIGroup`, delegate to `RecoverViaExternalCommit`, adopt + re-derive SA).
- [ ] gofmt+vet; commit: `feat(ironcore): fork auto-recovery via external commit (Plan 11 sequencer + Plan 12 recovery)`.

### Task 9 — Invariant guards + full suite
- [ ] Verify the no-wallclock/no-goroutine invariant: `grep -nE 'time\.Now|go func|^\s*go [a-z]' ironcore/controller.go` prints nothing.
- [ ] `nix develop -c go test ./...` (full suite green); `nix develop -c go vet ./...`; `nix develop -c gofmt -l mls/ ironcore/` (nothing).
- [ ] `git status` — confirm only the intended new/changed files are present; **no `zz_*`/`zzz_*`/`throwaway_*` stragglers**.
- [ ] Commit: `test(ironcore): membership-controller invariants + full-suite green`.

---

## Definition of Done

- [ ] `mls/group/members.go` adds exactly the two read-only accessors (`ActiveLeaves`, `LeafCredential`); no other `mls/` change; unit-tested.
- [ ] `ironcore/controller.go` implements the full public API above; **no goroutines, no `time.Now()`**; not-concurrency-safe is documented; serialized per-Controller.
- [ ] **Gate 1 (lifecycle convergence):** N nodes form a VNI; the committer `Reconcile`s a series of adds/removes; all nodes converge (byte-equal `EpochAuthenticator` + ESP `SA.Key` + epoch) after each change.
- [ ] **Gate 2 (committer handover):** removing the sitting committer → the next-lowest surviving leaf becomes committer (`IsCommitter()` flips), drives the next change; all converge; the departing committer's `Reconcile` correctly no-ops on its own removal.
- [ ] **Gate 3 (periodic rekey + PCS):** committer `Rekey()` advances the epoch, `SA.Key` rotates, all converge, `PreviousSA()` exposes the prior SA (make-before-break); a removed member's stale SA ≠ the post-removal SA.
- [ ] **Gate 4 (auto-recovery):** induced fork → the losing committer detects `ok=false`/`ErrLostRace` and `AutoRecover`s via external commit onto the canonical branch; converges.
- [ ] All gates run under suite **0xF001** (X-Wing PQ) as primary; `go test ./...`, `go vet ./...`, `gofmt -l` all clean.
- [ ] `git status` shows only this plan + the intended source files; **no throwaway stragglers**.

---

## Notes for the remaining roadmap (post-Plan-13)

- **gRPC interop conformance harness** (design spec §6.4) — the `MLSClient` interop server (`interop/proto/mls_client.proto`) against OpenMLS + mls-rs for the **classical** suites; the X-Wing PQ suite uses self-generated vectors (no IANA registration yet). Orthogonal to the controller.
- **metalbond adapters** — metalbond implements the `DeliveryService` + `Ordering` ports in **its own** repo (design spec §3): a real per-VNI fan-out `DeliveryService` and a B1 `FencedSequencer` (or B2 consensus) backed by etcd / the Kubernetes control plane. The controller here is delivery-agnostic (it returns commit/welcome bytes for the caller to fan out); a thin metalbond glue loop will pump inbound `Incoming` into `HandleCommit` and schedule `Rekey`/`Reconcile` on its own timers.
- **`external_senders` extension (deferred MLS feature)** — an alternative membership model where metalnet's control plane is an authorized **external proposer** (emits Add/Remove proposals it cannot commit; a member commits them). This plan deliberately uses the **designated-committer-MEMBER** model (the committer creates Add/Remove directly from control-plane events) to avoid the extra MLS surface; `external_senders` is the future refinement if the control plane should propose without a committer-member relaying.
- **Stickier committer election (N2 caveat)** — leaf-index reuse after removals can move committer identity on Add. A stable per-member token (rather than raw leaf index) would make handover stickier; deferred as a refinement, not a correctness fix.
- **KeyPackage distribution & freshness** (design spec §12.5) — the `KeyPackageResolver` abstracts control-plane KeyPackage publication; lifetime/rotation policy and the `Clock`-driven freshness check are a follow-up.
- **Persistent/sealed `StateStore`** (design spec §9/§12.6) — on restart a node rejoins via `JoinViaExternalCommit` (already supported); an optional sealed store to mitigate rejoin storms is future work.
```
