# Encrypted Member Handshakes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a group member frame Commit/Proposal/Update handshakes as an AEAD-encrypted MLS `PrivateMessage` (RFC 9420 `encrypt_handshake`), so a metalbond reflector relaying them sees only ciphertext, with a per-VNI ironcore toggle defaulting ON.

**Architecture:** The `mls/framing` crypto already encrypts Commit/Proposal content (`ProtectPrivate`/`UnprotectPrivate`). This feature *routes* member handshakes through that path: the send side picks the wire format (and the transcript is computed under it); the receive side dispatches on the inbound `WireFormat`. External-commit/recovery stays `PublicMessage` (RFC-mandated). ironcore exposes a `HandshakePrivacy` config (zero value = Encrypted); the sim and gRPC conformance/OpenMLS e2e exercise it.

**Tech Stack:** Go (stdlib-only root module), Nix dev shell (`nix develop -c go ...` — Go is not on PATH), golangci-lint, the nested `interop/` gRPC module, OpenMLS e2e via `nix develop .#e2e`.

**Read first:** `docs/superpowers/specs/2026-06-28-encrypted-handshakes-design.md`.

**Conventions for every task:**
- Run Go via `nix develop -c go test ./...` etc. (never bare `go`).
- Keep the root module dependency-free; keep both modules golangci-lint clean.
- The 15 RFC KATs (`nix develop -c make kat`) and existing public-framing tests must stay green — `PublicMessage` remains the library default.
- Work on branch `feat/encrypted-handshakes` (already created). Commit after each task.

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `mls/framing/generate.go` | `SignCommit` — sign + transcript input | Modify: add `wf WireFormat` param |
| `mls/framing/private.go` | PrivateMessage seal/open | Modify: extract `sealPrivate`; add `AssembleCommitPrivate` |
| `mls/group/group.go` | `Group` state | Modify: add `encryptHandshakes`, `handshakeGeneration`; `SetEncryptHandshakes`; `sigPubByLeaf` |
| `mls/group/commit_gen.go` | Generate a Commit | Modify: pick wire format; branch Public/Private framing |
| `mls/group/process.go` | Process a Commit | Modify: dispatch on wire format; shared proposal-auth helper |
| `mls/group/propose.go` | `FrameProposal` | Modify: encrypt standalone proposals when enabled |
| `mls/group/external_commit.go` | External commit | Modify: `SignCommit` call passes Public (no behavior change) |
| `ironcore/controller.go` | Controller config + wiring | Modify: `HandshakePrivacy`; set flag on the group |
| `sim/scenario.go` | Scenario definitions | Modify: `EncryptHandshakes` field; `EncryptedChurn()` |
| `sim/client.go` | Sim actor → ironcore | Modify: thread the flag into `controllerCfg` |
| `sim/ds.go` | Reflector relay | Modify: count plaintext member handshakes |
| `sim/metrics.go` / `sim/invariant.go` | Metrics + invariants | Modify: `PlaintextHandshakeExposures` + invariant |
| `interop/server/server.go` | gRPC harness | Modify: honor `encrypt_handshake` (remove Unimplemented) |
| `interop/conformance_test.go` | Self-conformance gate | Modify: add encrypted subtests |
| `scripts/e2e-openmls.sh` + `scripts/e2e-configs/` | OpenMLS e2e | Modify: encrypt_handshake scenario on suite 1 |
| `README.md` | Feature matrix | Modify: move feature to supported |

---

## Task 1: framing — generalize `SignCommit`; add `AssembleCommitPrivate`

**Files:**
- Modify: `mls/framing/generate.go:19` (`SignCommit`)
- Modify: `mls/framing/private.go` (extract `sealPrivate`, add `AssembleCommitPrivate`)
- Modify: `mls/group/commit_gen.go:149`, `mls/group/external_commit.go:140` (callers pass `WireFormatPublicMessage`)
- Test: `mls/framing/private_test.go`, `mls/framing/generate_test.go`

- [ ] **Step 1: Write the failing test for `SignCommit` honoring the wire format**

Add to `mls/framing/generate_test.go`:

```go
func TestSignCommitWireFormatBinding(t *testing.T) {
	suite := mustSuite(t, 0x0001) // existing helper in framing tests; use the suite-1 lookup
	signer, pub := mustSigner(t, suite)
	gc := mustGroupContext(t, suite) // existing helper producing a minimal GroupContext
	fc := FramedContent{
		GroupID:     gc.GroupID,
		Epoch:       gc.Epoch,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 0},
		ContentType: ContentTypeCommit,
		Content:     []byte("commit-body"),
	}
	pubInput, _, err := SignCommit(suite, signer, &gc, fc, WireFormatPublicMessage)
	if err != nil {
		t.Fatal(err)
	}
	privInput, _, err := SignCommit(suite, signer, &gc, fc, WireFormatPrivateMessage)
	if err != nil {
		t.Fatal(err)
	}
	// confirmedInput begins with the 2-byte wire_format.
	if pubInput[1] != byte(WireFormatPublicMessage) {
		t.Fatalf("public input wire_format byte = %d", pubInput[1])
	}
	if privInput[1] != byte(WireFormatPrivateMessage) {
		t.Fatalf("private input wire_format byte = %d", privInput[1])
	}
	// The two transcript inputs must differ (wire_format is bound).
	if bytes.Equal(pubInput, privInput) {
		t.Fatal("SignCommit produced identical input for different wire formats")
	}
	_ = pub
}
```

If helpers `mustSuite`/`mustSigner`/`mustGroupContext` do not already exist in the framing test package, reuse whatever the existing `generate_test.go`/`private_test.go` use to build a suite, signer, and GroupContext (read those files first and mirror their setup). Add `import "bytes"` if missing.

- [ ] **Step 2: Run it — expect a compile failure**

Run: `nix develop -c go test ./mls/framing/ -run TestSignCommitWireFormatBinding`
Expected: FAIL — `too many arguments in call to SignCommit`.

- [ ] **Step 3: Generalize `SignCommit`**

In `mls/framing/generate.go`, change the signature and body to take `wf WireFormat`:

```go
// SignCommit signs FramedContentTBS for a commit under the given wire format and
// returns the ConfirmedTranscriptHashInput (wire_format ‖ FramedContent ‖
// signature<V>) plus the signature (RFC 9420 §6.1 / §8.2). The wire_format is
// part of both the signature TBS and the transcript input, so a commit framed as
// PrivateMessage produces a different transcript than the same commit as
// PublicMessage.
func SignCommit(suite cipher.Suite, signer crypto.Signer, gc *keyschedule.GroupContext, fc FramedContent, wf WireFormat) (confirmedInput, signature []byte, err error) {
	ac := AuthenticatedContent{WireFormat: wf, Content: fc}
	if err := ac.sign(suite, signer, gc); err != nil {
		return nil, nil, err
	}
	b := syntax.NewBuilder()
	b.WriteUint16(uint16(wf))
	if err := fc.marshal(b); err != nil {
		return nil, nil, err
	}
	if err := b.WriteOpaqueV(ac.Auth.Signature); err != nil {
		return nil, nil, err
	}
	return b.Bytes(), ac.Auth.Signature, nil
}
```

- [ ] **Step 4: Update the two callers to pass `WireFormatPublicMessage` (no behavior change)**

In `mls/group/commit_gen.go:149`:

```go
	confirmedInput, sig, err := framing.SignCommit(g.suite, g.signer, &gc, fc, framing.WireFormatPublicMessage)
```

In `mls/group/external_commit.go:140`:

```go
	confirmedInput, sig, err := framing.SignCommit(suite, signer, &gc, fc, framing.WireFormatPublicMessage)
```

- [ ] **Step 5: Run the binding test + the full framing/group suites — expect PASS**

Run: `nix develop -c go test ./mls/framing/ ./mls/group/`
Expected: PASS (existing commit/KAT behavior unchanged because both callers still use Public).

- [ ] **Step 6: Write the failing test for `AssembleCommitPrivate`**

Add to `mls/framing/private_test.go`:

```go
func TestAssembleCommitPrivateRoundTrip(t *testing.T) {
	suite := mustSuite(t, 0x0001)
	signer, _ := mustSigner(t, suite)
	gc := mustGroupContext(t, suite)
	st, senderDataSecret, sigPub := mustSecretTree(t, suite, signer) // leaf 0 tree + sig lookup
	fc := FramedContent{
		GroupID:     gc.GroupID,
		Epoch:       gc.Epoch,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 0},
		ContentType: ContentTypeCommit,
		Content:     []byte("commit-body"),
	}
	// Precompute signature + a dummy confirmation tag the way commit_gen does.
	_, sig, err := SignCommit(suite, signer, &gc, fc, WireFormatPrivateMessage)
	if err != nil {
		t.Fatal(err)
	}
	confTag := suite.MAC(make([]byte, suite.HashLen()), []byte("confirmed"))

	var guard [4]byte
	pm, err := AssembleCommitPrivate(suite, st, senderDataSecret, fc, 0, guard, 0, sig, confTag)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := UnprotectPrivate(suite, sigPub, &gc, st, senderDataSecret, pm)
	if err != nil {
		t.Fatalf("UnprotectPrivate: %v", err)
	}
	if ac.WireFormat != WireFormatPrivateMessage {
		t.Fatalf("ac.WireFormat = %d, want Private", ac.WireFormat)
	}
	if !bytes.Equal(ac.Content.Content, fc.Content) {
		t.Fatal("content mismatch after round trip")
	}
	if !bytes.Equal(ac.Auth.ConfirmationTag, confTag) {
		t.Fatal("confirmation_tag not recovered")
	}
}
```

Build `mustSecretTree` to mirror how `private_test.go` already constructs a `*keyschedule.SecretTree` + `senderDataSecret` + a `func(uint32) ([]byte, error)` signature-key lookup for the existing `ProtectPrivate`/`UnprotectPrivate` tests (read the file and reuse its setup; if such a helper exists, call it).

- [ ] **Step 7: Run it — expect a compile failure**

Run: `nix develop -c go test ./mls/framing/ -run TestAssembleCommitPrivateRoundTrip`
Expected: FAIL — `undefined: AssembleCommitPrivate`.

- [ ] **Step 8: Extract `sealPrivate` and add `AssembleCommitPrivate`**

In `mls/framing/private.go`, refactor `ProtectPrivate` so its AEAD half is a reusable helper, then add the assemble function. Replace the body of `ProtectPrivate` after the signing step with a call to `sealPrivate`, and add:

```go
// sealPrivate performs the two AEAD steps of PrivateMessage construction
// (content encryption with the ratchet key/nonce, then sender-data encryption)
// given an already-populated FramedContentAuthData. It is shared by
// ProtectPrivate (which signs first) and AssembleCommitPrivate (which is handed
// a precomputed signature + confirmation_tag).
func sealPrivate(suite cipher.Suite, st *keyschedule.SecretTree, senderDataSecret []byte, fc FramedContent, auth FramedContentAuthData, generation uint32, reuseGuard [4]byte, paddingSize int) (PrivateMessage, error) {
	key, nonce, err := st.KeyNonce(fc.Sender.LeafIndex, ratchetTypeFor(fc.ContentType), generation)
	if err != nil {
		return PrivateMessage{}, err
	}
	contentAAD, err := privateContentAAD(fc.GroupID, fc.Epoch, fc.ContentType, fc.AuthenticatedData)
	if err != nil {
		return PrivateMessage{}, err
	}
	pt, err := privateMessageContent(fc, auth, paddingSize)
	if err != nil {
		return PrivateMessage{}, err
	}
	ciphertext, err := suite.Seal(key, applyReuseGuard(nonce, reuseGuard), contentAAD, pt)
	if err != nil {
		return PrivateMessage{}, err
	}
	sdKey, sdNonce, err := keyschedule.SenderDataKeyNonce(suite, senderDataSecret, ciphertext)
	if err != nil {
		return PrivateMessage{}, err
	}
	sdAAD, err := senderDataAAD(fc.GroupID, fc.Epoch, fc.ContentType)
	if err != nil {
		return PrivateMessage{}, err
	}
	sdb := syntax.NewBuilder()
	senderData{LeafIndex: fc.Sender.LeafIndex, Generation: generation, ReuseGuard: reuseGuard}.marshal(sdb)
	encSD, err := suite.Seal(sdKey, sdNonce, sdAAD, sdb.Bytes())
	if err != nil {
		return PrivateMessage{}, err
	}
	return PrivateMessage{
		GroupID:             fc.GroupID,
		Epoch:               fc.Epoch,
		ContentType:         fc.ContentType,
		AuthenticatedData:   fc.AuthenticatedData,
		EncryptedSenderData: encSD,
		Ciphertext:          ciphertext,
	}, nil
}

// AssembleCommitPrivate frames fc as a PrivateMessage using a precomputed
// signature and confirmation_tag (the commit equivalent of AssembleCommitPublic).
// It does NOT sign — commit_gen.go already produced the signature feeding the
// transcript, and re-signing would diverge from that value.
func AssembleCommitPrivate(suite cipher.Suite, st *keyschedule.SecretTree, senderDataSecret []byte, fc FramedContent, generation uint32, reuseGuard [4]byte, paddingSize int, signature, confTag []byte) (PrivateMessage, error) {
	auth := FramedContentAuthData{Signature: signature, ConfirmationTag: confTag}
	return sealPrivate(suite, st, senderDataSecret, fc, auth, generation, reuseGuard, paddingSize)
}
```

Then change `ProtectPrivate`'s tail (everything after `ac.sign(...)` succeeds) to:

```go
	return sealPrivate(suite, st, senderDataSecret, fc, ac.Auth, generation, reuseGuard, paddingSize)
```

(Delete the now-duplicated AEAD block from `ProtectPrivate`.)

- [ ] **Step 9: Run the framing suite — expect PASS**

Run: `nix develop -c go test ./mls/framing/`
Expected: PASS (the refactor is behavior-preserving for `ProtectPrivate`; the new round-trip passes).

- [ ] **Step 10: Lint + commit**

```bash
nix develop -c golangci-lint run ./mls/framing/... ./mls/group/...
git add mls/framing/ mls/group/commit_gen.go mls/group/external_commit.go
git commit -m "feat(framing): wire-format-aware SignCommit + AssembleCommitPrivate"
```

---

## Task 2: group — handshake send flag, counter, and encrypted Commit framing

**Files:**
- Modify: `mls/group/group.go` (fields + `SetEncryptHandshakes` + `sigPubByLeaf`)
- Modify: `mls/group/commit_gen.go` (branch framing; reset counter)
- Test: `mls/group/encrypted_handshake_test.go` (new)

- [ ] **Step 1: Write the failing test — committer with encryption produces a Private commit**

Create `mls/group/encrypted_handshake_test.go`:

```go
package group

import (
	"testing"

	"github.com/trevex/mls-go/mls/framing"
)

// twoMemberGroup is a helper: returns a committer (leaf 0) and a member (leaf 1)
// in the same epoch-1 group, plus the suite. Reuse the existing test helpers in
// testutil_test.go / group_test.go that build a two-party group via NewGroup +
// Commit(Add) + JoinFromWelcome; do NOT hand-roll the tree.
func TestEncryptedCommitIsPrivateMessage(t *testing.T) {
	committer, _ := twoMemberGroup(t) // see helper note above
	committer.SetEncryptHandshakes(true)

	commit, _, err := committer.Commit(CommitOptions{})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(commit); err != nil {
		t.Fatal(err)
	}
	if m.WireFormat != framing.WireFormatPrivateMessage || m.Private == nil {
		t.Fatalf("encrypted commit wire_format = %d, want PrivateMessage", m.WireFormat)
	}
}
```

Implement `twoMemberGroup(t)` in this file by reusing the existing two-party setup helper from the group test package (read `mls/group/testutil_test.go` and `group_test.go`; there is already a pattern that creates a founder, adds a second member by-value, and returns both joined `*Group`s — wrap it). If no such helper exists, write one that calls `NewGroup`, `Commit(CommitOptions{ByValue: []Proposal{ProposeAdd(kp)}})`, and `JoinFromWelcome`.

- [ ] **Step 2: Run it — expect compile failure**

Run: `nix develop -c go test ./mls/group/ -run TestEncryptedCommitIsPrivateMessage`
Expected: FAIL — `committer.SetEncryptHandshakes undefined`.

- [ ] **Step 3: Add the Group fields, setter, and sig-lookup method**

In `mls/group/group.go`, add to the `Group` struct (next to `appGeneration`):

```go
	// encryptHandshakes makes this member frame its OWN Commit/Proposal/Update as
	// a PrivateMessage (RFC 9420 encrypt_handshake). Receive is always wire-format
	// agnostic; this only affects outbound member handshakes. Default false.
	encryptHandshakes bool
	// handshakeGeneration is the per-epoch monotonic counter for the handshake
	// ratchet (separate from appGeneration). Reset to 0 on every epoch change.
	handshakeGeneration uint32
```

Add methods (place near `OwnLeaf`):

```go
// SetEncryptHandshakes selects whether this member frames its own outbound
// handshakes (Commit/Proposal/Update) as encrypted PrivateMessages. Call it at
// create/join time. It never affects the receive path (which dispatches on the
// inbound wire format) nor external commits (always PublicMessage).
func (g *Group) SetEncryptHandshakes(v bool) { g.encryptHandshakes = v }

// sigPubByLeaf resolves a leaf index to its signature public key from the
// ratchet tree (the verifier callback for UnprotectPrivate).
func (g *Group) sigPubByLeaf(leaf uint32) ([]byte, error) {
	ln, err := g.tree.LeafNodeAt(leaf)
	if err != nil {
		return nil, err
	}
	return ln.SignatureKey, nil
}
```

- [ ] **Step 4: Branch the Commit framing on the flag**

In `mls/group/commit_gen.go`, replace the framing block (the `SignCommit` call through `commitBytes`) so the wire format is chosen up front and the assembly branches. Replace:

```go
	gc := g.groupContext
	confirmedInput, sig, err := framing.SignCommit(g.suite, g.signer, &gc, fc, framing.WireFormatPublicMessage)
```

with:

```go
	gc := g.groupContext
	wf := framing.WireFormatPublicMessage
	if g.encryptHandshakes {
		wf = framing.WireFormatPrivateMessage
	}
	confirmedInput, sig, err := framing.SignCommit(g.suite, g.signer, &gc, fc, wf)
```

Then replace the `AssembleCommitPublic` + `commitMLS` block with:

```go
	var commitMLS framing.MLSMessage
	if wf == framing.WireFormatPrivateMessage {
		var guard [4]byte
		if _, err := rand.Read(guard[:]); err != nil {
			return nil, nil, fmt.Errorf("group: Commit: rand.Read(guard): %w", err)
		}
		// Frame under the CURRENT (epoch-n) secret tree + sender-data secret,
		// BEFORE the atomic state swap below installs epoch n+1.
		privMsg, err := framing.AssembleCommitPrivate(g.suite, g.secretTree, g.epoch.SenderDataSecret, fc, g.handshakeGeneration, guard, 0, sig, confTag)
		if err != nil {
			return nil, nil, fmt.Errorf("group: Commit: AssembleCommitPrivate: %w", err)
		}
		g.handshakeGeneration++
		commitMLS = framing.MLSMessage{Version: tree.ProtocolVersionMLS10, WireFormat: framing.WireFormatPrivateMessage, Private: &privMsg}
	} else {
		pubMsg, err := framing.AssembleCommitPublic(g.suite, &gc, g.epoch.MembershipKey, fc, sig, confTag)
		if err != nil {
			return nil, nil, fmt.Errorf("group: Commit: AssembleCommitPublic: %w", err)
		}
		commitMLS = framing.MLSMessage{Version: tree.ProtocolVersionMLS10, WireFormat: framing.WireFormatPublicMessage, Public: &pubMsg}
	}
	commitBytes, err := commitMLS.MarshalMLS()
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: marshal commit MLSMessage: %w", err)
	}
```

In the same function's atomic-swap block (where `g.appGeneration = 0`), add:

```go
	g.handshakeGeneration = 0
```

- [ ] **Step 5: Run the test + full group suite — expect PASS**

Run: `nix develop -c go test ./mls/group/`
Expected: PASS — the encrypted commit decodes as PrivateMessage; all existing (public-default) tests unaffected.

- [ ] **Step 6: Lint + commit**

```bash
nix develop -c golangci-lint run ./mls/group/...
git add mls/group/group.go mls/group/commit_gen.go mls/group/encrypted_handshake_test.go
git commit -m "feat(group): frame own commits as PrivateMessage when encryptHandshakes is set"
```

---

## Task 3: group — receive Private commits (dispatch + round trip)

**Files:**
- Modify: `mls/group/process.go` (wire-format dispatch in `ProcessCommit`)
- Test: `mls/group/encrypted_handshake_test.go`

- [ ] **Step 1: Write the failing round-trip + binding tests (all three suites)**

Append to `mls/group/encrypted_handshake_test.go`:

```go
func TestEncryptedCommitRoundTripAllSuites(t *testing.T) {
	for _, id := range []uint16{0x0001, 0x0002, 0xF001} {
		id := id
		t.Run(suiteName(id), func(t *testing.T) {
			committer, member := twoMemberGroupSuite(t, id) // two-party group on this suite
			committer.SetEncryptHandshakes(true)

			commit, _, err := committer.Commit(CommitOptions{})
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if err := member.ProcessCommit(nil, commit); err != nil {
				t.Fatalf("ProcessCommit(private): %v", err)
			}
			if got, want := member.EpochAuthenticator(), committer.EpochAuthenticator(); !bytesEqual(got, want) {
				t.Fatal("epoch_authenticator mismatch after encrypted commit")
			}
			if member.Epoch() != committer.Epoch() {
				t.Fatalf("epoch mismatch: member=%d committer=%d", member.Epoch(), committer.Epoch())
			}
		})
	}
}

func TestWireFormatBindsTranscript(t *testing.T) {
	// Same logical empty commit, framed public vs private, must yield DIFFERENT
	// epoch_authenticators (proving wire_format is bound into the transcript).
	cPub, _ := twoMemberGroup(t)
	cPriv, _ := twoMemberGroup(t)
	if _, _, err := cPub.Commit(CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	cPriv.SetEncryptHandshakes(true)
	if _, _, err := cPriv.Commit(CommitOptions{}); err != nil {
		t.Fatal(err)
	}
	if bytesEqual(cPub.EpochAuthenticator(), cPriv.EpochAuthenticator()) {
		t.Fatal("public and private commits produced identical epoch_authenticator")
	}
}

func TestEncryptedCommitTamperRejected(t *testing.T) {
	committer, member := twoMemberGroup(t)
	committer.SetEncryptHandshakes(true)
	commit, _, err := committer.Commit(CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	commit[len(commit)-1] ^= 0xFF // flip a ciphertext byte
	if err := member.ProcessCommit(nil, commit); err == nil {
		t.Fatal("ProcessCommit accepted a tampered PrivateMessage commit")
	}
}
```

Provide `twoMemberGroupSuite(t, id)`, `suiteName`, and `bytesEqual` by mirroring existing helpers (the group tests already build per-suite groups for the KAT/round-trip tests — reuse that). `TestWireFormatBindsTranscript` is the key correctness assertion from the spec.

- [ ] **Step 2: Run — expect FAIL (`commit is not a PublicMessage`)**

Run: `nix develop -c go test ./mls/group/ -run 'TestEncryptedCommitRoundTrip|TestWireFormatBinds|TestEncryptedCommitTamper'`
Expected: FAIL — `ProcessCommit: commit is not a PublicMessage`.

- [ ] **Step 3: Add a wire-format-agnostic auth helper and dispatch in `ProcessCommit`**

In `mls/group/process.go`, add a helper:

```go
// authenticateCommit recovers the AuthenticatedContent of an inbound member
// commit, dispatching on its wire format. PrivateMessage commits are decrypted
// with the current epoch's secret tree; the recovered sender MUST be a member
// (external/new_member commits are PublicMessage by RFC 9420 — fail closed).
func (g *Group) authenticateCommit(m framing.MLSMessage) (framing.AuthenticatedContent, error) {
	gc := g.groupContext
	switch {
	case m.WireFormat == framing.WireFormatPublicMessage && m.Public != nil:
		leaf := m.Public.Content.Sender.LeafIndex
		ln, err := g.tree.LeafNodeAt(leaf)
		if err != nil {
			return framing.AuthenticatedContent{}, fmt.Errorf("committer leaf %d: %w", leaf, err)
		}
		return framing.UnprotectPublic(g.suite, ln.SignatureKey, &gc, g.epoch.MembershipKey, *m.Public)
	case m.WireFormat == framing.WireFormatPrivateMessage && m.Private != nil:
		ac, err := framing.UnprotectPrivate(g.suite, g.sigPubByLeaf, &gc, g.secretTree, g.epoch.SenderDataSecret, *m.Private)
		if err != nil {
			return framing.AuthenticatedContent{}, err
		}
		if ac.Content.Sender.Type != framing.SenderTypeMember {
			return framing.AuthenticatedContent{}, errors.New("framing: external sender in PrivateMessage commit")
		}
		return ac, nil
	default:
		return framing.AuthenticatedContent{}, errors.New("group: ProcessCommit: unsupported commit wire format")
	}
}
```

Then in `ProcessCommit`, replace step-2's hard Public requirement and the inline `UnprotectPublic` with dispatch. Replace:

```go
	if m.WireFormat != framing.WireFormatPublicMessage || m.Public == nil {
		return fmt.Errorf("group: ProcessCommit: commit is not a PublicMessage")
	}

	// Dispatch: new_member_commit (external joiner) is handled separately ...
	if m.Public.Content.Sender.Type == framing.SenderTypeNewMemberCommit {
		return g.processExternalCommit(m)
	}

	committerLeaf := m.Public.Content.Sender.LeafIndex
	committerLeafNode, err := g.tree.LeafNodeAt(committerLeaf)
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: committer leaf %d: %w", committerLeaf, err)
	}
	gc := g.groupContext
	ac, err := framing.UnprotectPublic(g.suite, committerLeafNode.SignatureKey, &gc, g.epoch.MembershipKey, *m.Public)
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: authenticate commit: %w", err)
	}
```

with:

```go
	// External joins are always PublicMessage with a new_member_commit sender.
	if m.WireFormat == framing.WireFormatPublicMessage && m.Public != nil &&
		m.Public.Content.Sender.Type == framing.SenderTypeNewMemberCommit {
		return g.processExternalCommit(m)
	}
	ac, err := g.authenticateCommit(m)
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: authenticate commit: %w", err)
	}
```

Ensure `errors` is imported in `process.go`. Any later reference to `committerLeaf` in `ProcessCommit` must use `ac.Content.Sender.LeafIndex` instead — read the rest of the function and update the variable usage accordingly (define `committerLeaf := ac.Content.Sender.LeafIndex` right after the auth call if needed).

Also reset the handshake counter on the receiver's epoch advance: find the line in `ProcessCommit`'s atomic state-commit where `g.appGeneration = 0` and add `g.handshakeGeneration = 0` next to it (symmetric with the committer in Task 2). A freshly-joined `Group` from `JoinFromWelcome` already has the zero value, so no change is needed there. Without this reset a member that processes several commits and *then* sends would emit handshakes at a stale, climbing generation — still decryptable (the generation rides in sender_data) but wasteful (the secret tree's `KeyNonce` is O(generation)) and asymmetric with `appGeneration`.

- [ ] **Step 4: Run the new tests + full group suite — expect PASS**

Run: `nix develop -c go test ./mls/group/`
Expected: PASS — round trip on all three suites; public/private transcripts differ; tamper rejected; existing tests green.

- [ ] **Step 5: Add the mixed-sequence test**

Append:

```go
func TestMixedPublicPrivateSequence(t *testing.T) {
	committer, member := twoMemberGroup(t)
	// Commit A: public.
	a, _, err := committer.Commit(CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := member.ProcessCommit(nil, a); err != nil {
		t.Fatal(err)
	}
	// Commits B, C: private.
	committer.SetEncryptHandshakes(true)
	for i := 0; i < 2; i++ {
		c, _, err := committer.Commit(CommitOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := member.ProcessCommit(nil, c); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	if !bytesEqual(member.EpochAuthenticator(), committer.EpochAuthenticator()) {
		t.Fatal("epoch_authenticator diverged across mixed public/private sequence")
	}
}
```

Run: `nix develop -c go test ./mls/group/ -run TestMixedPublicPrivateSequence`
Expected: PASS.

- [ ] **Step 6: Lint + commit**

```bash
nix develop -c golangci-lint run ./mls/group/...
git add mls/group/process.go mls/group/encrypted_handshake_test.go
git commit -m "feat(group): process PrivateMessage commits; bind wire_format in transcript"
```

---

## Task 4: group — encrypted standalone proposals + encrypted by-reference

**Files:**
- Modify: `mls/group/propose.go` (`FrameProposal` honors the flag)
- Modify: `mls/group/process.go` + `mls/group/commit_gen.go` (by-ref proposal auth dispatch)
- Test: `mls/group/encrypted_handshake_test.go`

- [ ] **Step 1: Write the failing test — a private Update proposal committed by reference**

Append:

```go
func TestEncryptedByReferenceProposal(t *testing.T) {
	committer, member := twoMemberGroup(t) // committer=leaf0, member=leaf1
	member.SetEncryptHandshakes(true)
	committer.SetEncryptHandshakes(true)

	// Member (leaf 1) frames a private Update proposal.
	upd, err := member.ProposeUpdate()
	if err != nil {
		t.Fatal(err)
	}
	propMsg, err := member.FrameProposal(upd)
	if err != nil {
		t.Fatal(err)
	}
	var pm framing.MLSMessage
	if err := pm.UnmarshalMLS(propMsg); err != nil {
		t.Fatal(err)
	}
	if pm.WireFormat != framing.WireFormatPrivateMessage {
		t.Fatalf("framed proposal wire_format = %d, want Private", pm.WireFormat)
	}

	// Committer includes it by reference and both advance together.
	commit, _, err := committer.Commit(CommitOptions{ByReference: [][]byte{propMsg}})
	if err != nil {
		t.Fatalf("Commit(by-ref private): %v", err)
	}
	if err := member.ProcessCommit([][]byte{propMsg}, commit); err != nil {
		t.Fatalf("ProcessCommit: %v", err)
	}
	if !bytesEqual(member.EpochAuthenticator(), committer.EpochAuthenticator()) {
		t.Fatal("epoch_authenticator mismatch with private by-reference proposal")
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `nix develop -c go test ./mls/group/ -run TestEncryptedByReferenceProposal`
Expected: FAIL — `FrameProposal` still emits Public, and `Commit`/`ProcessCommit` reject the non-Public by-reference entry.

- [ ] **Step 3: Make `FrameProposal` honor the flag**

In `mls/group/propose.go`, replace the framing tail of `FrameProposal` with a branch:

```go
	gc := g.groupContext
	if g.encryptHandshakes {
		var guard [4]byte
		if _, err := rand.Read(guard[:]); err != nil {
			return nil, err
		}
		pm, err := framing.ProtectPrivate(g.suite, g.signer, &gc, g.secretTree, g.epoch.SenderDataSecret, fc, g.handshakeGeneration, guard, 0, nil)
		if err != nil {
			return nil, err
		}
		g.handshakeGeneration++
		msg := framing.MLSMessage{Version: tree.ProtocolVersionMLS10, WireFormat: framing.WireFormatPrivateMessage, Private: &pm}
		return msg.MarshalMLS()
	}
	pm, err := framing.ProtectPublic(g.suite, g.signer, &gc, g.epoch.MembershipKey, fc, nil)
	if err != nil {
		return nil, err
	}
	msg := framing.MLSMessage{Version: tree.ProtocolVersionMLS10, WireFormat: framing.WireFormatPublicMessage, Public: &pm}
	return msg.MarshalMLS()
```

Add `"crypto/rand"` to `propose.go` imports. (Proposals carry no confirmation_tag, so the signing `ProtectPrivate` is exactly right — no AssembleCommitPrivate needed here.)

- [ ] **Step 4: Add a shared by-reference proposal authenticator and use it in both call sites**

In `mls/group/process.go`, add:

```go
// authenticateProposalMessage recovers an inbound by-reference proposal,
// dispatching on its wire format, and returns its ProposalRef (RefHash over the
// AuthenticatedContent), the parsed Proposal, and the sender leaf. The ref
// includes wire_format, so committer and processor compute matching refs for the
// same delivered bytes.
func (g *Group) authenticateProposalMessage(propBytes []byte) (ref []byte, prop Proposal, senderLeaf uint32, err error) {
	var m framing.MLSMessage
	if err = m.UnmarshalMLS(propBytes); err != nil {
		return nil, Proposal{}, 0, err
	}
	gc := g.groupContext
	var ac framing.AuthenticatedContent
	switch {
	case m.WireFormat == framing.WireFormatPublicMessage && m.Public != nil:
		leaf := m.Public.Content.Sender.LeafIndex
		ln, lerr := g.tree.LeafNodeAt(leaf)
		if lerr != nil {
			return nil, Proposal{}, 0, lerr
		}
		ac, err = framing.UnprotectPublic(g.suite, ln.SignatureKey, &gc, g.epoch.MembershipKey, *m.Public)
	case m.WireFormat == framing.WireFormatPrivateMessage && m.Private != nil:
		ac, err = framing.UnprotectPrivate(g.suite, g.sigPubByLeaf, &gc, g.secretTree, g.epoch.SenderDataSecret, *m.Private)
		if err == nil && ac.Content.Sender.Type != framing.SenderTypeMember {
			err = errors.New("framing: external sender in PrivateMessage proposal")
		}
	default:
		err = errors.New("group: unsupported proposal wire format")
	}
	if err != nil {
		return nil, Proposal{}, 0, err
	}
	acBytes, merr := ac.MarshalMLS()
	if merr != nil {
		return nil, Proposal{}, 0, merr
	}
	ref, err = g.suite.RefHash("MLS 1.0 Proposal Reference", acBytes)
	if err != nil {
		return nil, Proposal{}, 0, err
	}
	if err = prop.UnmarshalMLS(ac.Content.Content); err != nil {
		return nil, Proposal{}, 0, err
	}
	return ref, prop, ac.Content.Sender.LeafIndex, nil
}
```

Replace the by-reference loop body in `ProcessCommit` (step 1) with calls to this helper:

```go
	for idx, propBytes := range proposals {
		ref, prop, senderLeaf, err := g.authenticateProposalMessage(propBytes)
		if err != nil {
			return fmt.Errorf("group: ProcessCommit: proposal[%d]: %w", idx, err)
		}
		cache[string(ref)] = cachedProposal{proposal: prop, sender: senderLeaf}
	}
```

Replace the by-reference loop body in `Commit` (`commit_gen.go`) similarly, keeping the `cm.Proposals` append:

```go
	for idx, propBytes := range opt.ByReference {
		ref, prop, senderLeaf, err := g.authenticateProposalMessage(propBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("group: Commit: by-reference[%d]: %w", idx, err)
		}
		cache[string(ref)] = cachedProposal{proposal: prop, sender: senderLeaf}
		cm.Proposals = append(cm.Proposals, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: ref})
	}
```

Remove the now-unused local imports/vars left behind (e.g. if `framing` is still used elsewhere in the file it stays).

- [ ] **Step 5: Run the new test + full group suite — expect PASS**

Run: `nix develop -c go test ./mls/group/`
Expected: PASS — private by-reference proposal commits and converges; all prior tests green.

- [ ] **Step 6: Lint + commit**

```bash
nix develop -c golangci-lint run ./mls/group/...
git add mls/group/propose.go mls/group/process.go mls/group/commit_gen.go mls/group/encrypted_handshake_test.go
git commit -m "feat(group): encrypt standalone + by-reference proposals; shared proposal auth"
```

---

## Task 5: ironcore — `HandshakePrivacy` config (default Encrypted) + wiring

**Files:**
- Modify: `ironcore/controller.go` (`HandshakePrivacy` type, config field, set on the group)
- Test: `ironcore/encrypted_handshake_test.go` (new)

- [ ] **Step 1: Write the failing test — default VNI encrypts member commits; recovery stays public**

Create `ironcore/encrypted_handshake_test.go` mirroring the existing `controller_test.go` setup helpers (`founderNode`, `mkNode`, `pqSuite`, `testVNI`, sequencer):

```go
package ironcore_test

import (
	"testing"

	"github.com/trevex/mls-go/ironcore"
	"github.com/trevex/mls-go/ironcore/sequencer"
	"github.com/trevex/mls-go/mls/framing"
)

func TestControllerDefaultEncryptsMemberCommit(t *testing.T) {
	suite := pqSuite(t)
	seq := sequencer.NewMemorySequencer()
	// founderNode uses the default ControllerConfig (HandshakePrivacy zero value
	// = Encrypted), so its member commits must be PrivateMessage.
	founder := founderNode(t, suite, testVNI, "node-0", seq, nil)
	// Drive a self-rekey commit (no membership change) and inspect the wire bytes.
	res, err := founder.Reconcile(testCtx(), nil) // use the same ctx/desired-set helper the other tests use
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(res.CommitMsg); err != nil {
		t.Fatal(err)
	}
	if m.WireFormat != framing.WireFormatPrivateMessage {
		t.Fatalf("default controller commit wire_format = %d, want Private", m.WireFormat)
	}
}
```

If `founderNode` produces a single-member group that cannot self-commit via `Reconcile` with an empty desired set, instead build a two-node group the way `controller_test.go`'s membership tests do (founder adds a joiner), then have the founder issue a follow-up commit; inspect that commit's wire format. Reuse the existing helpers verbatim — do not invent new membership flows.

- [ ] **Step 2: Run — expect FAIL (commit is Public)**

Run: `nix develop -c go test ./ironcore/ -run TestControllerDefaultEncryptsMemberCommit`
Expected: FAIL — commit is `PublicMessage` (the controller does not yet set the flag).

- [ ] **Step 3: Add the `HandshakePrivacy` type + config field**

In `ironcore/controller.go`, near `ControllerConfig`:

```go
// HandshakePrivacy selects how a VNI frames its members' outbound handshakes.
// The zero value is Encrypted — metalnet's default — so a reflector relaying a
// member commit/proposal sees only ciphertext. External-commit recovery is
// always PublicMessage regardless (RFC 9420).
type HandshakePrivacy int

const (
	HandshakeEncrypted HandshakePrivacy = iota // default: member handshakes are PrivateMessage
	HandshakePlaintext                         // member handshakes are PublicMessage
)
```

Add the field to `ControllerConfig`:

```go
	// HandshakePrivacy selects PrivateMessage (default) vs PublicMessage framing
	// for this VNI's member handshakes. Zero value = HandshakeEncrypted.
	HandshakePrivacy HandshakePrivacy
```

- [ ] **Step 4: Apply the flag wherever the controller adopts a group**

In `ironcore/controller.go`, add a helper and call it from `NewController` (when `g != nil`) and from `JoinViaWelcome` (after the group is built), and anywhere else a `*group.Group` becomes `c.g`:

```go
// applyHandshakePrivacy sets the group's outbound-handshake framing from config.
func (c *Controller) applyHandshakePrivacy() {
	if c.g != nil {
		c.g.SetEncryptHandshakes(c.cfg.HandshakePrivacy != HandshakePlaintext)
	}
}
```

Call `c.applyHandshakePrivacy()` immediately after `c.g = g` (or after `NewController` constructs the controller with a non-nil group, and at the end of `JoinViaWelcome`/`RecoverViaExternalCommit`-adopt paths). Grep for assignments to `c.g` and cover each. Recovery's *external commit itself* is produced by `group.ExternalCommit`/`RecoverViaExternalCommit`, which always frames Public — no change needed there; only the adopted group's *future* commits follow the flag.

- [ ] **Step 5: Run the new test + full ironcore suite — expect PASS**

Run: `nix develop -c go test ./ironcore/...`
Expected: PASS — default controller emits Private commits; existing tests still converge (HandleCommit is wire-format agnostic). If any existing test decodes a commit expecting `PublicMessage`, set `HandshakePrivacy: ironcore.HandshakePlaintext` in that test's `ControllerConfig` to preserve its intent, and note it.

- [ ] **Step 6: Add the recovery-stays-public assertion**

Append to `ironcore/encrypted_handshake_test.go` a test that triggers `RecoverViaExternalCommit`/`AutoRecover` on an encrypted-default controller and asserts the produced recovery commit decodes as `framing.WireFormatPublicMessage` with a `new_member_commit` sender. Mirror the existing recovery test setup in `ironcore/recovery_test.go`.

Run: `nix develop -c go test ./ironcore/...`
Expected: PASS.

- [ ] **Step 7: Lint + commit**

```bash
nix develop -c golangci-lint run ./ironcore/...
git add ironcore/controller.go ironcore/encrypted_handshake_test.go
git commit -m "feat(ironcore): per-VNI HandshakePrivacy (default Encrypted)"
```

---

## Task 6: sim — `encrypted_churn` scenario + plaintext-exposure invariant

**Files:**
- Modify: `sim/scenario.go` (`EncryptHandshakes` field; `EncryptedChurn()`; add to `All()`)
- Modify: `sim/client.go` (thread the flag into `controllerCfg`)
- Modify: `sim/ds.go` (count plaintext member handshakes)
- Modify: `sim/metrics.go` (`PlaintextHandshakeExposures` counter)
- Modify: `sim/invariant.go` (fail if exposures > 0 in an encrypted scenario)
- Test: `sim/sim_test.go`

- [ ] **Step 1: Write the failing test**

Append to `sim/sim_test.go`:

```go
func TestEncryptedChurnHidesHandshakes(t *testing.T) {
	r := Run(EncryptedChurn(), 1)
	if !r.InvariantsHeld {
		t.Fatalf("encrypted_churn invariants failed: divergence=%v membership=%v packetLoss=%d exposures=%d",
			r.Divergence, r.Membership, len(r.PacketLoss), r.Metrics.PlaintextHandshakeExposures)
	}
	if r.Metrics.PlaintextHandshakeExposures != 0 {
		t.Fatalf("reflector observed %d plaintext member handshakes, want 0", r.Metrics.PlaintextHandshakeExposures)
	}
	if r.Metrics.CommitMsgs == 0 {
		t.Fatal("scenario produced no commits to protect")
	}
}
```

- [ ] **Step 2: Run — expect compile failure**

Run: `nix develop -c go test ./sim/ -run TestEncryptedChurnHidesHandshakes`
Expected: FAIL — `undefined: EncryptedChurn` / `PlaintextHandshakeExposures`.

- [ ] **Step 3: Add the scenario field + constructor**

In `sim/scenario.go`, add to the `Scenario` struct:

```go
	// EncryptHandshakes makes every VNI in this scenario frame member handshakes
	// as PrivateMessage (maps to ironcore HandshakePrivacy). Default false so the
	// other scenarios keep their existing PublicMessage behavior.
	EncryptHandshakes bool
```

Add the constructor (mirror `Nominal()` with churn enabled):

```go
// EncryptedChurn drives membership churn with encrypted member handshakes and
// asserts the reflectors never observe plaintext membership changes.
func EncryptedChurn() Scenario {
	s := Nominal()
	s.Name = "encrypted_churn"
	s.EncryptHandshakes = true
	return s
}
```

Add it to `All()`:

```go
func All() []Scenario {
	return []Scenario{Nominal(), Drops(), DSDown(), PartitionRecover(), BothRekey(), EncryptedChurn()}
}
```

- [ ] **Step 4: Thread the flag into the controller config**

In `sim/client.go`, give `Client` an `encryptHandshakes bool` field set at world construction from `scenario.EncryptHandshakes` (read how the client receives scenario-derived config — e.g. `W`, suite — and mirror it). Then in `controllerCfg`:

```go
func (c *Client) controllerCfg(ch uint32) ironcore.ControllerConfig {
	hp := ironcore.HandshakePlaintext
	if c.encryptHandshakes {
		hp = ironcore.HandshakeEncrypted
	}
	return ironcore.ControllerConfig{
		VNI:              ch,
		Suite:            c.suite,
		Ordering:         optimisticOrdering{},
		Clock:            fixedClock{},
		Validator:        group.BasicCredentialValidator{},
		Cred:             c.dir.cred(c.identity),
		Signer:           c.signer,
		Lifetime:         maxLifetime(),
		Resolve:          c.dir.resolver(ch),
		HandshakePrivacy: hp,
	}
}
```

(Explicitly defaulting non-encrypted scenarios to `HandshakePlaintext` keeps every existing scenario byte-for-byte identical, isolating the new behavior to `encrypted_churn`.)

- [ ] **Step 5: Add the metric + the reflector-side detector**

In `sim/metrics.go`, add to `Metrics`:

```go
	PlaintextHandshakeExposures int // member handshakes a reflector saw as PublicMessage in an encrypted VNI
```

In `sim/ds.go`, where the reflector ingests a relayed commit/proposal envelope, decode the wire format and count plaintext member handshakes when the scenario is encrypted. Add a helper the DS can call (the DS already holds a `*Metrics`); pass the scenario's `EncryptHandshakes` to the DS at construction (mirror how the DS gets other config). Detector:

```go
// observeHandshakePrivacy flags a member handshake that a reflector could read
// in cleartext while the VNI is configured to encrypt handshakes.
func (d *DS) observeHandshakePrivacy(env Envelope, m *Metrics) {
	if !d.encryptHandshakes {
		return
	}
	if env.Type != MsgCommit { // proposals ride inside by-value commits in this model
		return
	}
	var msg framing.MLSMessage
	if err := msg.UnmarshalMLS(env.Payload); err != nil {
		return // unparseable bytes are not a plaintext exposure
	}
	// new_member_commit (external join/recovery) is PublicMessage by RFC — ignore.
	if msg.WireFormat == framing.WireFormatPublicMessage && msg.Public != nil &&
		msg.Public.Content.Sender.Type != framing.SenderTypeNewMemberCommit {
		m.PlaintextHandshakeExposures++
	}
}
```

Call `d.observeHandshakePrivacy(env, metrics)` in the DS commit-ingest path. Add `framing "github.com/trevex/mls-go/mls/framing"` to `ds.go` imports and a `encryptHandshakes bool` field on `DS` set at construction.

- [ ] **Step 6: Add the invariant**

In `sim/invariant.go` (or wherever `Result.InvariantsHeld` is finalized in `sim.go`), fail the run if `metrics.PlaintextHandshakeExposures > 0`. Mirror the existing invariant wiring; e.g. in `sim.go` after `checker.Evaluate`:

```go
	if metrics.PlaintextHandshakeExposures > 0 {
		r.InvariantsHeld = false
	}
```

(Match the actual mechanism the other invariants use to flip `InvariantsHeld`/populate the result — read `invariant.go`/`sim.go` and follow it.)

- [ ] **Step 7: Run the encrypted scenario + full sim suite — expect PASS**

Run: `nix develop -c go test ./sim/`
Expected: PASS — `encrypted_churn` converges with zero exposures; existing scenarios unchanged.

- [ ] **Step 8: Lint + commit**

```bash
nix develop -c golangci-lint run ./sim/...
git add sim/
git commit -m "feat(sim): encrypted_churn scenario + plaintext-handshake-exposure invariant"
```

---

## Task 7: interop — honor `encrypt_handshake`; encrypted self-conformance subtests

**Files:**
- Modify: `interop/server/server.go` (remove the 3 Unimplemented rejections; set the flag)
- Modify: `interop/conformance_test.go` (encrypted subtests across suites)

- [ ] **Step 1: Make the server honor `encrypt_handshake`**

In `interop/server/server.go`:

`CreateGroup` — replace the rejection at line 124 with setting the flag after the group is built:

```go
	// (remove the `if req.EncryptHandshake { return Unimplemented }` block)
	...
	g, err := group.NewGroup(suite, req.GroupId, cred, signer, maxLifetime())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "NewGroup: %v", err)
	}
	g.SetEncryptHandshakes(req.EncryptHandshake)
```

`JoinGroup` — remove the rejection at line 189; after `JoinFromWelcome` succeeds, add `g.SetEncryptHandshakes(req.EncryptHandshake)`.

`ExternalJoin` — remove the rejection at line 397; after `group.ExternalCommit(...)` succeeds, add `g.SetEncryptHandshakes(req.EncryptHandshake)` (the external commit itself stays Public; the flag governs the joiner's *future* commits).

`HandleCommit` needs no change — `ProcessCommit` already dispatches on wire format.

- [ ] **Step 2: Build the interop module**

Run: `nix develop -c bash -c 'cd interop && go build ./...'`
Expected: builds clean.

- [ ] **Step 3: Add an encrypted-handshake conformance subtest**

In `interop/conformance_test.go`, add a test that runs a create→add→commit→handle cycle with `EncryptHandshake: true` across all three suites (0x0001, 0x0002, 0xF001), mirroring `TestUpdateCommit`/`TestThreePartyJoin` but setting `EncryptHandshake: true` on the `CreateGroupRequest`/`JoinGroupRequest`, and asserting (a) `HandleCommit` succeeds and (b) the returned commit message decodes as `WireFormatPrivateMessage`. Reuse the existing in-process client/bufconn harness and suite-iteration helper in that file.

```go
func TestEncryptedHandshakeCommit(t *testing.T) {
	for _, suiteID := range allConformanceSuites { // existing slice of the 3 suite ids
		suiteID := suiteID
		t.Run(suiteName(suiteID), func(t *testing.T) {
			// ... build two members with EncryptHandshake:true on Create/Join ...
			// ... member-0 commits an Add of member-1; assert commit is Private ...
			// ... member-1 HandleCommit succeeds; ExportSecret equality holds ...
		})
	}
}
```

Fill the body using the exact helpers the neighboring tests use (client construction, `CreateGroup`, `CreateKeyPackage`, `Commit`, `HandleCommit`, `ExportSecret`). The assertion that the commit is Private is the new coverage.

- [ ] **Step 4: Run the conformance gate — expect PASS**

Run: `nix develop -c bash -c 'cd interop && go test -count=1 ./...'`
Expected: PASS — existing 21 subtests plus the new encrypted subtests.

- [ ] **Step 5: Lint + commit**

```bash
(cd interop && nix develop -c golangci-lint run ./...)
git add interop/server/server.go interop/conformance_test.go
git commit -m "feat(interop): honor encrypt_handshake; encrypted conformance subtests"
```

---

## Task 8: OpenMLS e2e — encrypted-handshake scenario on suite 1

**Files:**
- Modify: `scripts/e2e-openmls.sh` and/or `scripts/e2e-configs/`
- Reference: `interop/README.md`, the e2e section of `docs/DEVELOPMENT.md`

- [ ] **Step 1: Inspect the existing e2e config + runner**

Read `scripts/e2e-openmls.sh`, `scripts/e2e-configs/commit.json`, and how the mlswg `test-runner` is invoked. Identify where a scenario sets `encrypt_handshake` (the mlswg runner config uses an `encrypt_handshake` boolean per scenario).

- [ ] **Step 2: Add an encrypted scenario config**

Create `scripts/e2e-configs/commit-encrypted.json` (or extend `commit.json` with an `encrypt_handshake: true` variant) covering a supported-only scenario on suite 1 (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`): create → add → commit → process, with `encrypt_handshake` set true, no PSK / no GroupContextExtensions / no across-epoch decryption (those remain unimplemented). Mirror the structure of the existing curated config.

- [ ] **Step 3: Wire it into the runner**

In `scripts/e2e-openmls.sh`, add the new config to the set of configs the script runs against OpenMLS's `interop_client` + our server, keeping the existing clone-if-absent/idempotent behavior and the all-role-assignments pass/fail gate.

- [ ] **Step 4: Run the e2e gate**

Run: `nix develop .#e2e -c bash scripts/e2e-openmls.sh`
Expected: exits 0 — every scenario (including the encrypted one) passes across all role assignments on suite 1. (This requires the Rust toolchain via the `e2e` Nix shell; it clones+builds OpenMLS on first run.)

- [ ] **Step 5: Commit**

```bash
git add scripts/e2e-openmls.sh scripts/e2e-configs/
git commit -m "test(e2e): encrypted-handshake interop scenario vs OpenMLS on suite 1"
```

---

## Task 9: docs — feature matrix + dev notes

**Files:**
- Modify: `README.md` (feature/limitation matrix)
- Modify: `docs/DEVELOPMENT.md` (if it lists the limitation)

- [ ] **Step 1: Move the feature from "Not yet implemented" to supported**

In `README.md`, remove the `**PrivateMessage** handshake framing (encrypt_handshake = true is rejected; …)` bullet from the "Not yet implemented" list and add a supported bullet, e.g.:

```markdown
- **PrivateMessage handshake framing** (`encrypt_handshake`): member
  Commit/Proposal/Update can be AEAD-encrypted so an untrusted delivery service
  sees only ciphertext. External-commit joins / recovery remain PublicMessage
  (RFC 9420). ironcore enables it per VNI (`HandshakePrivacy`, default Encrypted).
```

Update any sentence in the README that says handshakes are framed only as PublicMessage (e.g. the OpenMLS e2e paragraph) to note the encrypted scenario is now exercised.

- [ ] **Step 2: Update the dev guide if it references the limitation**

Grep `docs/DEVELOPMENT.md` for `encrypt_handshake` / "PublicMessage handshake" and update to reflect the new capability + the OpenMLS encrypted scenario.

- [ ] **Step 3: Full green sweep**

```bash
nix develop -c go test ./...
nix develop -c bash -c 'cd interop && go test -count=1 ./...'
nix develop -c make kat
nix develop -c make check-zero-dep
nix develop -c golangci-lint run ./... && (cd interop && nix develop -c golangci-lint run ./...)
```
Expected: all PASS / clean.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/DEVELOPMENT.md
git commit -m "docs: mark encrypted handshakes supported in the feature matrix"
```

---

## Final verification (after all tasks)

- [ ] Root tests, interop conformance, KATs, zero-dep, lint (both modules) all green (commands in Task 9 Step 3).
- [ ] OpenMLS e2e (Task 8 Step 4) exits 0.
- [ ] `sim` `encrypted_churn` reports `plaintext-handshake-exposures 0` with convergence + zero packet loss.
- [ ] `PublicMessage` remains the library default (a zero-config `NewGroup` still frames public); ironcore default is Encrypted.
