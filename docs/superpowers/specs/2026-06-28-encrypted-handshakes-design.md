# Encrypted Member Handshakes (PrivateMessage handshake framing) — Design

**Status:** approved (brainstorming) — pending implementation plan
**Date:** 2026-06-28
**Module:** `github.com/trevex/mls-go`

## Goal

Let a group member frame its **handshake** messages (Commit / Proposal / Update)
as an AEAD-encrypted MLS `PrivateMessage` instead of a signed-but-cleartext
`PublicMessage`, so an untrusted delivery service (metalbond route reflector)
relaying the message sees only ciphertext — not the membership change, the
joiner/leaver identities and credentials, or the leaf public keys.

This is the RFC 9420 `encrypt_handshake` capability. It is the one
"not-yet-implemented" feature that closes a real gap for the metalnet per-VNI
use case (membership-churn metadata confidentiality vs. the reflectors) without
disturbing the ordering or SA machinery the integration relies on.

## Motivation & context

- A group = a VNI; members are metalnet hosts; metalbond reflectors are the
  delivery service and are **untrusted for confidentiality** (RFC 9750 §5).
- Today handshakes are `PublicMessage`, so a reflector can read who is being
  added/removed from a VNI, their SPIFFE/PKI credentials, and leaf keys.
- The MLS exporter secret → ESP SA derivation is unaffected by handshake
  framing; encryption is orthogonal to the data-plane keys.

## Key architectural insight

The `mls/framing` **cryptography already exists**: `ProtectPrivate` /
`UnprotectPrivate` already handle the Commit and Proposal content types, the
handshake ratchet (`ratchetTypeFor`), and the commit `confirmation_tag`. They
are the same primitives application data already uses. **No new cryptography is
required.** The work is *routing* member handshakes through the existing private
path plus the supporting wiring.

### Wire format is a per-sender, per-message choice — not a group-wide mode

`confirmed_transcript_hash` chains `{wire_format, FramedContent, signature}` for
each commit, computed by both sender and receiver from that single message *as
sent*. Therefore:

- A **receiver** dispatches on the inbound message's `WireFormat` field
  (`Public` → existing path; `Private` → decrypt, then the same downstream
  logic). No prior agreement between members is needed.
- A **sender** independently chooses how to frame its own member handshakes.

Consequences: no consensus/migration problem; mixed public+private commits in
one group remain transcript-consistent; partial rollout "just works"; the mode
reduces to a simple sender-side flag.

### Hard RFC constraint (already satisfied)

External-commit joins and any external / `new_member_commit` sender **must** be
`PublicMessage` — the joiner is not yet in the secret tree, so there is no key
to encrypt under. The recovery path (`RecoverViaExternalCommit`) is an external
commit, so **recovery and joins stay in cleartext**. The privacy win is for
steady-state membership churn (Add / Remove / Update by existing members). This
is inherent to MLS, not a limitation chosen here. The code already enforces
Public for these paths (`external_commit.go`, `external_join.go`).

## Scope

Full vertical slice: `mls/group` capability, `ironcore` per-VNI toggle, the
`sim` model, the gRPC self-conformance gate, **and** an OpenMLS e2e scenario.

## Components

### `mls/group` (the bulk of the work)

**Receive path** (`process.go`, `propose.go`): dispatch on
`MLSMessage.WireFormat`. Today the commit path and the by-reference proposal
cache require `Public`; add a `Private` branch that calls `framing.UnprotectPrivate`
(using `g.secretTree`, `g.epoch.SenderDataSecret`, and a `signaturePub(leafIndex)`
lookup from the ratchet tree) to recover the `AuthenticatedContent`, then feed
the **same** downstream logic. By-reference proposals are decrypted the same way
so that `ProposalRef = RefHash(AuthenticatedContent)` (which includes
`wire_format`) is computed identically by committer and processor.

**Send path** (`commit_gen.go`, `propose.go`): a per-`Group` sender flag (set via
a `GroupOption` at create/join; **default = Public** to preserve the library
default). When enabled, a member Commit / Proposal / Update is framed via
`framing.ProtectPrivate` using a new per-epoch handshake generation counter
`g.handshakeGeneration` (mirrors the existing `g.appGeneration`), incremented per
outbound handshake and reset each epoch.

**Transcript correctness** (the one true hazard): `SignCommit` / `commit_gen`
currently hardcode `WireFormatPublicMessage` in the transcript input.
Generalize them to sign and build the `ConfirmedTranscriptHashInput` under the
*actual* wire format chosen. The receive side is correct for free:
`UnprotectPrivate` returns `ac.WireFormat = Private`, and the existing
`ac.MarshalMLS()` → `keyschedule.SplitAuthenticatedContent` then derives the
right input automatically.

**Fail-closed guard:** a recovered `Private` message whose sender resolves to
external / `new_member_commit` is rejected (it cannot decrypt anyway).

### `ironcore`

- `ControllerConfig` gains a `HandshakePrivacy` enum whose **zero value =
  `Encrypted`** — the metalnet default is ON without callers setting anything; a
  `Plaintext` value opts out. Maps to the group send flag.
- Send path frames member commits/proposals private when enabled.
  `AutoRecover` / external-commit **always force Public**, ignoring the setting
  (a requested encrypted external commit is a forced-Public no-op override, not
  an error).
- Receive (`HandleCommit`) becomes wire-format-agnostic via the group receive
  change. `CommitRef = Hash(commitMsg)` is unchanged (it hashes the transmitted
  bytes, encrypted or not), so the sequencer / ordering / fork detection are
  untouched.

### `sim`

- New `encrypted_churn` scenario.
- New invariant + metric `plaintext-handshake-exposures`, which must be `0`:
  every reflector-relayed member handshake in an encrypted VNI is observed as
  `WireFormatPrivateMessage`. The existing convergence and zero-packet-loss
  invariants continue to hold.

### `interop`

- The gRPC harness honors `encrypt_handshake = true` (currently rejected) by
  setting the group send flag.
- The self-conformance gate adds encrypted-handshake subtests across all three
  suites (0x0001 / 0x0002 / 0xF001).
- `scripts/e2e-openmls` gains an `encrypt_handshake` scenario on suite 1: our
  `PrivateMessage` commits decode in OpenMLS and vice-versa.

## Data flow (send → relay → receive), encrypted member commit

1. Committer builds `FramedContent` (member sender), signs it under the chosen
   `wire_format = Private`, and computes `confirmed_transcript_hash` from that.
2. `framing.ProtectPrivate` AEAD-encrypts the content with the handshake ratchet
   key/nonce at `(leaf, handshakeGeneration)`, plus the sender-data AEAD.
3. ironcore broadcasts the opaque `PrivateMessage` bytes; the reflector orders by
   `CommitRef = Hash(bytes)` and relays ciphertext.
4. Each receiver dispatches on `WireFormat = Private`, runs `UnprotectPrivate`
   (recovering `ac.WireFormat = Private`), then the existing commit-processing
   logic; transcript and `epoch_authenticator` match the committer.

## Error handling

- AEAD failure (wrong epoch's secret tree, tampering) → existing
  `UnprotectPrivate` errors ("sender data open" / "content open"), wrapped with a
  `ProcessCommit` context.
- Handshake-ratchet generation / `reuse_guard` reuse → same handling as
  application data; `g.handshakeGeneration` resets per epoch alongside
  `appGeneration`.
- External/new-member sender arriving as `Private` → rejected (fail closed).

## Testing & validation

**`mls/group`:** round-trip Add/Remove/Update proposal and a by-value Commit
framed Private across all three suites, asserting identical `epoch_authenticator`
at committer and receivers; wire-format binding (same logical commit Public vs
Private ⇒ *different* `epoch_authenticator`); a mixed Public→Private→Private
sequence stays consistent; tampered-ciphertext and external-sender-as-Private are
rejected.

**`ironcore`:** a default (`Encrypted`) VNI processes Add→Update→Remove to
convergence with on-wire commit bytes `WireFormatPrivateMessage`; recovery still
works and its external commit is `Public`; SA derivation unchanged.

**`sim`:** `encrypted_churn` asserts `plaintext-handshake-exposures == 0` with
convergence and zero-packet-loss still holding.

**`interop`:** encrypted subtests across all three suites in the self-conformance
gate; an OpenMLS e2e `encrypt_handshake` scenario on suite 1.

**Gates that stay green:** zero-dependency root, golangci-lint (both modules),
the 15 RFC KATs, and all existing public-framing tests (Public remains the
library default — no regression).

## Alternatives considered

- **In-band policy via a GroupContext extension** (bind a required wire format in
  group context so joiners learn it cryptographically). Rejected for now: it
  pulls in `GroupContextExtensionsProposal` (itself unimplemented) and is
  unnecessary because the per-sender model needs no agreement and ironcore
  configures all members of a VNI identically. Noted as future hardening.
- **Group-wide negotiated mode.** Unnecessary given the per-sender insight.

## Non-goals

- PSK, ReInit, Branch, external-signer, `NewMemberAddProposal`,
  `GroupContextExtensionsProposal` (separate not-implemented features).
- Encrypting the external-commit / recovery path (RFC-prohibited).
- Hiding the *fact* that a handshake occurred or its size/timing (only the
  contents are protected; padding policy is out of scope beyond what
  `ProtectPrivate` already offers).
