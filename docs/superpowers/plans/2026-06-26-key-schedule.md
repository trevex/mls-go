# Key Schedule / Secret Tree / Transcript Hashes / PSK (Plan 5 of 8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the RFC 9420 §8 key schedule and §9 secret tree, plus the §8.2/§6.1 transcript hashes and §8.4 PSK aggregation, all gated by their official KAT vectors. Concretely: the `GroupContext` wire object (§8.1); the `psk_secret` chain (§8.4); the per-epoch derivation from `init_secret`/`commit_secret`/`psk_secret` into `joiner_secret`, `welcome_secret`, `epoch_secret`, and every epoch-derived secret (`sender_data`, `encryption`, `exporter`, `external`, `confirmation`, `membership`, `resumption`, `epoch_authenticator`, next `init_secret`), the `external_pub` HPKE keypair derivation, and the `MLS-Exporter` function (§8.5); the secret tree's per-leaf handshake/application ratchets and the `sender_data` key/nonce (§9/§9.1); and the `confirmed_transcript_hash`/`interim_transcript_hash` updates with `confirmation_tag` (§8.2/§6.1). The four KATs `psk_secret.json`, `key-schedule.json`, `secret-tree.json`, `transcript-hashes.json` are the authoritative acceptance tests.

**Architecture:** A new package **`mls/keyschedule`** holds all of this. Justification: these objects form a single cohesive responsibility (epoch secret evolution) that sits *above* `mls/cipher` (it consumes `Suite.Extract`/`ExpandWithLabel`/`DeriveSecret`/`DeriveTreeSecret`/`DeriveKeyPair`/`MAC`/`Hash`) and *beside* `mls/tree` (it reuses `tree.ProtocolVersion`, `tree.Extension`, and the node-index math `tree.Root`/`Left`/`Right` for the secret tree). It cannot live in `cipher` (which must stay a pure primitive registry with no dependency on `tree`) nor in `tree` (wrong altitude; tree is the ratchet-tree data model). `keyschedule` imports `cipher`, `tree`, `syntax`; nothing imports `keyschedule`, so there is no cycle. New types follow the established codec convention — unexported `marshal(*syntax.Builder) error` + package-level `decodeX(*syntax.Cursor) (X, error)` + exported `MarshalMLS()`/`UnmarshalMLS()` wrappers (top-level `Unmarshal` enforces `Cursor.Empty()`).

This plan also makes two small, justified additions to existing packages (each its own TDD task):
- **`mls/cipher`**: `Suite.Extract`, `Suite.AEADKeySize`, `Suite.AEADNonceSize`, `Suite.DeriveKeyPair` (the §9 secret tree needs AEAD `Nk`/`Nn`; the key schedule needs `KDF.Extract` and `external_pub` derivation).
- **`mls/tree`**: exported `Extension.MarshalTo` / `DecodeExtension` wrappers so `keyschedule` can embed an `Extension extensions<V>` vector in `GroupContext`.

**Tech Stack:** Go 1.26 standard library only (`crypto/hkdf`, `crypto/hmac` already wrapped by `cipher`; `fmt`, `bytes`/`encoding/hex` in tests). Builds on `mls/syntax` (Builder/Cursor + generic `WriteVectorV`/`ReadVectorV`), `mls/cipher` (`Suite`, `Lookup`, `CipherSuite`, `ExpandWithLabel`, `DeriveSecret`, `DeriveTreeSecret`, `Hash`, `MAC`, `HashLen`, `NewHash`), `mls/tree` (`ProtocolVersion`, `ProtocolVersionMLS10`, `Extension`, `Root`, `Left`, `Right`), and `mls/internal/katutil` (`HexBytes`, `Load`).

**Spec reference:** RFC 9420 §6 (framing — only the subset needed to slice a transcript input), §6.1 (content authentication / `confirmation_tag`), §8 (key schedule), §8.1 (GroupContext), §8.2 (transcript hashes), §8.4 (PSKs), §8.5 (exporters), §9 / §9.1 (secret tree, ratchets, sender data). KAT format: <https://github.com/mlswg/mls-implementations/blob/main/test-vectors.md>.

> **Go invocation convention:** Go is **not** on `PATH`. Every Go command runs through the nix devshell, e.g. `nix develop -c go test ./mls/keyschedule/`, `nix develop -c go vet ./mls/...`, `nix develop -c gofmt -l mls/`. Use this form everywhere below.

---

## Design notes (read before implementing)

These facts are pinned **verbatim from RFC 9420 and verified byte-for-byte against the live KAT vectors** (joiner/welcome/epoch/sender-data/init/authentication/external_pub/exporter from `key-schedule.json` epoch 0, the 1-PSK case from `psk_secret.json`, sender-data + 1-leaf and 8-leaf trees + generation-15 ratchet from `secret-tree.json`, and the full transcript update from `transcript-hashes.json` were all reproduced during planning). Get them exactly right or the KATs will not pass.

### N0. The `KDF.Extract` argument order is **swapped** relative to Go's `crypto/hkdf`
RFC notation is `KDF.Extract(salt, IKM)`. Go's `crypto/hkdf.Extract[H](h func() H, secret, salt []byte)` takes the **IKM as `secret`** and the salt second. Therefore the new `cipher.Suite.Extract(salt, ikm)` MUST call `hkdf.Extract(s.NewHash, ikm, salt)` — IKM first, salt second. Every "Extract" below uses this `Suite.Extract(salt, ikm)` signature.

### N1. Key schedule (RFC 9420 §8, Figure 22) — exact order and labels
```
            init_secret_[n-1]                       (salt, "from the top")
commit_secret -> KDF.Extract                        (IKM, "from the left")
            -> ExpandWithLabel(., "joiner", GroupContext_[n], KDF.Nh) = joiner_secret
            joiner_secret                           (salt)
psk_secret(or 0) -> KDF.Extract                     (IKM)
            +-> DeriveSecret(., "welcome")          = welcome_secret
            -> ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh) = epoch_secret
            +-> DeriveSecret(., <label>)            = <secret>   (Table 4)
            -> DeriveSecret(., "init")              = init_secret_[n]
```
So: `joiner = ExpandWithLabel(Extract(salt=init_secret, ikm=commit_secret), "joiner", gc, Nh)`; `member = Extract(salt=joiner, ikm=psk_secret)`; `welcome = DeriveSecret(member, "welcome")`; `epoch = ExpandWithLabel(member, "epoch", gc, Nh)`. `commit_secret` defaults to the all-zero `KDF.Nh` vector when absent; `psk_secret` defaults to the all-zero vector (its §8.4 `psk_secret_[0]` value). `KDF.Nh == Suite.HashLen()`.

**Table 4 — epoch-derived secrets** (`secret = DeriveSecret(epoch_secret, Label)`), exact label strings:

| Label | Secret |
|---|---|
| `"sender data"` | `sender_data_secret` |
| `"encryption"` | `encryption_secret` |
| `"exporter"` | `exporter_secret` |
| `"external"` | `external_secret` |
| `"confirm"` | `confirmation_key` |
| `"membership"` | `membership_key` |
| `"resumption"` | `resumption_psk` |
| `"authentication"` | `epoch_authenticator` |

Plus `init_secret_[n] = DeriveSecret(epoch_secret, "init")`. **Note the label/field-name mismatch**: label `"confirm"` → `confirmation_key`, `"authentication"` → `epoch_authenticator`, `"resumption"` → `resumption_psk`. Do **not** use `"sender data secret"`/`"confirmation key"`/etc. (a web summary hallucinated those — the table above is the verbatim RFC).

### N2. `external_pub` (RFC 9420 §8)
`external_priv, external_pub = KEM.DeriveKeyPair(external_secret)`. Implemented via the new `Suite.DeriveKeyPair(external_secret)` which wraps `hpke.KEM.DeriveKeyPair(ikm)` and returns the serialized public key (`sk.PublicKey().Bytes()`). For suite 1 (X25519) this is the 32-byte raw public key, matching the KAT.

### N3. `MLS-Exporter` (RFC 9420 §8.5)
```
MLS-Exporter(Label, Context, Length) =
    ExpandWithLabel(DeriveSecret(exporter_secret, Label), "exported", Hash(Context), Length)
```
The inner secret is `DeriveSecret(exporter_secret, Label)`; the outer expand uses the **literal label `"exported"`** and the **hash of the context** (not the raw context). In the `key-schedule.json` `exporter` sub-case, `label` and `context` are raw byte strings (hex), `length` is the output length, and `secret` is the **expected output** (the input is the epoch's `exporter_secret`).

### N4. `psk_secret` chain (RFC 9420 §8.4, Figure 24)
```
PreSharedKeyID:
  PSKType psktype;                       // external(1), resumption(2)
  case external:   opaque psk_id<V>;
  case resumption: ResumptionPSKUsage usage; opaque psk_group_id<V>; uint64 psk_epoch;
  opaque psk_nonce<V>;                   // always present, trailing
PSKLabel: { PreSharedKeyID id; uint16 index; uint16 count; }

psk_extracted_[i] = KDF.Extract(0, psk_[i])                                  // salt = 0
psk_input_[i]     = ExpandWithLabel(psk_extracted_[i], "derived psk", PSKLabel_[i], KDF.Nh)
psk_secret_[0]    = 0                                                        // all-zero KDF.Nh
psk_secret_[i+1]  = KDF.Extract(psk_input_[i], psk_secret_[i])               // salt = psk_input, IKM = running secret
psk_secret        = psk_secret_[n]
```
`index` is the 0-based position in the `psks` array; `count` is `len(psks)`. With zero PSKs, `psk_secret` is the all-zero `KDF.Nh` vector. In `Suite.Extract(salt, ikm)` terms: `psk_extracted = Extract(nil, psk)` (nil/empty salt is HKDF's "0"); `psk_secret_next = Extract(psk_input, psk_secret)`. The `psk_secret.json` PSKs are all **external** type (`psktype=1`, fields `psk_id`/`psk`/`psk_nonce`).

### N5. Secret tree (RFC 9420 §9, Figures 25/26) and ratchets (§9.1)
- The tree has `len(leaves)` leaves; `encryption_secret` is the secret at the **root node** `tree.Root(nLeaves)`. Walk down: `left_child_secret = ExpandWithLabel(node_secret, "tree", "left", Nh)`, `right_child_secret = ExpandWithLabel(node_secret, "tree", "right", Nh)` (context is the ASCII string `left`/`right`). For a 1-leaf tree, `Root(1)==0==leaf 0`, so leaf 0's node secret **is** `encryption_secret` (no expansion) — verified against the KAT.
- **Leaf `i` sits at node index `2*i`** (`tree.Left` returns `ok=false` at a leaf). At each leaf node: `handshake_ratchet_secret_[0] = ExpandWithLabel(leaf_secret, "handshake", "", Nh)`, `application_ratchet_secret_[0] = ExpandWithLabel(leaf_secret, "application", "", Nh)`.
- Ratchet forward with `DeriveTreeSecret(Secret, Label, Generation, Length) = ExpandWithLabel(Secret, Label, encode_uint32(Generation), Length)`:
  ```
  ratchet_key_[N]_[j]    = DeriveTreeSecret(ratchet_secret_[N]_[j], "key",    j, AEAD.Nk)
  ratchet_nonce_[N]_[j]  = DeriveTreeSecret(ratchet_secret_[N]_[j], "nonce",  j, AEAD.Nn)
  ratchet_secret_[N]_[j+1] = DeriveTreeSecret(ratchet_secret_[N]_[j], "secret", j, KDF.Nh)
  ```
  `Generation` is **the current secret's index `j`** in all three calls (so the `key`/`nonce` at generation `j` and the `secret` that advances to `j+1` all use context `j`). The KAT lists sparse generations per leaf (e.g. `{0, 15}`), so advance the running secret from 0 up to the requested generation.

### N6. Sender data key/nonce (RFC 9420 §9.1)
```
ciphertext_sample = ciphertext[0 .. KDF.Nh-1]      // whole ciphertext if shorter
sender_data_key   = ExpandWithLabel(sender_data_secret, "key",   ciphertext_sample, AEAD.Nk)
sender_data_nonce = ExpandWithLabel(sender_data_secret, "nonce", ciphertext_sample, AEAD.Nn)
```

### N7. AEAD `Nk`/`Nn` (RFC 9180 §7.3)
`crypto/hpke.AEAD` exposes only `ID()` (no size accessors — confirmed via `go doc crypto/hpke.AEAD`). Map by AEAD id (empirically `AES128GCM().ID()==0x1`, `AES256GCM().ID()==0x2`, `ChaCha20Poly1305().ID()==0x3`):

| AEAD id | AEAD | Nk | Nn |
|---|---|---|---|
| `0x0001` | AES-128-GCM | 16 | 12 |
| `0x0002` | AES-256-GCM | 32 | 12 |
| `0x0003` | ChaCha20Poly1305 | 32 | 12 |

So registered suites 1/2 → Nk=16, Nn=12; suite 0xF001 → Nk=32, Nn=12.

### N8. Transcript hashes (RFC 9420 §8.2) and confirmation tag (§6.1)
```
ConfirmedTranscriptHashInput { WireFormat wire_format; FramedContent content; opaque signature<V>; }   // content_type == commit
InterimTranscriptHashInput   { MAC confirmation_tag; }                                                  // MAC = opaque<V>

confirmed_transcript_hash_[n] = Hash(interim_transcript_hash_[n-1] || ConfirmedTranscriptHashInput_[n])
interim_transcript_hash_[n]   = Hash(confirmed_transcript_hash_[n]   || InterimTranscriptHashInput_[n])
confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)        // §6.1
```
The KAT supplies the serialized **`AuthenticatedContent`** = `WireFormat wire_format || FramedContent content || FramedContentAuthData auth`, where for a Commit `auth = opaque signature<V> || MAC confirmation_tag<V>`. **`ConfirmedTranscriptHashInput` is exactly the `AuthenticatedContent` with the trailing `confirmation_tag<V>` field removed** (it is `wire_format || content || signature`, i.e. everything before the final field). Because `confirmation_tag` is the last field and is a MAC of fixed length `KDF.Nh`, its serialized field length is `len(WriteOpaqueV(make([]byte, HashLen)))` — so we peel it from the end **without parsing the FramedContent/Commit body** (full framing is Plan 7). This was decoded and verified against the live vector (the trailing 33 bytes `0x20 || <32-byte tag>` split off cleanly and the resulting confirmed/interim hashes matched). Cross-check: `MAC(confirmation_key, confirmed_after)` must equal the peeled `confirmation_tag`; the interim update wraps that same `confirmation_tag` as `opaque<V>`.

### N9. `GroupContext` (RFC 9420 §8.1) — full struct (note the leading two enums)
```
struct {
    ProtocolVersion version = mls10;   // uint16
    CipherSuite cipher_suite;          // uint16
    opaque group_id<V>;
    uint64 epoch;
    opaque tree_hash<V>;
    opaque confirmed_transcript_hash<V>;
    Extension extensions<V>;
} GroupContext;
```
Verified: `key-schedule.json` epoch 0 `group_context` = `0001`(version) `0001`(suite) `20…`(group_id<V>) `00…00`(epoch uint64) `20…`(tree_hash<V>) `20…`(confirmed<V>) `00`(empty extensions<V>). `epoch` equals the 0-based index in the `epochs` array. All key-schedule vectors have empty `extensions`.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `mls/cipher/keyschedule.go` | Create | `Suite.Extract`, `Suite.AEADKeySize`, `Suite.AEADNonceSize`, `Suite.DeriveKeyPair`. |
| `mls/cipher/keyschedule_test.go` | Create | `package cipher` unit tests for the four new methods. |
| `mls/tree/leaf.go` | Edit | Add exported `Extension.MarshalTo` + `DecodeExtension` wrappers. |
| `mls/tree/leaf_test.go` | Edit | Add a round-trip test through the exported `MarshalTo`/`DecodeExtension`. |
| `mls/keyschedule/context.go` | Create | `GroupContext` + marshal/decode + `MarshalMLS`/`UnmarshalMLS`. |
| `mls/keyschedule/context_test.go` | Create | `package keyschedule` round-trip + fixed-vector byte test. |
| `mls/keyschedule/psk.go` | Create | `PSKType`, `ResumptionPSKUsage`, `PreSharedKeyID`, `PSK`, `pskLabel`, `PSKSecret`. |
| `mls/keyschedule/psk_test.go` | Create | `package keyschedule` PreSharedKeyID round-trip + zero-PSK unit test. |
| `mls/keyschedule/psk_kat_test.go` | Create | `package keyschedule_test` — `psk_secret.json` KAT (gate). |
| `mls/keyschedule/schedule.go` | Create | `EpochSecrets`, `JoinerSecret`, `DeriveEpochSecrets`, `ExternalPub`, `MLSExporter`. |
| `mls/keyschedule/schedule_test.go` | Create | `package keyschedule` unit test (zero-PSK chain, exporter). |
| `mls/keyschedule/schedule_kat_test.go` | Create | `package keyschedule_test` — `key-schedule.json` KAT (gate). |
| `mls/keyschedule/secrettree.go` | Create | `SenderDataKeyNonce`, `SecretTree`, `RatchetType`, `KeyNonce`. |
| `mls/keyschedule/secrettree_test.go` | Create | `package keyschedule` unit test (1-leaf root, ratchet advance). |
| `mls/keyschedule/secrettree_kat_test.go` | Create | `package keyschedule_test` — `secret-tree.json` KAT (gate). |
| `mls/keyschedule/transcript.go` | Create | `ConfirmationTag`, `ConfirmedTranscriptHash`, `InterimTranscriptHash`, `SplitAuthenticatedContent`. |
| `mls/keyschedule/transcript_kat_test.go` | Create | `package keyschedule_test` — `transcript-hashes.json` KAT (gate). |
| `mls/testdata/psk_secret.json` | Vendor (curl) | Official KAT. |
| `mls/testdata/key-schedule.json` | Vendor (curl) | Official KAT. |
| `mls/testdata/secret-tree.json` | Vendor (curl) | Official KAT. |
| `mls/testdata/transcript-hashes.json` | Vendor (curl) | Official KAT. |

> Unit-test files are `package keyschedule`/`package cipher`/`package tree` (internal) so they can exercise unexported helpers (`marshal`, `pskLabel`, `deriveNode`). KAT files are `package keyschedule_test` (external). Go allows both packages in one directory.

Vendor the KATs up front:
```sh
for f in psk_secret key-schedule secret-tree transcript-hashes; do
  curl -fsSL -o mls/testdata/$f.json \
    https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/$f.json
done
```

---

## Task 0: `cipher` primitives — `Extract`, AEAD sizes, `DeriveKeyPair`

**Files:** Create `mls/cipher/keyschedule.go`, `mls/cipher/keyschedule_test.go`. Vendor the four KAT JSONs (above) in this task so later tasks can load them.

- [ ] **Step 1: Write the failing test.** Create `mls/cipher/keyschedule_test.go`:

```go
package cipher

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAEADSizes(t *testing.T) {
	for _, tc := range []struct {
		id         CipherSuite
		nk, nn     int
	}{
		{X25519_AES128GCM_SHA256_Ed25519, 16, 12},
		{P256_AES128GCM_SHA256_P256, 16, 12},
		{XWING_AES256GCM_SHA256_Ed25519, 32, 12},
	} {
		s, ok := Lookup(tc.id)
		if !ok {
			t.Fatalf("suite %#x not registered", tc.id)
		}
		if got := s.AEADKeySize(); got != tc.nk {
			t.Errorf("suite %#x AEADKeySize=%d want %d", tc.id, got, tc.nk)
		}
		if got := s.AEADNonceSize(); got != tc.nn {
			t.Errorf("suite %#x AEADNonceSize=%d want %d", tc.id, got, tc.nn)
		}
	}
}

func TestExtractMatchesKAT(t *testing.T) {
	// key-schedule.json case 0, epoch 0: Extract(salt=initial_init_secret,
	// IKM=commit_secret) then ExpandWithLabel("joiner", group_context) == joiner_secret.
	s, _ := Lookup(X25519_AES128GCM_SHA256_Ed25519)
	initSecret := mustHex(t, "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e")
	commit := mustHex(t, "a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509")
	gc := mustHex(t, "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00")
	prk, err := s.Extract(initSecret, commit)
	if err != nil {
		t.Fatal(err)
	}
	joiner, err := s.ExpandWithLabel(prk, "joiner", gc, s.HashLen())
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "4fb996ba26b29a70f3ce6c310151ce8701cb812d027f4d4bbf5cc4e9f884638d")
	if !bytes.Equal(joiner, want) {
		t.Fatalf("joiner=%x want %x", joiner, want)
	}
}

func TestDeriveKeyPairMatchesKAT(t *testing.T) {
	// key-schedule.json case 0, epoch 0: DeriveKeyPair(external_secret).pub == external_pub.
	s, _ := Lookup(X25519_AES128GCM_SHA256_Ed25519)
	external := mustHex(t, "b5cb5666cfb9c501ed76715c6ed1cafbed5061cd6b86898ae5d3fd4cb05abb26")
	_, pub, err := s.DeriveKeyPair(external)
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "640117516be304ac1160933c894a6df9290231f1843f3685c124fc42c785c02c")
	if !bytes.Equal(pub, want) {
		t.Fatalf("external_pub=%x want %x", pub, want)
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/cipher/ -run 'TestAEADSizes|TestExtractMatchesKAT|TestDeriveKeyPairMatchesKAT'` → FAIL (`s.AEADKeySize undefined`, etc.).

- [ ] **Step 3: Implement `mls/cipher/keyschedule.go`:**

```go
package cipher

import "crypto/hkdf"

// Extract implements the MLS key schedule's KDF.Extract (RFC 9420 §8): it
// returns a pseudorandom key of length KDF.Nh.
//
// NOTE on argument order: the RFC writes KDF.Extract(salt, IKM), but Go's
// crypto/hkdf.Extract takes the IKM ("secret") first and the salt second.
// This wrapper presents the RFC order (salt, ikm) and swaps internally.
func (s Suite) Extract(salt, ikm []byte) ([]byte, error) {
	return hkdf.Extract(s.NewHash, ikm, salt)
}

// AEADKeySize returns AEAD.Nk (the AEAD key length in bytes, RFC 9180 §7.3) for
// the suite's AEAD.
func (s Suite) AEADKeySize() int {
	switch s.aead.ID() {
	case 0x0001: // AES-128-GCM
		return 16
	case 0x0002, 0x0003: // AES-256-GCM, ChaCha20Poly1305
		return 32
	default:
		return 0
	}
}

// AEADNonceSize returns AEAD.Nn (the AEAD nonce length in bytes, RFC 9180 §7.3).
// Every AEAD used by an MLS cipher suite uses a 12-byte nonce.
func (s Suite) AEADNonceSize() int {
	switch s.aead.ID() {
	case 0x0001, 0x0002, 0x0003:
		return 12
	default:
		return 0
	}
}

// DeriveKeyPair deterministically derives an HPKE key pair from ikm
// (RFC 9180 DeriveKeyPair), returning the serialized private and public keys
// (the MLS HPKEPrivateKey / HPKEPublicKey encodings). Used to derive external_pub
// from external_secret (RFC 9420 §8).
func (s Suite) DeriveKeyPair(ikm []byte) (priv, pub []byte, err error) {
	sk, err := s.kem.DeriveKeyPair(ikm)
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := sk.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return privBytes, sk.PublicKey().Bytes(), nil
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/cipher/` → PASS.
- [ ] **Step 5: Vendor KATs** with the `curl` loop above; confirm the four files exist under `mls/testdata/`.
- [ ] **Step 6: Vet + format.** `nix develop -c go vet ./mls/cipher/` and `nix develop -c gofmt -l mls/cipher/` (no output).
- [ ] **Step 7: Commit.** `feat(cipher): add KDF.Extract, AEAD sizes, DeriveKeyPair for the key schedule` (include the four vendored KAT files). End the message with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.

---

## Task 1: `tree` — export `Extension` codec helpers

**Files:** Edit `mls/tree/leaf.go`, `mls/tree/leaf_test.go`.

- [ ] **Step 1: Write the failing test.** Append to `mls/tree/leaf_test.go` (package `tree`):

```go
func TestExtensionExportedCodec(t *testing.T) {
	in := Extension{ExtensionType: 0x0005, ExtensionData: []byte("data")}
	b := syntax.NewBuilder()
	if err := in.MarshalTo(b); err != nil {
		t.Fatal(err)
	}
	c := syntax.NewCursor(b.Bytes())
	out, err := DecodeExtension(c)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Empty() {
		t.Fatal("trailing bytes")
	}
	if out.ExtensionType != in.ExtensionType || string(out.ExtensionData) != "data" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}
```
(Ensure `leaf_test.go` imports `"github.com/trevex/mls-go/mls/syntax"`.)

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/tree/ -run TestExtensionExportedCodec` → FAIL (`in.MarshalTo undefined`).

- [ ] **Step 3: Implement.** Add to `mls/tree/leaf.go`, just after `decodeExtension`:

```go
// MarshalTo writes the Extension into b (RFC 9420 §7.2). Exported so that other
// packages (e.g. mls/keyschedule, for GroupContext.extensions<V>) can embed an
// Extension vector via syntax.WriteVectorV.
func (e Extension) MarshalTo(b *syntax.Builder) error { return e.marshal(b) }

// DecodeExtension reads one Extension from c. Exported counterpart to MarshalTo,
// suitable as the element decoder for syntax.ReadVectorV.
func DecodeExtension(c *syntax.Cursor) (Extension, error) { return decodeExtension(c) }
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/tree/` → PASS.
- [ ] **Step 5: Vet + format.** `nix develop -c go vet ./mls/tree/`, `nix develop -c gofmt -l mls/tree/`.
- [ ] **Step 6: Commit.** `feat(tree): export Extension.MarshalTo/DecodeExtension for GroupContext` + trailer.

---

## Task 2: `GroupContext` (§8.1)

**Files:** Create `mls/keyschedule/context.go`, `mls/keyschedule/context_test.go`.

- [ ] **Step 1: Write the failing test.** Create `mls/keyschedule/context_test.go` (package `keyschedule`):

```go
package keyschedule

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/tree"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGroupContextFixedVector(t *testing.T) {
	// key-schedule.json case 0, epoch 0.
	gc := GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:                 hx(t, "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"),
		Epoch:                   0,
		TreeHash:                hx(t, "9769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818"),
		ConfirmedTranscriptHash: hx(t, "5e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f"),
	}
	enc, err := gc.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	want := hx(t, "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00")
	if !bytes.Equal(enc, want) {
		t.Fatalf("marshal=%x want %x", enc, want)
	}
	var out GroupContext
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	re, _ := out.MarshalMLS()
	if !bytes.Equal(re, want) {
		t.Fatalf("round-trip mismatch: %x", re)
	}
}

func TestGroupContextWithExtensions(t *testing.T) {
	gc := GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:                 []byte("g"),
		Epoch:                   7,
		TreeHash:                []byte("th"),
		ConfirmedTranscriptHash: []byte("cth"),
		Extensions:              []tree.Extension{{ExtensionType: 0x0003, ExtensionData: []byte("x")}},
	}
	enc, err := gc.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	var out GroupContext
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if len(out.Extensions) != 1 || out.Extensions[0].ExtensionType != 0x0003 ||
		string(out.Extensions[0].ExtensionData) != "x" || out.Epoch != 7 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if err := out.UnmarshalMLS(append(enc, 0x00)); err == nil {
		t.Fatal("expected trailing-byte error")
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/keyschedule/` → FAIL (`undefined: GroupContext`).

- [ ] **Step 3: Implement `mls/keyschedule/context.go`:**

```go
// Package keyschedule implements the RFC 9420 §8 key schedule, the §9 secret
// tree, the §8.2/§6.1 transcript hashes, and the §8.4 pre-shared-key
// aggregation.
package keyschedule

import (
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/syntax"
	"github.com/trevex/mls-go/mls/tree"
)

// GroupContext summarizes the group state hashed into the key schedule
// (RFC 9420 §8.1):
//
//	struct {
//	    ProtocolVersion version = mls10;
//	    CipherSuite cipher_suite;
//	    opaque group_id<V>;
//	    uint64 epoch;
//	    opaque tree_hash<V>;
//	    opaque confirmed_transcript_hash<V>;
//	    Extension extensions<V>;
//	} GroupContext;
type GroupContext struct {
	Version                 tree.ProtocolVersion
	CipherSuite             cipher.CipherSuite
	GroupID                 []byte
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
	Extensions              []tree.Extension
}

func (gc GroupContext) marshal(b *syntax.Builder) error {
	b.WriteUint16(uint16(gc.Version))
	b.WriteUint16(uint16(gc.CipherSuite))
	if err := b.WriteOpaqueV(gc.GroupID); err != nil {
		return err
	}
	b.WriteUint64(gc.Epoch)
	if err := b.WriteOpaqueV(gc.TreeHash); err != nil {
		return err
	}
	if err := b.WriteOpaqueV(gc.ConfirmedTranscriptHash); err != nil {
		return err
	}
	return syntax.WriteVectorV(b, gc.Extensions, func(b *syntax.Builder, e tree.Extension) error {
		return e.MarshalTo(b)
	})
}

func decodeGroupContext(c *syntax.Cursor) (GroupContext, error) {
	var gc GroupContext
	v, err := c.ReadUint16()
	if err != nil {
		return gc, err
	}
	gc.Version = tree.ProtocolVersion(v)
	cs, err := c.ReadUint16()
	if err != nil {
		return gc, err
	}
	gc.CipherSuite = cipher.CipherSuite(cs)
	if gc.GroupID, err = c.ReadOpaqueV(); err != nil {
		return gc, err
	}
	if gc.Epoch, err = c.ReadUint64(); err != nil {
		return gc, err
	}
	if gc.TreeHash, err = c.ReadOpaqueV(); err != nil {
		return gc, err
	}
	if gc.ConfirmedTranscriptHash, err = c.ReadOpaqueV(); err != nil {
		return gc, err
	}
	if gc.Extensions, err = syntax.ReadVectorV(c, tree.DecodeExtension); err != nil {
		return gc, err
	}
	return gc, nil
}

// MarshalMLS encodes the GroupContext to its MLS wire form.
func (gc GroupContext) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := gc.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a GroupContext, rejecting trailing bytes.
func (gc *GroupContext) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeGroupContext(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("keyschedule: trailing bytes after GroupContext")
	}
	*gc = v
	return nil
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/keyschedule/` → PASS.
- [ ] **Step 5: Vet + format.** `nix develop -c go vet ./mls/keyschedule/`, `nix develop -c gofmt -l mls/keyschedule/`.
- [ ] **Step 6: Commit.** `feat(keyschedule): GroupContext marshal/unmarshal (RFC 9420 §8.1)` + trailer.

---

## Task 3: PSK secret aggregation (§8.4) + `psk_secret.json` KAT

**Files:** Create `mls/keyschedule/psk.go`, `mls/keyschedule/psk_test.go`, `mls/keyschedule/psk_kat_test.go`.

- [ ] **Step 1: Write the failing tests.** Create `mls/keyschedule/psk_test.go` (package `keyschedule`):

```go
package keyschedule

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/syntax"
)

func TestPreSharedKeyIDExternalRoundTrip(t *testing.T) {
	in := PreSharedKeyID{
		PSKType:  PSKTypeExternal,
		PSKID:    []byte("id"),
		PSKNonce: []byte("nonce"),
	}
	b := syntax.NewBuilder()
	if err := in.marshal(b); err != nil {
		t.Fatal(err)
	}
	c := syntax.NewCursor(b.Bytes())
	out, err := decodePreSharedKeyID(c)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Empty() || out.PSKType != PSKTypeExternal ||
		string(out.PSKID) != "id" || string(out.PSKNonce) != "nonce" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestPreSharedKeyIDResumptionRoundTrip(t *testing.T) {
	in := PreSharedKeyID{
		PSKType:    PSKTypeResumption,
		Usage:      ResumptionPSKUsageApplication,
		PSKGroupID: []byte("g"),
		PSKEpoch:   42,
		PSKNonce:   []byte("n"),
	}
	b := syntax.NewBuilder()
	if err := in.marshal(b); err != nil {
		t.Fatal(err)
	}
	c := syntax.NewCursor(b.Bytes())
	out, err := decodePreSharedKeyID(c)
	if err != nil {
		t.Fatal(err)
	}
	if out.PSKType != PSKTypeResumption || out.Usage != ResumptionPSKUsageApplication ||
		string(out.PSKGroupID) != "g" || out.PSKEpoch != 42 || string(out.PSKNonce) != "n" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestPSKSecretEmptyIsZero(t *testing.T) {
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	got, err := PSKSecret(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, make([]byte, s.HashLen())) {
		t.Fatalf("empty psk_secret=%x want all-zero", got)
	}
}
```

Create `mls/keyschedule/psk_kat_test.go` (package `keyschedule_test`):

```go
package keyschedule_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/internal/katutil"
	"github.com/trevex/mls-go/mls/keyschedule"
)

type pskKATEntry struct {
	PSKID    katutil.HexBytes `json:"psk_id"`
	PSK      katutil.HexBytes `json:"psk"`
	PSKNonce katutil.HexBytes `json:"psk_nonce"`
}

type pskKATCase struct {
	CipherSuite uint16           `json:"cipher_suite"`
	PSKs        []pskKATEntry    `json:"psks"`
	PSKSecret   katutil.HexBytes `json:"psk_secret"`
}

func TestPSKSecretKAT(t *testing.T) {
	var cases []pskKATCase
	katutil.Load(t, "psk_secret.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no psk_secret vectors loaded")
	}
	executed := 0
	for idx, c := range cases {
		t.Run(fmt.Sprintf("case=%d/suite=%d", idx, c.CipherSuite), func(t *testing.T) {
			s, ok := cipher.Lookup(cipher.CipherSuite(c.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", c.CipherSuite)
			}
			executed++
			psks := make([]keyschedule.PSK, len(c.PSKs))
			for i, p := range c.PSKs {
				psks[i] = keyschedule.PSK{
					ID: keyschedule.PreSharedKeyID{
						PSKType:  keyschedule.PSKTypeExternal,
						PSKID:    p.PSKID,
						PSKNonce: p.PSKNonce,
					},
					PSK: p.PSK,
				}
			}
			got, err := keyschedule.PSKSecret(s, psks)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, c.PSKSecret) {
				t.Fatalf("psk_secret=%x want %x", got, []byte(c.PSKSecret))
			}
		})
	}
	if executed == 0 {
		t.Fatal("no vectors executed (all skipped) — check cipher suite registration")
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/keyschedule/` → FAIL (`undefined: PreSharedKeyID`).

- [ ] **Step 3: Implement `mls/keyschedule/psk.go`:**

```go
package keyschedule

import (
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/syntax"
)

// PSKType designates how a PSK was provisioned (RFC 9420 §8.4).
type PSKType uint8

const (
	PSKTypeReserved   PSKType = 0
	PSKTypeExternal   PSKType = 1
	PSKTypeResumption PSKType = 2
)

// ResumptionPSKUsage classifies a resumption PSK (RFC 9420 §8.4).
type ResumptionPSKUsage uint8

const (
	ResumptionPSKUsageReserved    ResumptionPSKUsage = 0
	ResumptionPSKUsageApplication ResumptionPSKUsage = 1
	ResumptionPSKUsageReinit      ResumptionPSKUsage = 2
	ResumptionPSKUsageBranch      ResumptionPSKUsage = 3
)

// PreSharedKeyID identifies one injected PSK (RFC 9420 §8.4):
//
//	struct {
//	    PSKType psktype;
//	    select (psktype) {
//	        case external:   opaque psk_id<V>;
//	        case resumption: ResumptionPSKUsage usage; opaque psk_group_id<V>; uint64 psk_epoch;
//	    };
//	    opaque psk_nonce<V>;
//	} PreSharedKeyID;
type PreSharedKeyID struct {
	PSKType PSKType
	// external:
	PSKID []byte
	// resumption:
	Usage      ResumptionPSKUsage
	PSKGroupID []byte
	PSKEpoch   uint64
	// both:
	PSKNonce []byte
}

func (p PreSharedKeyID) marshal(b *syntax.Builder) error {
	b.WriteUint8(uint8(p.PSKType))
	switch p.PSKType {
	case PSKTypeExternal:
		if err := b.WriteOpaqueV(p.PSKID); err != nil {
			return err
		}
	case PSKTypeResumption:
		b.WriteUint8(uint8(p.Usage))
		if err := b.WriteOpaqueV(p.PSKGroupID); err != nil {
			return err
		}
		b.WriteUint64(p.PSKEpoch)
	default:
		return fmt.Errorf("keyschedule: invalid psk_type %d", p.PSKType)
	}
	return b.WriteOpaqueV(p.PSKNonce)
}

func decodePreSharedKeyID(c *syntax.Cursor) (PreSharedKeyID, error) {
	var p PreSharedKeyID
	t, err := c.ReadUint8()
	if err != nil {
		return p, err
	}
	p.PSKType = PSKType(t)
	switch p.PSKType {
	case PSKTypeExternal:
		if p.PSKID, err = c.ReadOpaqueV(); err != nil {
			return p, err
		}
	case PSKTypeResumption:
		u, err := c.ReadUint8()
		if err != nil {
			return p, err
		}
		p.Usage = ResumptionPSKUsage(u)
		if p.PSKGroupID, err = c.ReadOpaqueV(); err != nil {
			return p, err
		}
		if p.PSKEpoch, err = c.ReadUint64(); err != nil {
			return p, err
		}
	default:
		return p, fmt.Errorf("keyschedule: invalid psk_type %d", p.PSKType)
	}
	if p.PSKNonce, err = c.ReadOpaqueV(); err != nil {
		return p, err
	}
	return p, nil
}

// pskLabel builds PSKLabel = struct{ PreSharedKeyID id; uint16 index; uint16
// count; } (RFC 9420 §8.4).
func pskLabel(id PreSharedKeyID, index, count uint16) ([]byte, error) {
	b := syntax.NewBuilder()
	if err := id.marshal(b); err != nil {
		return nil, err
	}
	b.WriteUint16(index)
	b.WriteUint16(count)
	return b.Bytes(), nil
}

// PSK pairs a PreSharedKeyID with its secret value.
type PSK struct {
	ID  PreSharedKeyID
	PSK []byte
}

// PSKSecret aggregates psks into psk_secret (RFC 9420 §8.4, Figure 24). With no
// PSKs it returns the all-zero vector of length KDF.Nh (psk_secret_[0]).
func PSKSecret(suite cipher.Suite, psks []PSK) ([]byte, error) {
	nh := suite.HashLen()
	pskSecret := make([]byte, nh) // psk_secret_[0] = 0
	count := uint16(len(psks))
	for i, p := range psks {
		// psk_extracted_[i] = KDF.Extract(0, psk_[i])
		pskExtracted, err := suite.Extract(nil, p.PSK)
		if err != nil {
			return nil, err
		}
		label, err := pskLabel(p.ID, uint16(i), count)
		if err != nil {
			return nil, err
		}
		// psk_input_[i] = ExpandWithLabel(psk_extracted_[i], "derived psk", PSKLabel, KDF.Nh)
		pskInput, err := suite.ExpandWithLabel(pskExtracted, "derived psk", label, nh)
		if err != nil {
			return nil, err
		}
		// psk_secret_[i+1] = KDF.Extract(psk_input_[i], psk_secret_[i])
		pskSecret, err = suite.Extract(pskInput, pskSecret)
		if err != nil {
			return nil, err
		}
	}
	return pskSecret, nil
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/keyschedule/` → PASS (the KAT now exercises 0..10-PSK cases for suites 1 and 2; suites 3–7 skipped, `executed > 0`).
- [ ] **Step 5: Vet + format.** `nix develop -c go vet ./mls/keyschedule/`, `nix develop -c gofmt -l mls/keyschedule/`.
- [ ] **Step 6: Commit.** `feat(keyschedule): PSK secret aggregation + psk_secret KAT (RFC 9420 §8.4)` + trailer.

---

## Task 4: Key schedule derivation (§8/§8.5) + `key-schedule.json` KAT

**Files:** Create `mls/keyschedule/schedule.go`, `mls/keyschedule/schedule_test.go`, `mls/keyschedule/schedule_kat_test.go`.

- [ ] **Step 1: Write the failing tests.** Create `mls/keyschedule/schedule_test.go` (package `keyschedule`):

```go
package keyschedule

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/tree"
)

func TestDeriveEpochSecretsEpoch0(t *testing.T) {
	// key-schedule.json case 0, epoch 0 (suite 1), psk_secret given directly.
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	gc := GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:                 hx(t, "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"),
		Epoch:                   0,
		TreeHash:                hx(t, "9769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818"),
		ConfirmedTranscriptHash: hx(t, "5e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f"),
	}
	gcBytes, _ := gc.MarshalMLS()
	es, err := DeriveEpochSecrets(s,
		hx(t, "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"), // init_secret
		hx(t, "a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509"), // commit_secret
		hx(t, "e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b"), // psk_secret
		gcBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(es.JoinerSecret, hx(t, "4fb996ba26b29a70f3ce6c310151ce8701cb812d027f4d4bbf5cc4e9f884638d")) {
		t.Errorf("joiner=%x", es.JoinerSecret)
	}
	if !bytes.Equal(es.WelcomeSecret, hx(t, "ddcd9ced2d264798f876cbd00a200cdc4d77311dfef96975257efb66b0ef2c4d")) {
		t.Errorf("welcome=%x", es.WelcomeSecret)
	}
	if !bytes.Equal(es.SenderDataSecret, hx(t, "9b3995e08589548b75e149190060cf35228df0eefe3527ea2fb39e49a84125b4")) {
		t.Errorf("sender_data=%x", es.SenderDataSecret)
	}
	if !bytes.Equal(es.EpochAuthenticator, hx(t, "7375d449cde2c5a856c13c8eb52c16bf9ef29eceef59b09d1f946bd1bac24643")) {
		t.Errorf("epoch_authenticator=%x", es.EpochAuthenticator)
	}
	if !bytes.Equal(es.InitSecret, hx(t, "505be2ce2ff922aa11e0a03d76346dda2981f1d9edf5cf98ecfc8757f69b00c9")) {
		t.Errorf("init=%x", es.InitSecret)
	}
	_, pub, err := ExternalPub(s, es.ExternalSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, hx(t, "640117516be304ac1160933c894a6df9290231f1843f3685c124fc42c785c02c")) {
		t.Errorf("external_pub=%x", pub)
	}
}

func TestMLSExporter(t *testing.T) {
	// key-schedule.json case 0, epoch 0 exporter sub-case.
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	out, err := MLSExporter(s,
		hx(t, "5a097e149f2a375d0b9e1d1f4dc3a9c6c1788df888e5441f41a8791f4dc56cea"), // exporter_secret
		string(hx(t, "9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4")), // label
		hx(t, "884f1af892ab002f5be4c5d5081ade9e0e6418c6ea7a9a92e90534f19dcef785"), // context
		32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, hx(t, "dbce4e25e59ab4dfa6f6200f113ed08393cf6e7286d024811141c6a4dd11c0cb")) {
		t.Fatalf("exporter=%x", out)
	}
}
```

Create `mls/keyschedule/schedule_kat_test.go` (package `keyschedule_test`):

```go
package keyschedule_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/internal/katutil"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/tree"
)

type ksExporter struct {
	Label   katutil.HexBytes `json:"label"`
	Context katutil.HexBytes `json:"context"`
	Length  int              `json:"length"`
	Secret  katutil.HexBytes `json:"secret"`
}

type ksEpoch struct {
	TreeHash                katutil.HexBytes `json:"tree_hash"`
	CommitSecret            katutil.HexBytes `json:"commit_secret"`
	PSKSecret               katutil.HexBytes `json:"psk_secret"`
	ConfirmedTranscriptHash katutil.HexBytes `json:"confirmed_transcript_hash"`
	GroupContext            katutil.HexBytes `json:"group_context"`
	JoinerSecret            katutil.HexBytes `json:"joiner_secret"`
	WelcomeSecret           katutil.HexBytes `json:"welcome_secret"`
	InitSecret              katutil.HexBytes `json:"init_secret"`
	SenderDataSecret        katutil.HexBytes `json:"sender_data_secret"`
	EncryptionSecret        katutil.HexBytes `json:"encryption_secret"`
	ExporterSecret          katutil.HexBytes `json:"exporter_secret"`
	EpochAuthenticator      katutil.HexBytes `json:"epoch_authenticator"`
	ExternalSecret          katutil.HexBytes `json:"external_secret"`
	ConfirmationKey         katutil.HexBytes `json:"confirmation_key"`
	MembershipKey           katutil.HexBytes `json:"membership_key"`
	ResumptionPSK           katutil.HexBytes `json:"resumption_psk"`
	ExternalPub             katutil.HexBytes `json:"external_pub"`
	Exporter                ksExporter       `json:"exporter"`
}

type ksCase struct {
	CipherSuite       uint16           `json:"cipher_suite"`
	GroupID           katutil.HexBytes `json:"group_id"`
	InitialInitSecret katutil.HexBytes `json:"initial_init_secret"`
	Epochs            []ksEpoch        `json:"epochs"`
}

func eq(t *testing.T, name string, got []byte, want katutil.HexBytes) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s=%x want %x", name, got, []byte(want))
	}
}

func TestKeyScheduleKAT(t *testing.T) {
	var cases []ksCase
	katutil.Load(t, "key-schedule.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no key-schedule vectors loaded")
	}
	executed := 0
	for idx, c := range cases {
		t.Run(fmt.Sprintf("case=%d/suite=%d", idx, c.CipherSuite), func(t *testing.T) {
			s, ok := cipher.Lookup(cipher.CipherSuite(c.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", c.CipherSuite)
			}
			executed++
			initSecret := []byte(c.InitialInitSecret)
			for e, ep := range c.Epochs {
				gc := keyschedule.GroupContext{
					Version:                 tree.ProtocolVersionMLS10,
					CipherSuite:             cipher.CipherSuite(c.CipherSuite),
					GroupID:                 c.GroupID,
					Epoch:                   uint64(e),
					TreeHash:                ep.TreeHash,
					ConfirmedTranscriptHash: ep.ConfirmedTranscriptHash,
				}
				gcBytes, err := gc.MarshalMLS()
				if err != nil {
					t.Fatal(err)
				}
				eq(t, fmt.Sprintf("ep%d.group_context", e), gcBytes, ep.GroupContext)

				es, err := keyschedule.DeriveEpochSecrets(s, initSecret, ep.CommitSecret, ep.PSKSecret, gcBytes)
				if err != nil {
					t.Fatal(err)
				}
				eq(t, "joiner_secret", es.JoinerSecret, ep.JoinerSecret)
				eq(t, "welcome_secret", es.WelcomeSecret, ep.WelcomeSecret)
				eq(t, "sender_data_secret", es.SenderDataSecret, ep.SenderDataSecret)
				eq(t, "encryption_secret", es.EncryptionSecret, ep.EncryptionSecret)
				eq(t, "exporter_secret", es.ExporterSecret, ep.ExporterSecret)
				eq(t, "external_secret", es.ExternalSecret, ep.ExternalSecret)
				eq(t, "confirmation_key", es.ConfirmationKey, ep.ConfirmationKey)
				eq(t, "membership_key", es.MembershipKey, ep.MembershipKey)
				eq(t, "resumption_psk", es.ResumptionPSK, ep.ResumptionPSK)
				eq(t, "epoch_authenticator", es.EpochAuthenticator, ep.EpochAuthenticator)
				eq(t, "init_secret", es.InitSecret, ep.InitSecret)

				_, pub, err := keyschedule.ExternalPub(s, es.ExternalSecret)
				if err != nil {
					t.Fatal(err)
				}
				eq(t, "external_pub", pub, ep.ExternalPub)

				out, err := keyschedule.MLSExporter(s, es.ExporterSecret,
					string(ep.Exporter.Label), ep.Exporter.Context, ep.Exporter.Length)
				if err != nil {
					t.Fatal(err)
				}
				eq(t, "exporter", out, ep.Exporter.Secret)

				initSecret = es.InitSecret // carry forward to the next epoch
			}
		})
	}
	if executed == 0 {
		t.Fatal("no vectors executed (all skipped) — check cipher suite registration")
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/keyschedule/` → FAIL (`undefined: DeriveEpochSecrets`).

- [ ] **Step 3: Implement `mls/keyschedule/schedule.go`:**

```go
package keyschedule

import "github.com/trevex/mls-go/mls/cipher"

// EpochSecrets holds the secrets derived from one epoch of the key schedule
// (RFC 9420 §8). InitSecret is init_secret_[n], the input to the *next* epoch.
type EpochSecrets struct {
	JoinerSecret       []byte
	WelcomeSecret      []byte
	EpochSecret        []byte
	SenderDataSecret   []byte
	EncryptionSecret   []byte
	ExporterSecret     []byte
	ExternalSecret     []byte
	ConfirmationKey    []byte
	MembershipKey      []byte
	ResumptionPSK      []byte
	EpochAuthenticator []byte
	InitSecret         []byte
}

// JoinerSecret derives joiner_secret (RFC 9420 §8):
//
//	joiner_secret = ExpandWithLabel(
//	    KDF.Extract(init_secret_[n-1], commit_secret), "joiner", GroupContext, KDF.Nh)
//
// A nil commitSecret is treated as the all-zero KDF.Nh vector.
func JoinerSecret(suite cipher.Suite, initSecret, commitSecret, groupContext []byte) ([]byte, error) {
	if commitSecret == nil {
		commitSecret = make([]byte, suite.HashLen())
	}
	extracted, err := suite.Extract(initSecret, commitSecret) // Extract(salt=init_secret, IKM=commit_secret)
	if err != nil {
		return nil, err
	}
	return suite.ExpandWithLabel(extracted, "joiner", groupContext, suite.HashLen())
}

// DeriveEpochSecrets runs the full RFC 9420 §8 key schedule for one epoch. A nil
// pskSecret is treated as the all-zero KDF.Nh vector (psk_secret_[0]).
func DeriveEpochSecrets(suite cipher.Suite, initSecret, commitSecret, pskSecret, groupContext []byte) (EpochSecrets, error) {
	nh := suite.HashLen()
	if pskSecret == nil {
		pskSecret = make([]byte, nh)
	}
	joiner, err := JoinerSecret(suite, initSecret, commitSecret, groupContext)
	if err != nil {
		return EpochSecrets{}, err
	}
	member, err := suite.Extract(joiner, pskSecret) // Extract(salt=joiner_secret, IKM=psk_secret)
	if err != nil {
		return EpochSecrets{}, err
	}
	welcome, err := suite.DeriveSecret(member, "welcome")
	if err != nil {
		return EpochSecrets{}, err
	}
	epoch, err := suite.ExpandWithLabel(member, "epoch", groupContext, nh)
	if err != nil {
		return EpochSecrets{}, err
	}
	es := EpochSecrets{JoinerSecret: joiner, WelcomeSecret: welcome, EpochSecret: epoch}
	for _, d := range []struct {
		label string
		out   *[]byte
	}{
		{"sender data", &es.SenderDataSecret},
		{"encryption", &es.EncryptionSecret},
		{"exporter", &es.ExporterSecret},
		{"external", &es.ExternalSecret},
		{"confirm", &es.ConfirmationKey},
		{"membership", &es.MembershipKey},
		{"resumption", &es.ResumptionPSK},
		{"authentication", &es.EpochAuthenticator},
		{"init", &es.InitSecret},
	} {
		v, err := suite.DeriveSecret(epoch, d.label)
		if err != nil {
			return EpochSecrets{}, err
		}
		*d.out = v
	}
	return es, nil
}

// ExternalPub derives the group's external HPKE key pair from external_secret
// (RFC 9420 §8): external_priv, external_pub = KEM.DeriveKeyPair(external_secret).
func ExternalPub(suite cipher.Suite, externalSecret []byte) (priv, pub []byte, err error) {
	return suite.DeriveKeyPair(externalSecret)
}

// MLSExporter implements MLS-Exporter (RFC 9420 §8.5):
//
//	MLS-Exporter(Label, Context, Length) =
//	    ExpandWithLabel(DeriveSecret(exporter_secret, Label), "exported", Hash(Context), Length)
func MLSExporter(suite cipher.Suite, exporterSecret []byte, label string, context []byte, length int) ([]byte, error) {
	derived, err := suite.DeriveSecret(exporterSecret, label)
	if err != nil {
		return nil, err
	}
	return suite.ExpandWithLabel(derived, "exported", suite.Hash(context), length)
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/keyschedule/` → PASS (KAT covers all epochs of suites 1 & 2, chaining init_secret across epochs).
- [ ] **Step 5: Vet + format.** `nix develop -c go vet ./mls/keyschedule/`, `nix develop -c gofmt -l mls/keyschedule/`.
- [ ] **Step 6: Commit.** `feat(keyschedule): epoch key schedule + exporter + key-schedule KAT (RFC 9420 §8)` + trailer.

---

## Task 5: Secret tree + ratchets + sender data (§9/§9.1) + `secret-tree.json` KAT

**Files:** Create `mls/keyschedule/secrettree.go`, `mls/keyschedule/secrettree_test.go`, `mls/keyschedule/secrettree_kat_test.go`.

- [ ] **Step 1: Write the failing tests.** Create `mls/keyschedule/secrettree_test.go` (package `keyschedule`):

```go
package keyschedule

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
)

func TestSenderDataKeyNonce(t *testing.T) {
	// secret-tree.json case 0 sender_data.
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	key, nonce, err := SenderDataKeyNonce(s,
		hx(t, "95684b805e1bbd9c71d1abaf8a1930c12112b9a06c12db937970be5bbb916573"),
		hx(t, "156f2eb3fa482cff20e3a090c267ce6481d4a0976aee2adb921d70ae8a04a6494339462ac049f185e7184d8245270e54e68b72bd5df66800367c50e423cafec0260ac4dc743c24cabfc6060fc5"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, hx(t, "92667d9c889a6b768c157538c0a79fed")) {
		t.Errorf("key=%x", key)
	}
	if !bytes.Equal(nonce, hx(t, "362785b1cc8bc775fcc216e7")) {
		t.Errorf("nonce=%x", nonce)
	}
}

func TestSecretTreeSingleLeafGeneration(t *testing.T) {
	// secret-tree.json case 0: 1 leaf, generations 0 and 15.
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	st, err := NewSecretTree(s, 1, hx(t, "d69fcc35969e94680461974bd26c7cda7594cbf45985c4bf668c3b3118b765ab"))
	if err != nil {
		t.Fatal(err)
	}
	hk0, hn0, err := st.KeyNonce(0, HandshakeRatchet, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hk0, hx(t, "a2d6b8a9255478e9b79a076872ae3563")) || !bytes.Equal(hn0, hx(t, "8e8fc08a4eb5189b7b558527")) {
		t.Errorf("gen0 handshake key/nonce mismatch: %x %x", hk0, hn0)
	}
	ak0, _, err := st.KeyNonce(0, ApplicationRatchet, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ak0, hx(t, "442e691710646617a21e41482d868a4e")) {
		t.Errorf("gen0 application key mismatch: %x", ak0)
	}
}
```

Create `mls/keyschedule/secrettree_kat_test.go` (package `keyschedule_test`):

```go
package keyschedule_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/internal/katutil"
	"github.com/trevex/mls-go/mls/keyschedule"
)

type stSenderData struct {
	SenderDataSecret katutil.HexBytes `json:"sender_data_secret"`
	Ciphertext       katutil.HexBytes `json:"ciphertext"`
	Key              katutil.HexBytes `json:"key"`
	Nonce            katutil.HexBytes `json:"nonce"`
}

type stRatchet struct {
	Generation       uint32           `json:"generation"`
	HandshakeKey     katutil.HexBytes `json:"handshake_key"`
	HandshakeNonce   katutil.HexBytes `json:"handshake_nonce"`
	ApplicationKey   katutil.HexBytes `json:"application_key"`
	ApplicationNonce katutil.HexBytes `json:"application_nonce"`
}

type stCase struct {
	CipherSuite      uint16           `json:"cipher_suite"`
	SenderData       stSenderData     `json:"sender_data"`
	EncryptionSecret katutil.HexBytes `json:"encryption_secret"`
	Leaves           [][]stRatchet    `json:"leaves"`
}

func TestSecretTreeKAT(t *testing.T) {
	var cases []stCase
	katutil.Load(t, "secret-tree.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no secret-tree vectors loaded")
	}
	executed := 0
	for idx, c := range cases {
		t.Run(fmt.Sprintf("case=%d/suite=%d", idx, c.CipherSuite), func(t *testing.T) {
			s, ok := cipher.Lookup(cipher.CipherSuite(c.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", c.CipherSuite)
			}
			executed++
			key, nonce, err := keyschedule.SenderDataKeyNonce(s, c.SenderData.SenderDataSecret, c.SenderData.Ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(key, c.SenderData.Key) || !bytes.Equal(nonce, c.SenderData.Nonce) {
				t.Fatalf("sender_data key/nonce mismatch: %x %x", key, nonce)
			}

			st, err := keyschedule.NewSecretTree(s, uint32(len(c.Leaves)), c.EncryptionSecret)
			if err != nil {
				t.Fatal(err)
			}
			for i, ratchets := range c.Leaves {
				for _, r := range ratchets {
					hk, hn, err := st.KeyNonce(uint32(i), keyschedule.HandshakeRatchet, r.Generation)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(hk, r.HandshakeKey) || !bytes.Equal(hn, r.HandshakeNonce) {
						t.Fatalf("leaf %d gen %d handshake mismatch", i, r.Generation)
					}
					ak, an, err := st.KeyNonce(uint32(i), keyschedule.ApplicationRatchet, r.Generation)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(ak, r.ApplicationKey) || !bytes.Equal(an, r.ApplicationNonce) {
						t.Fatalf("leaf %d gen %d application mismatch", i, r.Generation)
					}
				}
			}
		})
	}
	if executed == 0 {
		t.Fatal("no vectors executed (all skipped) — check cipher suite registration")
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/keyschedule/` → FAIL (`undefined: SenderDataKeyNonce`).

- [ ] **Step 3: Implement `mls/keyschedule/secrettree.go`:**

```go
package keyschedule

import (
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/tree"
)

// SenderDataKeyNonce derives the sender-data AEAD key and nonce (RFC 9420 §9.1):
//
//	ciphertext_sample = ciphertext[0 .. KDF.Nh-1]   (whole ciphertext if shorter)
//	sender_data_key   = ExpandWithLabel(sender_data_secret, "key",   sample, AEAD.Nk)
//	sender_data_nonce = ExpandWithLabel(sender_data_secret, "nonce", sample, AEAD.Nn)
func SenderDataKeyNonce(suite cipher.Suite, senderDataSecret, ciphertext []byte) (key, nonce []byte, err error) {
	sample := ciphertext
	if nh := suite.HashLen(); len(sample) > nh {
		sample = sample[:nh]
	}
	key, err = suite.ExpandWithLabel(senderDataSecret, "key", sample, suite.AEADKeySize())
	if err != nil {
		return nil, nil, err
	}
	nonce, err = suite.ExpandWithLabel(senderDataSecret, "nonce", sample, suite.AEADNonceSize())
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}

// RatchetType selects a leaf's handshake or application ratchet (RFC 9420 §9.1).
type RatchetType int

const (
	HandshakeRatchet RatchetType = iota
	ApplicationRatchet
)

// SecretTree holds the per-leaf ratchet base secrets derived from
// encryption_secret (RFC 9420 §9).
type SecretTree struct {
	suite           cipher.Suite
	nLeaves         uint32
	handshakeBase   map[uint32][]byte // leaf index -> handshake_ratchet_secret_[N]_[0]
	applicationBase map[uint32][]byte // leaf index -> application_ratchet_secret_[N]_[0]
}

// NewSecretTree builds the secret tree for nLeaves leaves with encryption_secret
// at the root, deriving each leaf's handshake/application ratchet roots (§9).
func NewSecretTree(suite cipher.Suite, nLeaves uint32, encryptionSecret []byte) (*SecretTree, error) {
	if nLeaves == 0 {
		return nil, fmt.Errorf("keyschedule: secret tree requires at least one leaf")
	}
	st := &SecretTree{
		suite:           suite,
		nLeaves:         nLeaves,
		handshakeBase:   make(map[uint32][]byte, nLeaves),
		applicationBase: make(map[uint32][]byte, nLeaves),
	}
	if err := st.deriveNode(tree.Root(nLeaves), encryptionSecret); err != nil {
		return nil, err
	}
	return st, nil
}

func (st *SecretTree) deriveNode(node uint32, secret []byte) error {
	nh := st.suite.HashLen()
	left, ok := tree.Left(node)
	if !ok {
		// Leaf node: node index == 2 * leaf index (RFC 9420 §9 / tree math).
		leaf := node / 2
		hs, err := st.suite.ExpandWithLabel(secret, "handshake", nil, nh)
		if err != nil {
			return err
		}
		app, err := st.suite.ExpandWithLabel(secret, "application", nil, nh)
		if err != nil {
			return err
		}
		st.handshakeBase[leaf] = hs
		st.applicationBase[leaf] = app
		return nil
	}
	right, _ := tree.Right(node, st.nLeaves)
	ls, err := st.suite.ExpandWithLabel(secret, "tree", []byte("left"), nh)
	if err != nil {
		return err
	}
	rs, err := st.suite.ExpandWithLabel(secret, "tree", []byte("right"), nh)
	if err != nil {
		return err
	}
	if err := st.deriveNode(left, ls); err != nil {
		return err
	}
	return st.deriveNode(right, rs)
}

// KeyNonce returns the AEAD key and nonce for a leaf's ratchet at the given
// generation (RFC 9420 §9.1). The running secret is advanced from generation 0.
func (st *SecretTree) KeyNonce(leaf uint32, rt RatchetType, generation uint32) (key, nonce []byte, err error) {
	var base []byte
	switch rt {
	case HandshakeRatchet:
		base = st.handshakeBase[leaf]
	case ApplicationRatchet:
		base = st.applicationBase[leaf]
	default:
		return nil, nil, fmt.Errorf("keyschedule: invalid ratchet type %d", rt)
	}
	if base == nil {
		return nil, nil, fmt.Errorf("keyschedule: no ratchet for leaf %d (nLeaves=%d)", leaf, st.nLeaves)
	}
	nh := st.suite.HashLen()
	secret := append([]byte(nil), base...)
	for j := uint32(0); j < generation; j++ {
		secret, err = st.suite.DeriveTreeSecret(secret, "secret", j, nh)
		if err != nil {
			return nil, nil, err
		}
	}
	key, err = st.suite.DeriveTreeSecret(secret, "key", generation, st.suite.AEADKeySize())
	if err != nil {
		return nil, nil, err
	}
	nonce, err = st.suite.DeriveTreeSecret(secret, "nonce", generation, st.suite.AEADNonceSize())
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/keyschedule/` → PASS (KAT covers 1/8/32-leaf trees, sparse generations, suites 1 & 2).
- [ ] **Step 5: Vet + format.** `nix develop -c go vet ./mls/keyschedule/`, `nix develop -c gofmt -l mls/keyschedule/`.
- [ ] **Step 6: Commit.** `feat(keyschedule): secret tree, ratchets, sender data + secret-tree KAT (RFC 9420 §9)` + trailer.

---

## Task 6: Transcript hashes (§8.2/§6.1) + `transcript-hashes.json` KAT

**Files:** Create `mls/keyschedule/transcript.go`, `mls/keyschedule/transcript_kat_test.go`.

- [ ] **Step 1: Write the failing test.** Create `mls/keyschedule/transcript_kat_test.go` (package `keyschedule_test`):

```go
package keyschedule_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/internal/katutil"
	"github.com/trevex/mls-go/mls/keyschedule"
)

type thCase struct {
	CipherSuite                  uint16           `json:"cipher_suite"`
	ConfirmationKey              katutil.HexBytes `json:"confirmation_key"`
	AuthenticatedContent         katutil.HexBytes `json:"authenticated_content"`
	InterimTranscriptHashBefore  katutil.HexBytes `json:"interim_transcript_hash_before"`
	ConfirmedTranscriptHashAfter katutil.HexBytes `json:"confirmed_transcript_hash_after"`
	InterimTranscriptHashAfter   katutil.HexBytes `json:"interim_transcript_hash_after"`
}

func TestTranscriptHashesKAT(t *testing.T) {
	var cases []thCase
	katutil.Load(t, "transcript-hashes.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no transcript-hashes vectors loaded")
	}
	executed := 0
	for idx, c := range cases {
		t.Run(fmt.Sprintf("case=%d/suite=%d", idx, c.CipherSuite), func(t *testing.T) {
			s, ok := cipher.Lookup(cipher.CipherSuite(c.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", c.CipherSuite)
			}
			executed++
			confirmedInput, confTag, err := keyschedule.SplitAuthenticatedContent(s, c.AuthenticatedContent)
			if err != nil {
				t.Fatal(err)
			}
			confirmed := keyschedule.ConfirmedTranscriptHash(s, c.InterimTranscriptHashBefore, confirmedInput)
			if !bytes.Equal(confirmed, c.ConfirmedTranscriptHashAfter) {
				t.Fatalf("confirmed_transcript_hash_after=%x want %x", confirmed, []byte(c.ConfirmedTranscriptHashAfter))
			}
			// The peeled tag must equal MAC(confirmation_key, confirmed_after).
			if want := keyschedule.ConfirmationTag(s, c.ConfirmationKey, confirmed); !bytes.Equal(confTag, want) {
				t.Fatalf("confirmation_tag mismatch: peeled %x vs computed %x", confTag, want)
			}
			interim, err := keyschedule.InterimTranscriptHash(s, confirmed, confTag)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(interim, c.InterimTranscriptHashAfter) {
				t.Fatalf("interim_transcript_hash_after=%x want %x", interim, []byte(c.InterimTranscriptHashAfter))
			}
		})
	}
	if executed == 0 {
		t.Fatal("no vectors executed (all skipped) — check cipher suite registration")
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/keyschedule/` → FAIL (`undefined: SplitAuthenticatedContent`).

- [ ] **Step 3: Implement `mls/keyschedule/transcript.go`:**

```go
package keyschedule

import (
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/syntax"
)

// ConfirmationTag computes a Commit's confirmation MAC (RFC 9420 §6.1):
//
//	confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)
func ConfirmationTag(suite cipher.Suite, confirmationKey, confirmedTranscriptHash []byte) []byte {
	return suite.MAC(confirmationKey, confirmedTranscriptHash)
}

// ConfirmedTranscriptHash updates the confirmed transcript hash (RFC 9420 §8.2):
//
//	confirmed_[n] = Hash(interim_[n-1] || ConfirmedTranscriptHashInput_[n])
func ConfirmedTranscriptHash(suite cipher.Suite, interimPrev, confirmedInput []byte) []byte {
	h := suite.NewHash()
	h.Write(interimPrev)
	h.Write(confirmedInput)
	return h.Sum(nil)
}

// InterimTranscriptHash updates the interim transcript hash (RFC 9420 §8.2):
//
//	interim_[n] = Hash(confirmed_[n] || InterimTranscriptHashInput_[n])
//	InterimTranscriptHashInput = struct { MAC confirmation_tag; }   // opaque<V>
func InterimTranscriptHash(suite cipher.Suite, confirmed, confirmationTag []byte) ([]byte, error) {
	in, err := syntax.WriteOpaqueV(confirmationTag)
	if err != nil {
		return nil, err
	}
	h := suite.NewHash()
	h.Write(confirmed)
	h.Write(in)
	return h.Sum(nil), nil
}

// SplitAuthenticatedContent splits a serialized Commit AuthenticatedContent into
// its ConfirmedTranscriptHashInput bytes and its confirmation_tag value
// (RFC 9420 §6/§8.2).
//
// AuthenticatedContent = wire_format || FramedContent content || FramedContentAuthData auth,
// and for a Commit auth = opaque signature<V> || MAC confirmation_tag<V>, so
// ConfirmedTranscriptHashInput (= wire_format || content || signature) is exactly
// the AuthenticatedContent with the trailing confirmation_tag<V> field removed.
// confirmation_tag is a MAC of fixed length KDF.Nh, so its serialized field
// length is deterministic and the field is peeled from the end without parsing
// the FramedContent/Commit body (full framing is implemented in a later plan).
func SplitAuthenticatedContent(suite cipher.Suite, ac []byte) (confirmedInput, confirmationTag []byte, err error) {
	macLen := suite.HashLen()
	field, err := syntax.WriteOpaqueV(make([]byte, macLen))
	if err != nil {
		return nil, nil, err
	}
	if len(ac) < len(field) {
		return nil, nil, fmt.Errorf("keyschedule: authenticated_content too short (%d < %d)", len(ac), len(field))
	}
	confirmedInput = ac[:len(ac)-len(field)]
	confirmationTag = ac[len(ac)-macLen:]
	return confirmedInput, confirmationTag, nil
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/keyschedule/` → PASS.
- [ ] **Step 5: Vet + format.** `nix develop -c go vet ./mls/keyschedule/`, `nix develop -c gofmt -l mls/keyschedule/`.
- [ ] **Step 6: Commit.** `feat(keyschedule): transcript hashes + confirmation tag + transcript-hashes KAT (RFC 9420 §8.2)` + trailer.

---

## Definition of Done

- [ ] All four KATs pass: `nix develop -c go test ./mls/keyschedule/` is green and each KAT test logs `executed > 0` (no all-skipped guard fired).
- [ ] `nix develop -c go test ./mls/...` passes for the whole module (no regressions in `cipher`/`tree`).
- [ ] `nix develop -c go vet ./mls/...` clean; `nix develop -c gofmt -l mls/` prints nothing.
- [ ] `mls/testdata/` contains the four vendored JSON files (`psk_secret.json`, `key-schedule.json`, `secret-tree.json`, `transcript-hashes.json`).
- [ ] Public API of `mls/keyschedule`: `GroupContext`(+`MarshalMLS`/`UnmarshalMLS`); `PSKType`/`ResumptionPSKUsage`/`PreSharedKeyID`/`PSK`/`PSKSecret`; `EpochSecrets`/`JoinerSecret`/`DeriveEpochSecrets`/`ExternalPub`/`MLSExporter`; `SenderDataKeyNonce`/`SecretTree`/`NewSecretTree`/`RatchetType`/`HandshakeRatchet`/`ApplicationRatchet`/`KeyNonce`; `ConfirmationTag`/`ConfirmedTranscriptHash`/`InterimTranscriptHash`/`SplitAuthenticatedContent`.
- [ ] New `cipher` methods (`Extract`, `AEADKeySize`, `AEADNonceSize`, `DeriveKeyPair`) and `tree` exports (`Extension.MarshalTo`, `DecodeExtension`) are covered by tests.
- [ ] Stdlib-only constraint preserved (no new external imports).
- [ ] One commit per task, each ending with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.

---

## Notes for the next plan (Plan 6 — TreeKEM / UpdatePath → `treekem.json`)

- **GroupContext is now available** in `mls/keyschedule` and is the context input for `EncryptWithLabel`/path-secret derivation and for `FramedContentTBS` signatures (Plan 7).
- **DeriveSecret/path secrets**: TreeKEM path secrets use `DeriveSecret(path_secret, "node")` and `ExpandWithLabel(path_secret, "path", "", KDF.Nh)` style derivations and `EncryptWithLabel(..., "UpdatePathNode", ...)` — the labeled HPKE is already in `cipher`; `commit_secret` produced by TreeKEM feeds `DeriveEpochSecrets` here.
- **`Suite.DeriveKeyPair`** (added in this plan) is also what TreeKEM uses to derive a node key pair from a path secret's node secret — reuse it.
- **Full framing** (`FramedContent`, `Sender`, `FramedContentAuthData`, `AuthenticatedContent`, `Commit`, `Proposal`, `ProposalOrRef`) is deferred to Plan 7; this plan deliberately avoided parsing the Commit body in the transcript code (see `SplitAuthenticatedContent`). When Plan 7 lands real framing, consider re-expressing `SplitAuthenticatedContent` in terms of a parsed `AuthenticatedContent` for robustness, but the byte-slice approach remains correct because `confirmation_tag` is always the final field of a Commit's auth data.
- **Secret tree consumers** (PrivateMessage encrypt/decrypt, Plan 7/8) will call `KeyNonce` per sender/generation; the current O(generation) advance is fine for KAT but a stateful per-leaf ratchet cursor may be worth adding when wiring message protection.
