# Ciphersuites & HPKE (Plan 2 of 6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HPKE-backed labeled public-key encryption (`EncryptWithLabel`/`DecryptWithLabel`, RFC 9420 §5.1.3) to the cipher suites, complete the `crypto-basics` KAT's `encrypt_with_label` field for the classical suites, and register the post-quantum **X-Wing** hybrid suite — all on the Go 1.26 standard library (`crypto/hpke`), no third-party dependencies.

**Architecture:** Extend the existing `mls/cipher.Suite` with its HPKE `KEM`/`KDF`/`AEAD` selection (from stdlib `crypto/hpke`). Add `EncryptWithLabel`/`DecryptWithLabel`/`GenerateHPKEKeyPair` methods that map MLS labeled encryption onto HPKE base-mode `SealBase`/`OpenBase`. Register a private-use X-Wing hybrid ciphersuite (`0xF001`) using `hpke.MLKEM768X25519()`. The labeled `EncryptContext` reuses the same `opaque<V>("MLS 1.0 "+label) || opaque<V>(context)` construction already used for signatures.

**Tech Stack:** Go 1.26 standard library only — `crypto/hpke` (new in 1.26: `DHKEM`, `MLKEM768X25519`, `HKDFSHA256`, `AES128GCM`, `AES256GCM`, `NewSender`/`NewRecipient`), `crypto/ecdh`, building on Plan 1's `mls/syntax` and `mls/cipher`.

**Spec reference:** `docs/superpowers/specs/2026-06-26-mls-mlkem-go-design.md` §7 (PQC posture: X-Wing via stdlib; EncryptWithLabel mapping), §6 (conformance: hybrid suite has no official KAT → self round-trip).

---

## Key facts (verified against Go 1.26 source — use exactly these identifiers)

- HPKE KEM constructors: `hpke.DHKEM(ecdh.X25519())` (id 0x0020), `hpke.DHKEM(ecdh.P256())` (id 0x0010), `hpke.MLKEM768X25519()` (id 0x647a = **X-Wing**, X25519+ML-KEM-768).
- KDF: `hpke.HKDFSHA256()`. AEAD: `hpke.AES128GCM()`, `hpke.AES256GCM()`.
- `kem.GenerateKey() (hpke.PrivateKey, error)`; `sk.PublicKey() hpke.PublicKey`; `pk.Bytes() []byte`; `sk.Bytes() ([]byte, error)`; `kem.NewPublicKey([]byte) (hpke.PublicKey, error)`; `kem.NewPrivateKey([]byte) (hpke.PrivateKey, error)`.
- Sender: `enc, s, err := hpke.NewSender(pk, kdf, aead, info)` then `ct, err := s.Seal(aad, plaintext)` — **aad first** (use `nil`).
- Recipient: `r, err := hpke.NewRecipient(enc, sk, kdf, aead, info)` then `pt, err := r.Open(aad, ciphertext)` — **aad first** (use `nil`).
- `EncryptWithLabel(pk, Label, Context, Plaintext)` = `SealBase(pk, info=EncryptContext, aad="", Plaintext)` → returns `(enc=kem_output, ciphertext)`. `EncryptContext = opaque<V>("MLS 1.0 "+Label) || opaque<V>(Context)`.
- `encrypt_with_label` KAT verified by **decrypting** `(kem_output, ciphertext)` with `priv` and comparing to `plaintext` (HPKE is randomized; never re-encrypt).
- MLS private-use ciphersuite id range is `0xF000–0xFFFF` (RFC 9420 §17.1). Use `0xF001` for the X-Wing suite.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `mls/cipher/suite.go` | Modify | Add unexported `kem/kdf/aead` HPKE fields to `Suite`; wire them into the registry for 0x0001 & 0x0002; add `GenerateHPKEKeyPair`. |
| `mls/cipher/labeled.go` | Modify | Factor shared `labeledContext` helper; add `EncryptWithLabel`/`DecryptWithLabel`. |
| `mls/cipher/hpke_test.go` | Create | Round-trip unit tests for labeled encryption. |
| `mls/cipher/kat_test.go` | Modify | Add `encrypt_with_label` decrypt check to the crypto-basics KAT. |
| `mls/cipher/suite_pq.go` | Create | Register the X-Wing private-use hybrid suite `0xF001`. |
| `mls/cipher/suite_pq_test.go` | Create | X-Wing round-trip + size assertions (no official KAT). |

---

## Task 1: HPKE config on Suite + labeled encryption

**Files:**
- Modify: `mls/cipher/suite.go`
- Modify: `mls/cipher/labeled.go`
- Test: `mls/cipher/hpke_test.go`

- [ ] **Step 1: Write the failing round-trip test**

Create `mls/cipher/hpke_test.go`:

```go
package cipher_test

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

func TestEncryptDecryptWithLabelRoundTrip(t *testing.T) {
	for _, id := range []cipher.CipherSuite{
		cipher.X25519_AES128GCM_SHA256_Ed25519,
		cipher.P256_AES128GCM_SHA256_P256,
	} {
		cs, ok := cipher.Lookup(id)
		if !ok {
			t.Fatalf("suite %#x not registered", id)
		}
		priv, pub, err := cs.GenerateHPKEKeyPair()
		if err != nil {
			t.Fatalf("suite %#x GenerateHPKEKeyPair: %v", id, err)
		}
		label := "test label"
		context := []byte("some context")
		plaintext := []byte("attack at dawn")

		kemOut, ct, err := cs.EncryptWithLabel(pub, label, context, plaintext)
		if err != nil {
			t.Fatalf("suite %#x EncryptWithLabel: %v", id, err)
		}
		got, err := cs.DecryptWithLabel(priv, label, context, kemOut, ct)
		if err != nil {
			t.Fatalf("suite %#x DecryptWithLabel: %v", id, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("suite %#x round-trip: got %q, want %q", id, got, plaintext)
		}

		// Wrong context must fail to decrypt (info is authenticated).
		if _, err := cs.DecryptWithLabel(priv, label, []byte("other"), kemOut, ct); err == nil {
			t.Fatalf("suite %#x: decrypt with wrong context should fail", id)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop -c go test ./mls/cipher/`
Expected: FAIL — `cs.GenerateHPKEKeyPair undefined` (build error).

- [ ] **Step 3: Add HPKE fields + key generation to `suite.go`**

Edit `mls/cipher/suite.go`. Add imports `crypto/ecdh` and `crypto/hpke`. Extend the `Suite` struct and registry, and add `GenerateHPKEKeyPair`.

Change the struct to:

```go
// Suite bundles the primitive constructors for one ciphersuite: the hash, the
// signature scheme, and the HPKE KEM/KDF/AEAD used by labeled public-key
// encryption (RFC 9420 §5.1.3).
type Suite struct {
	ID      CipherSuite
	NewHash func() hash.Hash
	Sig     SignatureScheme

	kem  hpke.KEM
	kdf  hpke.KDF
	aead hpke.AEAD
}
```

Change the registry entries to include the HPKE selection:

```go
var registry = map[CipherSuite]Suite{
	X25519_AES128GCM_SHA256_Ed25519: {
		ID:      X25519_AES128GCM_SHA256_Ed25519,
		NewHash: sha256.New,
		Sig:     SigEd25519,
		kem:     hpke.DHKEM(ecdh.X25519()),
		kdf:     hpke.HKDFSHA256(),
		aead:    hpke.AES128GCM(),
	},
	P256_AES128GCM_SHA256_P256: {
		ID:      P256_AES128GCM_SHA256_P256,
		NewHash: sha256.New,
		Sig:     SigECDSAP256,
		kem:     hpke.DHKEM(ecdh.P256()),
		kdf:     hpke.HKDFSHA256(),
		aead:    hpke.AES128GCM(),
	},
}
```

Add at the end of `suite.go`:

```go
// GenerateHPKEKeyPair generates a fresh HPKE key pair for the suite's KEM,
// returning the serialized private and public keys (the MLS HPKEPrivateKey /
// HPKEPublicKey encodings).
func (s Suite) GenerateHPKEKeyPair() (priv, pub []byte, err error) {
	sk, err := s.kem.GenerateKey()
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

- [ ] **Step 4: Factor the labeled-context helper and add labeled encryption in `labeled.go`**

Edit `mls/cipher/labeled.go`. Add import `crypto/hpke`. Replace the `signContent` method with a shared `labeledContext` helper, and update `SignWithLabel`/`VerifyWithLabel` to call it.

Replace:

```go
// signContent builds SignContent = struct{ opaque label<V>; opaque content<V> }
// with label = "MLS 1.0 " + Label (RFC 9420 §5.1.2).
func (s Suite) signContent(label string, content []byte) ([]byte, error) {
	lbl, err := syntax.WriteOpaqueV([]byte(mlsLabelPrefix + label))
	if err != nil {
		return nil, err
	}
	body, err := syntax.WriteOpaqueV(content)
	if err != nil {
		return nil, err
	}
	return append(lbl, body...), nil
}
```

with:

```go
// labeledContext builds the struct{ opaque label<V>; opaque data<V> } used by
// both SignContent (RFC 9420 §5.1.2) and EncryptContext (§5.1.3), with
// label = "MLS 1.0 " + Label.
func (s Suite) labeledContext(label string, data []byte) ([]byte, error) {
	lbl, err := syntax.WriteOpaqueV([]byte(mlsLabelPrefix + label))
	if err != nil {
		return nil, err
	}
	body, err := syntax.WriteOpaqueV(data)
	if err != nil {
		return nil, err
	}
	return append(lbl, body...), nil
}
```

Update the two callers: in `SignWithLabel` and `VerifyWithLabel`, change `s.signContent(label, content)` to `s.labeledContext(label, content)`.

Then append the labeled-encryption methods to `labeled.go`:

```go
// EncryptWithLabel implements RFC 9420 §5.1.3:
//
//	EncryptWithLabel(PublicKey, Label, Context, Plaintext)
//	    = SealBase(PublicKey, EncryptContext, "", Plaintext)
//
// where EncryptContext = struct{ opaque label<V> = "MLS 1.0 "+Label;
// opaque context<V> = Context }. It returns the KEM output (HPKE enc) and the
// AEAD ciphertext. pub is the serialized HPKEPublicKey.
func (s Suite) EncryptWithLabel(pub []byte, label string, context, plaintext []byte) (kemOutput, ciphertext []byte, err error) {
	pk, err := s.kem.NewPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	info, err := s.labeledContext(label, context)
	if err != nil {
		return nil, nil, err
	}
	enc, sender, err := hpke.NewSender(pk, s.kdf, s.aead, info)
	if err != nil {
		return nil, nil, err
	}
	ct, err := sender.Seal(nil, plaintext) // empty aad
	if err != nil {
		return nil, nil, err
	}
	return enc, ct, nil
}

// DecryptWithLabel implements RFC 9420 §5.1.3 OpenBase. priv is the serialized
// HPKEPrivateKey; kemOutput is the HPKE enc from EncryptWithLabel.
func (s Suite) DecryptWithLabel(priv []byte, label string, context, kemOutput, ciphertext []byte) ([]byte, error) {
	sk, err := s.kem.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	info, err := s.labeledContext(label, context)
	if err != nil {
		return nil, err
	}
	recipient, err := hpke.NewRecipient(kemOutput, sk, s.kdf, s.aead, info)
	if err != nil {
		return nil, err
	}
	return recipient.Open(nil, ciphertext) // empty aad
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `nix develop -c go test ./mls/cipher/ -run TestEncryptDecryptWithLabelRoundTrip -v`
Expected: PASS for both suites. Then `nix develop -c go vet ./mls/...` and `nix develop -c gofmt -l mls/` — clean.

- [ ] **Step 6: Commit**

```bash
git add mls/cipher/suite.go mls/cipher/labeled.go mls/cipher/hpke_test.go
git commit -m "feat(cipher): HPKE EncryptWithLabel/DecryptWithLabel via stdlib crypto/hpke"
```

---

## Task 2: Complete the crypto-basics `encrypt_with_label` KAT

**Files:**
- Modify: `mls/cipher/kat_test.go`

The `crypto-basics.json` vectors from Plan 1 already contain `encrypt_with_label`; Plan 1 deferred it. Now verify it by decryption for the classical suites.

- [ ] **Step 1: Add the vector struct and assertion**

Edit `mls/cipher/kat_test.go`. Add this struct type alongside the existing vector structs:

```go
type encryptVec struct {
	Priv       katutil.HexBytes `json:"priv"`
	Pub        katutil.HexBytes `json:"pub"`
	Label      string           `json:"label"`
	Context    katutil.HexBytes `json:"context"`
	Plaintext  katutil.HexBytes `json:"plaintext"`
	KEMOutput  katutil.HexBytes `json:"kem_output"`
	Ciphertext katutil.HexBytes `json:"ciphertext"`
}
```

Add the field to `cryptoBasicsCase` (replace the deferral comment):

```go
	SignWithLabel    signVec            `json:"sign_with_label"`
	EncryptWithLabel encryptVec         `json:"encrypt_with_label"`
}
```

Inside the per-suite `t.Run` subtest body in `TestCryptoBasicsKAT`, after the `VerifyWithLabel` assertion, add:

```go
		// encrypt_with_label: HPKE is randomized, so DECRYPT the vector's
		// (kem_output, ciphertext) with priv and compare to plaintext.
		ewl := c.EncryptWithLabel
		pt, err := cs.DecryptWithLabel(ewl.Priv, ewl.Label, ewl.Context, ewl.KEMOutput, ewl.Ciphertext)
		if err != nil || !bytes.Equal(pt, ewl.Plaintext) {
			t.Fatalf("case %d EncryptWithLabel(decrypt): got %x err %v, want %x", i, pt, err, ewl.Plaintext)
		}
```

- [ ] **Step 2: Run the KAT**

Run: `nix develop -c go test ./mls/cipher/ -run TestCryptoBasicsKAT -v`
Expected: PASS — subtests `suite-0x0001` and `suite-0x0002` now also verify `encrypt_with_label` by decryption.

- [ ] **Step 3: Run the whole package + commit**

Run: `nix develop -c go test ./mls/cipher/` and `nix develop -c go vet ./mls/...` — clean.

```bash
git add mls/cipher/kat_test.go
git commit -m "test(cipher): verify crypto-basics encrypt_with_label via decryption"
```

---

## Task 3: Register the X-Wing post-quantum hybrid suite

**Files:**
- Create: `mls/cipher/suite_pq.go`
- Test: `mls/cipher/suite_pq_test.go`

- [ ] **Step 1: Write the failing test**

Create `mls/cipher/suite_pq_test.go`:

```go
package cipher_test

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

func TestXWingSuiteRoundTrip(t *testing.T) {
	cs, ok := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("X-Wing suite 0xF001 not registered")
	}
	if cs.HashLen() != 32 {
		t.Fatalf("HashLen=%d, want 32", cs.HashLen())
	}

	priv, pub, err := cs.GenerateHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHPKEKeyPair: %v", err)
	}
	// X-Wing public key = ML-KEM-768 enc key (1184) + X25519 (32) = 1216 bytes.
	if len(pub) != 1216 {
		t.Fatalf("X-Wing public key len=%d, want 1216", len(pub))
	}

	label := "pq label"
	context := []byte("ctx")
	plaintext := []byte("post-quantum secret")

	kemOut, ct, err := cs.EncryptWithLabel(pub, label, context, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithLabel: %v", err)
	}
	// X-Wing KEM output = ML-KEM-768 ciphertext (1088) + X25519 (32) = 1120 bytes;
	// this confirms ML-KEM is actually engaged, not just X25519.
	if len(kemOut) != 1120 {
		t.Fatalf("X-Wing kem_output len=%d, want 1120", len(kemOut))
	}

	got, err := cs.DecryptWithLabel(priv, label, context, kemOut, ct)
	if err != nil {
		t.Fatalf("DecryptWithLabel: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip: got %q, want %q", got, plaintext)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop -c go test ./mls/cipher/`
Expected: FAIL — `undefined: cipher.XWING_AES256GCM_SHA256_Ed25519`.

- [ ] **Step 3: Register the suite**

Create `mls/cipher/suite_pq.go`:

```go
package cipher

import (
	"crypto/hpke"
	"crypto/sha256"
)

// XWING_AES256GCM_SHA256_Ed25519 is a private-use (RFC 9420 §17.1 range
// 0xF000–0xFFFF) post-quantum ciphersuite: HPKE over the X-Wing hybrid KEM
// (X25519 + ML-KEM-768, draft-connolly-cfrg-xwing-kem, HPKE KEM id 0x647a),
// AES-256-GCM, SHA-256, with classical Ed25519 signatures. See design spec §7
// for why signatures stay classical.
const XWING_AES256GCM_SHA256_Ed25519 CipherSuite = 0xF001

func init() {
	registry[XWING_AES256GCM_SHA256_Ed25519] = Suite{
		ID:      XWING_AES256GCM_SHA256_Ed25519,
		NewHash: sha256.New,
		Sig:     SigEd25519,
		kem:     hpke.MLKEM768X25519(), // X-Wing
		kdf:     hpke.HKDFSHA256(),
		aead:    hpke.AES256GCM(),
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `nix develop -c go test ./mls/cipher/ -run TestXWingSuiteRoundTrip -v`
Expected: PASS — keypair generation, the 1216/1120 size checks, and the encrypt/decrypt round-trip all succeed.

- [ ] **Step 5: Run everything + commit**

Run: `nix develop -c go test ./...`, `nix develop -c go vet ./...`, `nix develop -c gofmt -l .` — all clean.

```bash
git add mls/cipher/suite_pq.go mls/cipher/suite_pq_test.go
git commit -m "feat(cipher): register X-Wing post-quantum hybrid suite (0xF001)"
```

---

## Definition of done (Plan 2)

- [ ] `go test ./...` passes from the module root; `go vet ./...` and `gofmt -l .` clean.
- [ ] `crypto-basics.json` now fully verified for suites 0x0001 & 0x0002, **including** `encrypt_with_label` (via decryption).
- [ ] X-Wing hybrid suite `0xF001` registered and round-trip tested, with size assertions confirming ML-KEM-768 is engaged (1216-byte pubkey, 1120-byte KEM output).
- [ ] `go.mod` remains dependency-free (stdlib `crypto/hpke` only).
- [ ] Three commits landed.

## Notes for the next plan
- Plan 3 (group state machine) will need raw AEAD seal/open (for message protection / the secret tree) and the HPKE key types threaded through TreeKEM. The `Suite.kem/kdf/aead` fields established here are the foundation; expose raw AEAD `Seal`/`Open` on `Suite` in Plan 3 where they are first exercised by `message-protection.json` / `secret-tree.json`.
- The X-Wing suite has no official KAT (no IANA-registered MLS PQ suite); its correctness rests on the stdlib X-Wing implementation plus our round-trip + size tests. If an IETF PQ-MLS suite is later registered, add its KATs and a registry alias.
