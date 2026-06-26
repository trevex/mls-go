# Foundations (Plan 1 of 6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the stdlib-only foundation of the MLS engine — the RFC 9420 wire codec (variable-length integers / `<V>` vectors), ratchet-tree array math, and labeled cryptography — and prove it against the official MLS KAT vectors `deserialization`, `tree-math`, and `crypto-basics` (non-HPKE fields).

**Architecture:** Three independent packages under `mls/`: `mls/syntax` (presentation-language codec), `mls/tree` (left-balanced binary tree index math), `mls/cipher` (ciphersuite registry + labeled crypto). Each is driven test-first by its own unit tests, then locked down by the matching official KAT JSON vendored under `mls/testdata/`. A tiny `mls/internal/katutil` provides hex-decoding JSON helpers shared by the KAT tests.

**Tech Stack:** Go 1.26 standard library only (`crypto/sha256`, `crypto/sha512`, `crypto/hmac`, `crypto/hkdf`, `crypto/ed25519`, `crypto/ecdsa`, `encoding/json`, `encoding/hex`). No third-party dependencies in this plan; HPKE/KEM and the hybrid PQC suite arrive in Plan 2.

**Spec reference:** `docs/superpowers/specs/2026-06-26-mls-mlkem-go-design.md` §6 (conformance), §7 (crypto). RFC 9420 §2.1.2 (varints), §4.1.2 (tree math), §5.1–5.2 (labeled crypto), §7.1 (DeriveTreeSecret).

---

## File Structure

| File | Responsibility |
|---|---|
| `mls/syntax/varint.go` | RFC 9420 §2.1.2 variable-length integer + `opaque<V>` encode/decode |
| `mls/syntax/varint_test.go` | Unit tests for varint round-trip + edge cases |
| `mls/syntax/kat_test.go` | `deserialization.json` KAT |
| `mls/tree/math.go` | Node-index math for the left-balanced binary tree (root/left/right/parent/sibling) |
| `mls/tree/math_test.go` | Unit tests for small trees |
| `mls/tree/kat_test.go` | `tree-math.json` KAT |
| `mls/cipher/suite.go` | `CipherSuite` type + registry; hash/HMAC/HKDF/signature primitives for suites 0x0001 & 0x0002 |
| `mls/cipher/errors.go` | Sentinel errors for the cipher package |
| `mls/cipher/suite_test.go` | Registry + primitive sanity tests |
| `mls/cipher/labeled.go` | `RefHash`, `ExpandWithLabel`, `DeriveSecret`, `DeriveTreeSecret`, `SignWithLabel`/`VerifyWithLabel` |
| `mls/cipher/labeled_test.go` | Unit tests for labeled crypto |
| `mls/cipher/kat_test.go` | `crypto-basics.json` KAT (all fields except `encrypt_with_label`, deferred to Plan 2) |
| `mls/internal/katutil/katutil.go` | `HexBytes` JSON type + `Load` helper for vendored vectors |
| `mls/testdata/*.json` | Vendored official KAT vectors |

---

## Task 1: Wire codec — variable-length integers and `opaque<V>`

**Files:**
- Create: `mls/internal/katutil/katutil.go`
- Create: `mls/syntax/varint.go`
- Test: `mls/syntax/varint_test.go`, `mls/syntax/kat_test.go`
- Data: `mls/testdata/deserialization.json`

- [ ] **Step 1: Add the shared KAT helper**

Create `mls/internal/katutil/katutil.go`:

```go
// Package katutil provides JSON helpers for loading the official MLS
// known-answer-test (KAT) vectors vendored under mls/testdata.
package katutil

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// HexBytes unmarshals a JSON hex string into raw bytes. An empty or absent
// JSON string decodes to a nil slice.
type HexBytes []byte

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*h = nil
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

// Load reads and JSON-decodes a vendored KAT file into v. The name is the
// bare file name, e.g. "tree-math.json". Tests live one directory below the
// module root, so testdata is resolved relative to the caller's package dir.
func Load(t *testing.T, name string, v any) {
	t.Helper()
	path := filepath.Join("..", "testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
}
```

- [ ] **Step 2: Vendor the `deserialization.json` vectors**

Run:
```bash
mkdir -p mls/testdata
curl -fsSL -o mls/testdata/deserialization.json \
  https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/deserialization.json
```
Expected: a JSON array of objects each with `vlbytes_header` (hex) and `length` (number). Verify with `head -c 200 mls/testdata/deserialization.json`.

- [ ] **Step 3: Write the failing unit test**

Create `mls/syntax/varint_test.go`:

```go
package syntax

import (
	"bytes"
	"testing"
)

func TestVarintRoundTrip(t *testing.T) {
	cases := []uint64{0, 1, 63, 64, 16383, 16384, (1 << 30) - 1}
	for _, v := range cases {
		enc, err := WriteVarint(v)
		if err != nil {
			t.Fatalf("WriteVarint(%d): %v", v, err)
		}
		got, n, err := ReadVarint(enc)
		if err != nil {
			t.Fatalf("ReadVarint(%x): %v", enc, err)
		}
		if got != v || n != len(enc) {
			t.Fatalf("round-trip %d: got (%d, %d), want (%d, %d)", v, got, n, v, len(enc))
		}
	}
}

func TestVarintRejectsNonMinimal(t *testing.T) {
	// 0x4000 is a 2-byte header encoding value 0, which must be 1-byte (0x00).
	if _, _, err := ReadVarint([]byte{0x40, 0x00}); err == nil {
		t.Fatal("expected non-minimal encoding to be rejected")
	}
}

func TestVarintRejectsEightByte(t *testing.T) {
	// 0b11 prefix => 8-byte form, disallowed by RFC 9420.
	if _, _, err := ReadVarint([]byte{0xc0, 0, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Fatal("expected 8-byte varint to be rejected")
	}
}

func TestOpaqueVRoundTrip(t *testing.T) {
	in := []byte("hello mls")
	enc, err := WriteOpaqueV(in)
	if err != nil {
		t.Fatalf("WriteOpaqueV: %v", err)
	}
	got, n, err := ReadOpaqueV(enc)
	if err != nil {
		t.Fatalf("ReadOpaqueV: %v", err)
	}
	if !bytes.Equal(got, in) || n != len(enc) {
		t.Fatalf("opaque round-trip: got %q (n=%d), want %q (n=%d)", got, n, in, len(enc))
	}
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd mls/syntax && go test ./...`
Expected: FAIL — `undefined: WriteVarint` (package does not compile yet).

- [ ] **Step 5: Implement the codec**

Create `mls/syntax/varint.go`:

```go
// Package syntax implements the RFC 9420 presentation-language wire encoding:
// QUIC-style variable-length integers (§2.1.2) and opaque<V> byte vectors.
package syntax

import "fmt"

// MaxVarint is the largest length RFC 9420 permits (2^30 - 1); the 8-byte
// QUIC varint form is disallowed.
const MaxVarint = (1 << 30) - 1

// WriteVarint encodes v using the minimal 1-, 2-, or 4-byte form.
func WriteVarint(v uint64) ([]byte, error) {
	switch {
	case v < (1 << 6):
		return []byte{byte(v)}, nil
	case v < (1 << 14):
		return []byte{0x40 | byte(v>>8), byte(v)}, nil
	case v <= MaxVarint:
		return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}, nil
	default:
		return nil, fmt.Errorf("syntax: varint %d exceeds max %d", v, MaxVarint)
	}
}

// ReadVarint decodes a varint from the front of b, returning the value and the
// number of bytes consumed. It enforces minimal encoding and rejects the
// 8-byte form, per RFC 9420 §2.1.2.
func ReadVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("syntax: empty varint")
	}
	prefix := b[0] >> 6
	if prefix == 3 {
		return 0, 0, fmt.Errorf("syntax: 8-byte varint not allowed in MLS")
	}
	length := 1 << prefix // 1, 2, or 4
	if len(b) < length {
		return 0, 0, fmt.Errorf("syntax: short varint: need %d, have %d", length, len(b))
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = (v << 8) | uint64(b[i])
	}
	canon, _ := WriteVarint(v)
	if len(canon) != length {
		return 0, 0, fmt.Errorf("syntax: non-minimal varint encoding")
	}
	return v, length, nil
}

// WriteOpaqueV encodes b as a varint length prefix followed by the bytes.
func WriteOpaqueV(b []byte) ([]byte, error) {
	hdr, err := WriteVarint(uint64(len(b)))
	if err != nil {
		return nil, err
	}
	return append(hdr, b...), nil
}

// ReadOpaqueV decodes a varint-prefixed byte vector, returning the contents and
// total bytes consumed (prefix + body).
func ReadOpaqueV(b []byte) ([]byte, int, error) {
	n, hdrLen, err := ReadVarint(b)
	if err != nil {
		return nil, 0, err
	}
	total := hdrLen + int(n)
	if len(b) < total {
		return nil, 0, fmt.Errorf("syntax: short opaque<V>: need %d, have %d", total, len(b))
	}
	return b[hdrLen:total], total, nil
}
```

- [ ] **Step 6: Run the unit test to verify it passes**

Run: `cd mls/syntax && go test ./...`
Expected: PASS.

- [ ] **Step 7: Write the KAT test**

Create `mls/syntax/kat_test.go`:

```go
package syntax_test

import (
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
)

type deserCase struct {
	VLBytesHeader katutil.HexBytes `json:"vlbytes_header"`
	Length        uint64           `json:"length"`
}

func TestDeserializationKAT(t *testing.T) {
	var cases []deserCase
	katutil.Load(t, "deserialization.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no deserialization vectors loaded")
	}
	for i, c := range cases {
		got, n, err := syntax.ReadVarint(c.VLBytesHeader)
		if err != nil {
			t.Fatalf("case %d: ReadVarint(%x): %v", i, c.VLBytesHeader, err)
		}
		if got != c.Length {
			t.Fatalf("case %d: length got %d, want %d", i, got, c.Length)
		}
		if n != len(c.VLBytesHeader) {
			t.Fatalf("case %d: consumed %d bytes, header is %d", i, n, len(c.VLBytesHeader))
		}
	}
}
```

- [ ] **Step 8: Run the KAT to verify it passes**

Run: `cd mls/syntax && go test ./...`
Expected: PASS, exercising every vector in `deserialization.json`.

- [ ] **Step 9: Commit**

```bash
git add mls/syntax mls/internal/katutil mls/testdata/deserialization.json
git commit -m "feat(syntax): RFC 9420 varint + opaque<V> codec with deserialization KAT"
```

---

## Task 2: Ratchet-tree array math

**Files:**
- Create: `mls/tree/math.go`
- Test: `mls/tree/math_test.go`, `mls/tree/kat_test.go`
- Data: `mls/testdata/tree-math.json`

- [ ] **Step 1: Vendor the `tree-math.json` vectors**

Run:
```bash
curl -fsSL -o mls/testdata/tree-math.json \
  https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/tree-math.json
```
Expected: JSON array of objects with `n_leaves`, `n_nodes`, `root`, and arrays `left`, `right`, `parent`, `sibling` whose elements are node indices or `null`.

- [ ] **Step 2: Write the failing unit test**

Create `mls/tree/math_test.go`:

```go
package tree

import "testing"

func TestNodeWidth(t *testing.T) {
	// n leaves => 2n-1 nodes.
	cases := map[uint32]uint32{1: 1, 2: 3, 3: 5, 4: 7, 5: 9}
	for n, want := range cases {
		if got := NodeWidth(n); got != want {
			t.Fatalf("NodeWidth(%d)=%d, want %d", n, got, want)
		}
	}
}

func TestRootAndParentSmall(t *testing.T) {
	// 4 leaves -> width 7, root index 3.
	if got := Root(4); got != 3 {
		t.Fatalf("Root(4)=%d, want 3", got)
	}
	// Leaf 0 (node index 0) has parent 1 in a 4-leaf tree.
	p, ok := Parent(0, 4)
	if !ok || p != 1 {
		t.Fatalf("Parent(0,4)=(%d,%v), want (1,true)", p, ok)
	}
	// The root has no parent.
	if _, ok := Parent(3, 4); ok {
		t.Fatal("Parent(root) should be none")
	}
	// Leaves have no children.
	if _, ok := Left(0); ok {
		t.Fatal("Left(leaf) should be none")
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd mls/tree && go test ./...`
Expected: FAIL — `undefined: NodeWidth`.

- [ ] **Step 4: Implement the tree math**

Create `mls/tree/math.go`. Node indices follow RFC 9420 §4.1.2: leaves are even indices `0,2,4,…`, parents are odd. Functions returning `(uint32, bool)` use `false` to mean "no such node" (JSON `null`).

```go
// Package tree implements the node-index math for the RFC 9420 §4.1.2
// left-balanced binary tree used by TreeKEM. Indices are array positions:
// leaves at even indices, intermediate nodes at odd indices.
package tree

// NodeWidth returns the number of nodes for a tree with nLeaves leaves.
func NodeWidth(nLeaves uint32) uint32 {
	if nLeaves == 0 {
		return 0
	}
	return 2*(nLeaves-1) + 1
}

// log2 returns floor(log2(x)); log2(0) == 0.
func log2(x uint32) uint32 {
	if x == 0 {
		return 0
	}
	k := uint32(0)
	for x>>k > 0 {
		k++
	}
	return k - 1
}

// level returns the height of node x (0 for leaves).
func level(x uint32) uint32 {
	if x&1 == 0 {
		return 0
	}
	k := uint32(0)
	for (x>>k)&1 == 1 {
		k++
	}
	return k
}

// Root returns the root node index for a tree of nLeaves leaves.
func Root(nLeaves uint32) uint32 {
	w := NodeWidth(nLeaves)
	return (1 << log2(w)) - 1
}

// Left returns the left child of x; ok is false if x is a leaf.
func Left(x uint32) (uint32, bool) {
	k := level(x)
	if k == 0 {
		return 0, false
	}
	return x ^ (1 << (k - 1)), true
}

// Right returns the right child of x; ok is false if x is a leaf.
func Right(x uint32) (uint32, bool) {
	k := level(x)
	if k == 0 {
		return 0, false
	}
	return x ^ (3 << (k - 1)), true
}

// parentStep computes the parent in the complete tree (ignores bounds).
func parentStep(x uint32) uint32 {
	k := level(x)
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1))
}

// Parent returns the parent of x within a tree of nLeaves; ok is false if x is
// the root. Parents that fall outside the (possibly non-full) tree are walked
// up until they land in range.
func Parent(x, nLeaves uint32) (uint32, bool) {
	if x == Root(nLeaves) {
		return 0, false
	}
	w := NodeWidth(nLeaves)
	p := parentStep(x)
	for p >= w {
		p = parentStep(p)
	}
	return p, true
}

// Sibling returns the sibling of x within a tree of nLeaves; ok is false if x
// is the root.
func Sibling(x, nLeaves uint32) (uint32, bool) {
	p, ok := Parent(x, nLeaves)
	if !ok {
		return 0, false
	}
	if l, _ := Left(p); l == x {
		return Right(p) // r always exists because p is internal
	}
	if l, ok := Left(p); ok {
		return l, true
	}
	return 0, false
}
```

> Note: the `tree-math.json` KAT (Task step 6) is the authoritative acceptance gate. If any vector disagrees, fix the math here and re-run; do not relax the test.

- [ ] **Step 5: Run the unit test to verify it passes**

Run: `cd mls/tree && go test ./...`
Expected: PASS.

- [ ] **Step 6: Write the KAT test**

Create `mls/tree/kat_test.go`:

```go
package tree_test

import (
	"encoding/json"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// nodeRef models a JSON element that is either a node index or null.
type nodeRef struct {
	val uint32
	set bool
}

func (n *nodeRef) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		n.set = false
		return nil
	}
	var v uint32
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	n.val, n.set = v, true
	return nil
}

type treeMathCase struct {
	NLeaves uint32    `json:"n_leaves"`
	NNodes  uint32    `json:"n_nodes"`
	Root    uint32    `json:"root"`
	Left    []nodeRef `json:"left"`
	Right   []nodeRef `json:"right"`
	Parent  []nodeRef `json:"parent"`
	Sibling []nodeRef `json:"sibling"`
}

func check(t *testing.T, idx int, name string, want nodeRef, gotVal uint32, gotOK bool) {
	t.Helper()
	if want.set != gotOK || (gotOK && want.val != gotVal) {
		t.Fatalf("node %d %s: got (%d,%v), want (%d,%v)", idx, name, gotVal, gotOK, want.val, want.set)
	}
}

func TestTreeMathKAT(t *testing.T) {
	var cases []treeMathCase
	katutil.Load(t, "tree-math.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no tree-math vectors loaded")
	}
	for _, c := range cases {
		if got := tree.NodeWidth(c.NLeaves); got != c.NNodes {
			t.Fatalf("NodeWidth(%d)=%d, want %d", c.NLeaves, got, c.NNodes)
		}
		if got := tree.Root(c.NLeaves); got != c.Root {
			t.Fatalf("Root(%d)=%d, want %d", c.NLeaves, got, c.Root)
		}
		for i := uint32(0); i < c.NNodes; i++ {
			lv, lok := tree.Left(i)
			check(t, int(i), "left", c.Left[i], lv, lok)
			rv, rok := tree.Right(i)
			check(t, int(i), "right", c.Right[i], rv, rok)
			pv, pok := tree.Parent(i, c.NLeaves)
			check(t, int(i), "parent", c.Parent[i], pv, pok)
			sv, sok := tree.Sibling(i, c.NLeaves)
			check(t, int(i), "sibling", c.Sibling[i], sv, sok)
		}
	}
}
```

- [ ] **Step 7: Run the KAT to verify it passes**

Run: `cd mls/tree && go test ./...`
Expected: PASS over all `tree-math.json` vectors. If a vector fails, correct `math.go` and re-run.

- [ ] **Step 8: Commit**

```bash
git add mls/tree mls/testdata/tree-math.json
git commit -m "feat(tree): RFC 9420 left-balanced tree node math with tree-math KAT"
```

---

## Task 3: Ciphersuite registry + stdlib primitives

**Files:**
- Create: `mls/cipher/suite.go`
- Test: `mls/cipher/suite_test.go`

- [ ] **Step 1: Write the failing test**

Create `mls/cipher/suite_test.go`:

```go
package cipher

import (
	"bytes"
	"testing"
)

func TestSuiteLookup(t *testing.T) {
	cs, ok := Lookup(X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite 0x0001 not registered")
	}
	if cs.HashLen() != 32 {
		t.Fatalf("HashLen=%d, want 32", cs.HashLen())
	}
}

func TestHashAndMAC(t *testing.T) {
	cs, _ := Lookup(X25519_AES128GCM_SHA256_Ed25519)
	h1 := cs.Hash([]byte("abc"))
	h2 := cs.Hash([]byte("abc"))
	if !bytes.Equal(h1, h2) || len(h1) != 32 {
		t.Fatalf("Hash unstable or wrong length: %x / %x", h1, h2)
	}
	tag := cs.MAC([]byte("key"), []byte("msg"))
	if len(tag) != 32 {
		t.Fatalf("MAC length=%d, want 32", len(tag))
	}
}

func TestUnknownSuite(t *testing.T) {
	if _, ok := Lookup(CipherSuite(0xFFFF)); ok {
		t.Fatal("unknown suite should not resolve")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd mls/cipher && go test ./...`
Expected: FAIL — `undefined: Lookup`.

- [ ] **Step 3: Implement the registry and primitives**

Create `mls/cipher/suite.go`:

```go
// Package cipher implements the MLS ciphersuite registry and the labeled
// cryptography of RFC 9420 §5. This plan covers the hash, HMAC, HKDF, and
// signature primitives plus labeled key derivation; HPKE (EncryptWithLabel)
// and the hybrid PQC suite are added in Plan 2.
package cipher

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// CipherSuite is the 2-byte MLS ciphersuite identifier (RFC 9420 §17.1).
type CipherSuite uint16

const (
	X25519_AES128GCM_SHA256_Ed25519 CipherSuite = 0x0001
	P256_AES128GCM_SHA256_P256      CipherSuite = 0x0002
)

// SignatureScheme enumerates the signature algorithms used by leaf credentials.
type SignatureScheme uint8

const (
	SigEd25519 SignatureScheme = iota
	SigECDSAP256
)

// Suite bundles the primitive constructors for one ciphersuite. KEM/AEAD/HPKE
// fields are added in Plan 2; this struct intentionally exposes only what the
// foundation needs.
type Suite struct {
	ID      CipherSuite
	NewHash func() hash.Hash
	Sig     SignatureScheme
}

var registry = map[CipherSuite]Suite{
	X25519_AES128GCM_SHA256_Ed25519: {
		ID:      X25519_AES128GCM_SHA256_Ed25519,
		NewHash: sha256.New,
		Sig:     SigEd25519,
	},
	P256_AES128GCM_SHA256_P256: {
		ID:      P256_AES128GCM_SHA256_P256,
		NewHash: sha256.New,
		Sig:     SigECDSAP256,
	},
}

// Lookup returns the Suite for id and whether it is registered.
func Lookup(id CipherSuite) (Suite, bool) {
	s, ok := registry[id]
	return s, ok
}

// HashLen returns the digest size in bytes.
func (s Suite) HashLen() int { return s.NewHash().Size() }

// Hash returns Hash(data).
func (s Suite) Hash(data []byte) []byte {
	h := s.NewHash()
	h.Write(data)
	return h.Sum(nil)
}

// MAC returns HMAC-Hash(key, data) — the MLS MAC primitive (RFC 9420 §5.2).
func (s Suite) MAC(key, data []byte) []byte {
	m := hmac.New(s.NewHash, key)
	m.Write(data)
	return m.Sum(nil)
}

// kdfExpand wraps HKDF-Expand with the suite hash (RFC 9420 §8 KDF.Expand).
func (s Suite) kdfExpand(secret, info []byte, length int) ([]byte, error) {
	return hkdf.Expand(s.NewHash, secret, string(info), length)
}

// verifyClassical verifies a raw signature for the suite's scheme. Used by
// VerifyWithLabel in labeled.go.
func (s Suite) verifyClassical(pub, message, sig []byte) bool {
	switch s.Sig {
	case SigEd25519:
		return len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), message, sig)
	case SigECDSAP256:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pub)
		if x == nil {
			xx, yy := elliptic.Unmarshal(elliptic.P256(), pub)
			if xx == nil {
				return false
			}
			x, y = xx, yy
		}
		pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		digest := s.Hash(message)
		return ecdsa.VerifyASN1(pk, digest, sig)
	default:
		return false
	}
}

// signClassical signs message with priv for the suite's scheme. Used by
// SignWithLabel in labeled.go and by tests.
func (s Suite) signClassical(priv crypto.Signer, message []byte) ([]byte, error) {
	switch s.Sig {
	case SigEd25519:
		return priv.Sign(nil, message, crypto.Hash(0))
	case SigECDSAP256:
		digest := s.Hash(message)
		return priv.Sign(nil, digest, crypto.SHA256)
	default:
		return nil, errUnsupportedScheme
	}
}
```

Create `mls/cipher/errors.go`:

```go
package cipher

import "errors"

var errUnsupportedScheme = errors.New("cipher: unsupported signature scheme")
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd mls/cipher && go test ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mls/cipher/suite.go mls/cipher/errors.go mls/cipher/suite_test.go
git commit -m "feat(cipher): ciphersuite registry with hash/MAC/HKDF/signature primitives"
```

---

## Task 4: Labeled cryptography + crypto-basics KAT

**Files:**
- Create: `mls/cipher/labeled.go`
- Test: `mls/cipher/labeled_test.go`, `mls/cipher/kat_test.go`
- Data: `mls/testdata/crypto-basics.json`

- [ ] **Step 1: Vendor the `crypto-basics.json` vectors**

Run:
```bash
curl -fsSL -o mls/testdata/crypto-basics.json \
  https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/crypto-basics.json
```
Expected: JSON array; each object has `cipher_suite` and sub-objects `ref_hash`, `expand_with_label`, `derive_secret`, `derive_tree_secret`, `sign_with_label`, `encrypt_with_label`.

- [ ] **Step 2: Write the failing unit test**

Create `mls/cipher/labeled_test.go`:

```go
package cipher

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestExpandWithLabelDeterministic(t *testing.T) {
	cs, _ := Lookup(X25519_AES128GCM_SHA256_Ed25519)
	out1, err := cs.ExpandWithLabel([]byte("secret0123456789secret0123456789"), "test", []byte("ctx"), 16)
	if err != nil {
		t.Fatal(err)
	}
	out2, _ := cs.ExpandWithLabel([]byte("secret0123456789secret0123456789"), "test", []byte("ctx"), 16)
	if !bytes.Equal(out1, out2) || len(out1) != 16 {
		t.Fatalf("ExpandWithLabel not deterministic / wrong length")
	}
}

func TestSignVerifyWithLabel(t *testing.T) {
	cs, _ := Lookup(X25519_AES128GCM_SHA256_Ed25519)
	pub, priv, _ := ed25519.GenerateKey(nil)
	content := []byte("payload")
	sig, err := cs.SignWithLabel(priv, "FramedContentTBS", content)
	if err != nil {
		t.Fatal(err)
	}
	if !cs.VerifyWithLabel(pub, "FramedContentTBS", content, sig) {
		t.Fatal("VerifyWithLabel rejected a valid signature")
	}
	if cs.VerifyWithLabel(pub, "FramedContentTBS", []byte("tampered"), sig) {
		t.Fatal("VerifyWithLabel accepted a forged signature")
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd mls/cipher && go test ./...`
Expected: FAIL — `undefined: cs.ExpandWithLabel`.

- [ ] **Step 4: Implement labeled crypto**

Create `mls/cipher/labeled.go`:

```go
package cipher

import (
	"crypto"
	"encoding/binary"

	"github.com/trevex/mls-mlkem-go/mls/syntax"
)

// mlsLabelPrefix is prepended to every label per RFC 9420 §5.
const mlsLabelPrefix = "MLS 1.0 "

// RefHash computes Hash(RefHashInput{label, value}) (RFC 9420 §5.2). The label
// is used verbatim (callers pass the full label, including any "MLS 1.0 ..."
// text as the vectors specify).
func (s Suite) RefHash(label string, value []byte) ([]byte, error) {
	lbl, err := syntax.WriteOpaqueV([]byte(label))
	if err != nil {
		return nil, err
	}
	val, err := syntax.WriteOpaqueV(value)
	if err != nil {
		return nil, err
	}
	return s.Hash(append(lbl, val...)), nil
}

// ExpandWithLabel implements RFC 9420 §8:
//
//	KDFLabel = struct{ uint16 length; opaque label<V>; opaque context<V> }
//	label = "MLS 1.0 " + Label
func (s Suite) ExpandWithLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, uint16(length))
	lbl, err := syntax.WriteOpaqueV([]byte(mlsLabelPrefix + label))
	if err != nil {
		return nil, err
	}
	buf = append(buf, lbl...)
	ctx, err := syntax.WriteOpaqueV(context)
	if err != nil {
		return nil, err
	}
	buf = append(buf, ctx...)
	return s.kdfExpand(secret, buf, length)
}

// DeriveSecret implements RFC 9420 §8:
//
//	DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "", Hash.length)
func (s Suite) DeriveSecret(secret []byte, label string) ([]byte, error) {
	return s.ExpandWithLabel(secret, label, nil, s.HashLen())
}

// DeriveTreeSecret implements RFC 9420 §7.1:
//
//	DeriveTreeSecret(Secret, Label, Generation, Length)
//	    = ExpandWithLabel(Secret, Label, encode_uint32(Generation), Length)
func (s Suite) DeriveTreeSecret(secret []byte, label string, generation uint32, length int) ([]byte, error) {
	ctx := binary.BigEndian.AppendUint32(nil, generation)
	return s.ExpandWithLabel(secret, label, ctx, length)
}

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

// SignWithLabel signs content under the labeled scheme (RFC 9420 §5.1.2).
func (s Suite) SignWithLabel(priv crypto.Signer, label string, content []byte) ([]byte, error) {
	tbs, err := s.signContent(label, content)
	if err != nil {
		return nil, err
	}
	return s.signClassical(priv, tbs)
}

// VerifyWithLabel verifies a labeled signature (RFC 9420 §5.1.2).
func (s Suite) VerifyWithLabel(pub []byte, label string, content, sig []byte) bool {
	tbs, err := s.signContent(label, content)
	if err != nil {
		return false
	}
	return s.verifyClassical(pub, tbs, sig)
}
```

- [ ] **Step 5: Run the unit test to verify it passes**

Run: `cd mls/cipher && go test ./...`
Expected: PASS.

- [ ] **Step 6: Write the crypto-basics KAT**

Create `mls/cipher/kat_test.go`:

```go
package cipher_test

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
)

type refHashVec struct {
	Label string           `json:"label"`
	Value katutil.HexBytes `json:"value"`
	Out   katutil.HexBytes `json:"out"`
}
type expandVec struct {
	Secret  katutil.HexBytes `json:"secret"`
	Label   string           `json:"label"`
	Context katutil.HexBytes `json:"context"`
	Length  int              `json:"length"`
	Out     katutil.HexBytes `json:"out"`
}
type deriveSecretVec struct {
	Secret katutil.HexBytes `json:"secret"`
	Label  string           `json:"label"`
	Out    katutil.HexBytes `json:"out"`
}
type deriveTreeVec struct {
	Secret     katutil.HexBytes `json:"secret"`
	Label      string           `json:"label"`
	Generation uint32           `json:"generation"`
	Length     int              `json:"length"`
	Out        katutil.HexBytes `json:"out"`
}
type signVec struct {
	Priv      katutil.HexBytes `json:"priv"`
	Pub       katutil.HexBytes `json:"pub"`
	Content   katutil.HexBytes `json:"content"`
	Label     string           `json:"label"`
	Signature katutil.HexBytes `json:"signature"`
}
type cryptoBasicsCase struct {
	CipherSuite      cipher.CipherSuite `json:"cipher_suite"`
	RefHash          refHashVec         `json:"ref_hash"`
	ExpandWithLabel  expandVec          `json:"expand_with_label"`
	DeriveSecret     deriveSecretVec    `json:"derive_secret"`
	DeriveTreeSecret deriveTreeVec      `json:"derive_tree_secret"`
	SignWithLabel    signVec            `json:"sign_with_label"`
	// encrypt_with_label is deferred to Plan 2 (needs HPKE).
}

func TestCryptoBasicsKAT(t *testing.T) {
	var cases []cryptoBasicsCase
	katutil.Load(t, "crypto-basics.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no crypto-basics vectors loaded")
	}
	for i, c := range cases {
		cs, ok := cipher.Lookup(c.CipherSuite)
		if !ok {
			continue // suites added in later plans (e.g. P-384/X448) are skipped here
		}

		if got, err := cs.RefHash(c.RefHash.Label, c.RefHash.Value); err != nil || !bytes.Equal(got, c.RefHash.Out) {
			t.Fatalf("case %d RefHash: got %x err %v, want %x", i, got, err, c.RefHash.Out)
		}

		ewl := c.ExpandWithLabel
		if got, err := cs.ExpandWithLabel(ewl.Secret, ewl.Label, ewl.Context, ewl.Length); err != nil || !bytes.Equal(got, ewl.Out) {
			t.Fatalf("case %d ExpandWithLabel: got %x err %v, want %x", i, got, err, ewl.Out)
		}

		ds := c.DeriveSecret
		if got, err := cs.DeriveSecret(ds.Secret, ds.Label); err != nil || !bytes.Equal(got, ds.Out) {
			t.Fatalf("case %d DeriveSecret: got %x err %v, want %x", i, got, err, ds.Out)
		}

		dt := c.DeriveTreeSecret
		if got, err := cs.DeriveTreeSecret(dt.Secret, dt.Label, dt.Generation, dt.Length); err != nil || !bytes.Equal(got, dt.Out) {
			t.Fatalf("case %d DeriveTreeSecret: got %x err %v, want %x", i, got, err, dt.Out)
		}

		// Signatures are randomized, so verify rather than re-sign.
		sw := c.SignWithLabel
		if !cs.VerifyWithLabel(sw.Pub, sw.Label, sw.Content, sw.Signature) {
			t.Fatalf("case %d SignWithLabel: VerifyWithLabel rejected the vector signature", i)
		}
	}
}
```

- [ ] **Step 7: Run the KAT to verify it passes**

Run: `cd mls/cipher && go test ./...`
Expected: PASS over every `crypto-basics.json` case whose suite is 0x0001 or 0x0002.

- [ ] **Step 8: Run the whole module and commit**

Run: `go test ./...` (from the module root)
Expected: PASS in `mls/syntax`, `mls/tree`, `mls/cipher`.

```bash
git add mls/cipher/labeled.go mls/cipher/labeled_test.go mls/cipher/kat_test.go mls/testdata/crypto-basics.json
git commit -m "feat(cipher): labeled crypto (RefHash/Expand/Derive/Sign) with crypto-basics KAT"
```

---

## Definition of done (Plan 1)

- [ ] `go test ./...` passes from the module root.
- [ ] `deserialization.json`, `tree-math.json`, and the non-HPKE fields of `crypto-basics.json` all verify against the implementation.
- [ ] No third-party dependencies added to `go.mod`.
- [ ] Four commits landed (one per task).

## Notes for the next plan
- `encrypt_with_label` in `crypto-basics.json` is intentionally unverified here; Plan 2 adds HPKE (RFC 9180) via CIRCL and completes that field, then introduces the hybrid `X25519MLKEM768` suite and a private-use ciphersuite ID (spec §7).
- The `Suite` struct will grow KEM/AEAD/HPKE fields in Plan 2; keep additions backward-compatible with the registry shape established here.
```
