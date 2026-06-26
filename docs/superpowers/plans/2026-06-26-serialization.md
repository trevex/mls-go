# Serialization Framework (Plan 3 of 8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the RFC 9420 TLS-presentation-language serialization toolkit that every MLS data structure (KeyPackage, LeafNode, ratchet tree, Proposal, Commit, MLSMessage, GroupInfo, Welcome) will use to marshal/unmarshal its wire form — a `Builder`/`Cursor` pair for fixed-width integers, `opaque<V>` byte strings, `<V>` vectors of variable-length elements, and `optional<T>`.

**Architecture:** Extend `mls/syntax` (which already has the varint + `opaque<V>` primitives) with a stateful `Builder` (append-only byte buffer) and `Cursor` (front-consuming reader), plus generic free functions `WriteVectorV`/`ReadVectorV`/`WriteOptional`/`ReadOptional` (Go generics; methods can't be generic). No new MLS *types* yet — those arrive in Plans 4–8 as each subsystem needs them; this plan delivers the reusable encoding mechanism and proves it with round-trip tests including a representative composite struct.

**Tech Stack:** Go 1.26 standard library only (`encoding/binary`, `fmt`). Builds on Plan 1's `mls/syntax` (`WriteVarint`/`ReadVarint`/`WriteOpaqueV`/`ReadOpaqueV`).

**Spec reference:** RFC 9420 §2.1 (presentation language), §2.1.2 (varint vectors). Note: the official `messages.json` / `deserialization.json` KATs that exercise the *full* type zoo are deferred — `deserialization.json` is already passing (Plan 1), and `messages.json` round-trip is run in Plan 8 once all MLS types exist. This plan is gated by unit round-trip tests of the framework itself.

---

## Design notes (read before implementing)

- An MLS `<V>` vector of variable-length elements is encoded as `varint(totalBodyLen) || elem0 || elem1 || …`. To read it, take the length-prefixed body and decode elements until the body is exhausted — there is no element count, the body boundary delimits them. `WriteVectorV`/`ReadVectorV` encapsulate exactly this.
- `optional<T>` is a presence byte (`0x00` absent, `0x01` present) followed by the value when present (RFC 9420 §2.1.1).
- The `Cursor` must reject trailing garbage where callers expect a complete decode — callers check `Cursor.Empty()` after decoding a top-level message. `ReadVectorV` relies on decoding exactly to the body boundary; a sub-decode that overruns or underruns the body is an error.
- Fixed-width integers are big-endian (network order).

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `mls/syntax/codec.go` | Create | `Builder` and `Cursor`: fixed-width ints, raw bytes, varint, `opaque<V>`. |
| `mls/syntax/codec_test.go` | Create | Round-trip unit tests for `Builder`/`Cursor` primitives + error paths. |
| `mls/syntax/vector.go` | Create | Generic `WriteVectorV`/`ReadVectorV`/`WriteOptional`/`ReadOptional`. |
| `mls/syntax/vector_test.go` | Create | Round-trip tests for vectors, optionals, and a composite struct. |

---

## Task 1: `Builder` and `Cursor` primitives

**Files:**
- Create: `mls/syntax/codec.go`
- Test: `mls/syntax/codec_test.go`

- [ ] **Step 1: Write the failing test**

Create `mls/syntax/codec_test.go`:

```go
package syntax

import (
	"bytes"
	"testing"
)

func TestBuilderCursorIntsRoundTrip(t *testing.T) {
	b := NewBuilder()
	b.WriteUint8(0x12)
	b.WriteUint16(0x3456)
	b.WriteUint32(0x789abcde)
	b.WriteUint64(0x0102030405060708)
	b.WriteRaw([]byte{0xaa, 0xbb})

	c := NewCursor(b.Bytes())
	if v, _ := c.ReadUint8(); v != 0x12 {
		t.Fatalf("uint8=%#x", v)
	}
	if v, _ := c.ReadUint16(); v != 0x3456 {
		t.Fatalf("uint16=%#x", v)
	}
	if v, _ := c.ReadUint32(); v != 0x789abcde {
		t.Fatalf("uint32=%#x", v)
	}
	if v, _ := c.ReadUint64(); v != 0x0102030405060708 {
		t.Fatalf("uint64=%#x", v)
	}
	raw, _ := c.ReadRaw(2)
	if !bytes.Equal(raw, []byte{0xaa, 0xbb}) {
		t.Fatalf("raw=%x", raw)
	}
	if !c.Empty() {
		t.Fatalf("cursor should be empty, %d left", c.Remaining())
	}
}

func TestBuilderCursorOpaqueV(t *testing.T) {
	b := NewBuilder()
	if err := b.WriteOpaqueV([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := b.WriteOpaqueV(nil); err != nil {
		t.Fatal(err)
	}
	c := NewCursor(b.Bytes())
	v, err := c.ReadOpaqueV()
	if err != nil || string(v) != "hello" {
		t.Fatalf("opaque1=%q err=%v", v, err)
	}
	v, err = c.ReadOpaqueV()
	if err != nil || len(v) != 0 {
		t.Fatalf("opaque2=%q err=%v", v, err)
	}
	if !c.Empty() {
		t.Fatal("cursor not empty")
	}
}

func TestCursorShortReads(t *testing.T) {
	c := NewCursor([]byte{0x01})
	if _, err := c.ReadUint16(); err == nil {
		t.Fatal("expected short read error for uint16")
	}
	c2 := NewCursor([]byte{0x05, 0x01}) // opaque header says 5 bytes, only 1 present
	if _, err := c2.ReadOpaqueV(); err == nil {
		t.Fatal("expected short read error for opaque<V>")
	}
	c3 := NewCursor(nil)
	if _, err := c3.ReadUint8(); err == nil {
		t.Fatal("expected error reading from empty cursor")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop -c go test ./mls/syntax/`
Expected: FAIL — `undefined: NewBuilder`.

- [ ] **Step 3: Implement `codec.go`**

Create `mls/syntax/codec.go`:

```go
package syntax

import (
	"encoding/binary"
	"fmt"
)

// Builder is an append-only buffer for encoding MLS wire structures.
type Builder struct {
	buf []byte
}

// NewBuilder returns an empty Builder.
func NewBuilder() *Builder { return &Builder{} }

func (b *Builder) WriteUint8(v uint8)   { b.buf = append(b.buf, v) }
func (b *Builder) WriteUint16(v uint16) { b.buf = binary.BigEndian.AppendUint16(b.buf, v) }
func (b *Builder) WriteUint32(v uint32) { b.buf = binary.BigEndian.AppendUint32(b.buf, v) }
func (b *Builder) WriteUint64(v uint64) { b.buf = binary.BigEndian.AppendUint64(b.buf, v) }

// WriteRaw appends bytes with no length prefix.
func (b *Builder) WriteRaw(p []byte) { b.buf = append(b.buf, p...) }

// WriteVarint appends a variable-length integer (RFC 9420 §2.1.2).
func (b *Builder) WriteVarint(v uint64) error {
	enc, err := WriteVarint(v)
	if err != nil {
		return err
	}
	b.buf = append(b.buf, enc...)
	return nil
}

// WriteOpaqueV appends a varint-length-prefixed byte vector (opaque<V>).
func (b *Builder) WriteOpaqueV(p []byte) error {
	if err := b.WriteVarint(uint64(len(p))); err != nil {
		return err
	}
	b.buf = append(b.buf, p...)
	return nil
}

// Bytes returns the accumulated encoding. The result aliases the Builder's
// buffer; do not mutate it while still using the Builder.
func (b *Builder) Bytes() []byte { return b.buf }

// Cursor consumes an MLS wire encoding from front to back.
type Cursor struct {
	buf []byte
}

// NewCursor returns a Cursor over b.
func NewCursor(b []byte) *Cursor { return &Cursor{buf: b} }

// Remaining returns the number of unread bytes.
func (c *Cursor) Remaining() int { return len(c.buf) }

// Empty reports whether all bytes have been consumed.
func (c *Cursor) Empty() bool { return len(c.buf) == 0 }

func (c *Cursor) take(n int) ([]byte, error) {
	if len(c.buf) < n {
		return nil, fmt.Errorf("syntax: short read: need %d, have %d", n, len(c.buf))
	}
	p := c.buf[:n]
	c.buf = c.buf[n:]
	return p, nil
}

func (c *Cursor) ReadUint8() (uint8, error) {
	p, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return p[0], nil
}

func (c *Cursor) ReadUint16() (uint16, error) {
	p, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(p), nil
}

func (c *Cursor) ReadUint32() (uint32, error) {
	p, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(p), nil
}

func (c *Cursor) ReadUint64() (uint64, error) {
	p, err := c.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(p), nil
}

// ReadRaw consumes exactly n bytes. The returned slice aliases the underlying
// buffer; copy it if you need to retain it past further mutation of the source.
func (c *Cursor) ReadRaw(n int) ([]byte, error) { return c.take(n) }

// ReadVarint consumes a variable-length integer.
func (c *Cursor) ReadVarint() (uint64, error) {
	v, n, err := ReadVarint(c.buf)
	if err != nil {
		return 0, err
	}
	c.buf = c.buf[n:]
	return v, nil
}

// ReadOpaqueV consumes a varint-length-prefixed byte vector.
func (c *Cursor) ReadOpaqueV() ([]byte, error) {
	n, err := c.ReadVarint()
	if err != nil {
		return nil, err
	}
	return c.take(int(n))
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop -c go test ./mls/syntax/`
Expected: PASS (new tests + Plan 1's existing varint/KAT tests). Then `nix develop -c go vet ./mls/...`, `nix develop -c gofmt -l mls/` clean.

- [ ] **Step 5: Commit**

```bash
git add mls/syntax/codec.go mls/syntax/codec_test.go
git commit -m "feat(syntax): Builder/Cursor for MLS presentation-language primitives"
```

---

## Task 2: Generic vectors and optionals

**Files:**
- Create: `mls/syntax/vector.go`
- Test: `mls/syntax/vector_test.go`

- [ ] **Step 1: Write the failing test**

Create `mls/syntax/vector_test.go`:

```go
package syntax

import (
	"bytes"
	"testing"
)

// A composite struct exercising nested vectors + optional, mimicking the shape
// of real MLS structs (e.g. a leaf-like record).
type record struct {
	id     uint32
	name   []byte   // opaque<V>
	tags   [][]byte // vector<V> of opaque<V>
	parent *uint32  // optional<uint32>
}

func encRecord(b *Builder, r record) error {
	b.WriteUint32(r.id)
	if err := b.WriteOpaqueV(r.name); err != nil {
		return err
	}
	if err := WriteVectorV(b, r.tags, func(b *Builder, t []byte) error { return b.WriteOpaqueV(t) }); err != nil {
		return err
	}
	return WriteOptional(b, r.parent, func(b *Builder, v uint32) error { b.WriteUint32(v); return nil })
}

func decRecord(c *Cursor) (record, error) {
	var r record
	var err error
	if r.id, err = c.ReadUint32(); err != nil {
		return r, err
	}
	if r.name, err = c.ReadOpaqueV(); err != nil {
		return r, err
	}
	if r.tags, err = ReadVectorV(c, func(c *Cursor) ([]byte, error) { return c.ReadOpaqueV() }); err != nil {
		return r, err
	}
	if r.parent, err = ReadOptional(c, func(c *Cursor) (uint32, error) { return c.ReadUint32() }); err != nil {
		return r, err
	}
	return r, nil
}

func TestVectorOfOpaqueRoundTrip(t *testing.T) {
	b := NewBuilder()
	in := [][]byte{[]byte("a"), []byte("bb"), nil, []byte("dddd")}
	if err := WriteVectorV(b, in, func(b *Builder, t []byte) error { return b.WriteOpaqueV(t) }); err != nil {
		t.Fatal(err)
	}
	c := NewCursor(b.Bytes())
	out, err := ReadVectorV(c, func(c *Cursor) ([]byte, error) { return c.ReadOpaqueV() })
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("len=%d want %d", len(out), len(in))
	}
	for i := range in {
		if !bytes.Equal(out[i], in[i]) {
			t.Fatalf("elem %d: got %q want %q", i, out[i], in[i])
		}
	}
	if !c.Empty() {
		t.Fatal("cursor not empty")
	}
}

func TestEmptyVectorRoundTrip(t *testing.T) {
	b := NewBuilder()
	if err := WriteVectorV(b, [][]byte{}, func(b *Builder, t []byte) error { return b.WriteOpaqueV(t) }); err != nil {
		t.Fatal(err)
	}
	c := NewCursor(b.Bytes())
	out, err := ReadVectorV(c, func(c *Cursor) ([]byte, error) { return c.ReadOpaqueV() })
	if err != nil || len(out) != 0 {
		t.Fatalf("expected empty vector, got %v err %v", out, err)
	}
}

func TestOptionalRoundTrip(t *testing.T) {
	val := uint32(0xdeadbeef)
	for _, in := range []*uint32{nil, &val} {
		b := NewBuilder()
		if err := WriteOptional(b, in, func(b *Builder, v uint32) error { b.WriteUint32(v); return nil }); err != nil {
			t.Fatal(err)
		}
		c := NewCursor(b.Bytes())
		out, err := ReadOptional(c, func(c *Cursor) (uint32, error) { return c.ReadUint32() })
		if err != nil {
			t.Fatal(err)
		}
		if (in == nil) != (out == nil) {
			t.Fatalf("presence mismatch: in=%v out=%v", in, out)
		}
		if in != nil && *out != *in {
			t.Fatalf("value=%#x want %#x", *out, *in)
		}
	}
}

func TestCompositeRecordRoundTrip(t *testing.T) {
	p := uint32(7)
	in := record{id: 42, name: []byte("leaf"), tags: [][]byte{[]byte("x"), []byte("yy")}, parent: &p}
	b := NewBuilder()
	if err := encRecord(b, in); err != nil {
		t.Fatal(err)
	}
	c := NewCursor(b.Bytes())
	out, err := decRecord(c)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Empty() {
		t.Fatalf("trailing bytes: %d", c.Remaining())
	}
	if out.id != in.id || !bytes.Equal(out.name, in.name) || *out.parent != *in.parent || len(out.tags) != 2 {
		t.Fatalf("round-trip mismatch: %+v vs %+v", out, in)
	}
}

func TestOptionalRejectsBadPresenceByte(t *testing.T) {
	c := NewCursor([]byte{0x02}) // neither 0 nor 1
	if _, err := ReadOptional(c, func(c *Cursor) (uint32, error) { return c.ReadUint32() }); err == nil {
		t.Fatal("expected error for invalid presence byte")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop -c go test ./mls/syntax/`
Expected: FAIL — `undefined: WriteVectorV`.

- [ ] **Step 3: Implement `vector.go`**

Create `mls/syntax/vector.go`:

```go
package syntax

import "fmt"

// WriteVectorV encodes items as an MLS <V> vector of variable-length elements:
// a varint length prefix over the concatenation of each item's encoding.
func WriteVectorV[T any](b *Builder, items []T, enc func(*Builder, T) error) error {
	inner := NewBuilder()
	for _, it := range items {
		if err := enc(inner, it); err != nil {
			return err
		}
	}
	return b.WriteOpaqueV(inner.Bytes())
}

// ReadVectorV decodes an MLS <V> vector: it reads the length-prefixed body, then
// applies dec repeatedly until the body is exactly exhausted. A dec that reads
// past the body boundary surfaces as a short-read error from the inner cursor.
func ReadVectorV[T any](c *Cursor, dec func(*Cursor) (T, error)) ([]T, error) {
	body, err := c.ReadOpaqueV()
	if err != nil {
		return nil, err
	}
	sub := NewCursor(body)
	out := make([]T, 0)
	for !sub.Empty() {
		v, err := dec(sub)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// WriteOptional encodes optional<T> (RFC 9420 §2.1.1): a presence byte (0 absent,
// 1 present) followed by the value when present.
func WriteOptional[T any](b *Builder, v *T, enc func(*Builder, T) error) error {
	if v == nil {
		b.WriteUint8(0)
		return nil
	}
	b.WriteUint8(1)
	return enc(b, *v)
}

// ReadOptional decodes optional<T>.
func ReadOptional[T any](c *Cursor, dec func(*Cursor) (T, error)) (*T, error) {
	present, err := c.ReadUint8()
	if err != nil {
		return nil, err
	}
	switch present {
	case 0:
		return nil, nil
	case 1:
		v, err := dec(c)
		if err != nil {
			return nil, err
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("syntax: invalid optional presence byte %d", present)
	}
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop -c go test ./mls/syntax/`
Expected: PASS. Then `nix develop -c go vet ./mls/...` and `nix develop -c gofmt -l mls/` clean.

- [ ] **Step 5: Run the whole module + commit**

Run: `nix develop -c go test ./...`
Expected: PASS.

```bash
git add mls/syntax/vector.go mls/syntax/vector_test.go
git commit -m "feat(syntax): generic <V> vectors and optional<T> codec helpers"
```

---

## Definition of done (Plan 3)

- [ ] `go test ./...` passes; `go vet ./...` and `gofmt -l .` clean.
- [ ] `Builder`/`Cursor` round-trip all fixed-width ints, raw bytes, varint, `opaque<V>`, with short-read errors.
- [ ] `WriteVectorV`/`ReadVectorV` round-trip `<V>` vectors (including empty); `WriteOptional`/`ReadOptional` round-trip both presence states and reject invalid presence bytes.
- [ ] A composite struct round-trips and the cursor ends empty (no trailing-byte tolerance).
- [ ] `go.mod` remains dependency-free.

## Notes for the next plan
- Plan 4 (ratchet tree / TreeSync) is the first consumer: `LeafNode`, `ParentNode`, `KeyPackage`, `UpdatePathNode`, `Credential`, and the `ratchet_tree` extension all get `MarshalMLS`/`UnmarshalMLS` built on this toolkit, validated by `tree-validation.json` / `tree-operations.json`.
- Consider establishing a convention there: each MLS type implements `marshal(*syntax.Builder) error` and a package-level `decodeX(*syntax.Cursor) (X, error)`, with exported `MarshalMLS() ([]byte, error)` / `UnmarshalMLS([]byte) error` wrappers that enforce `Cursor.Empty()` at the top level.
