package syntax

import (
	"bytes"
	"testing"
)

type record struct {
	id     uint32
	name   []byte
	tags   [][]byte
	parent *uint32
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
	c := NewCursor([]byte{0x02})
	if _, err := ReadOptional(c, func(c *Cursor) (uint32, error) { return c.ReadUint32() }); err == nil {
		t.Fatal("expected error for invalid presence byte")
	}
}
