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
	c2 := NewCursor([]byte{0x05, 0x01})
	if _, err := c2.ReadOpaqueV(); err == nil {
		t.Fatal("expected short read error for opaque<V>")
	}
	c3 := NewCursor(nil)
	if _, err := c3.ReadUint8(); err == nil {
		t.Fatal("expected error reading from empty cursor")
	}
}
