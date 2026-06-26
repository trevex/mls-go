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
