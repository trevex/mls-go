package ironcore

import (
	"bytes"
	"testing"
)

func TestGroupIDRoundTrip(t *testing.T) {
	cases := []uint32{0, 1, 0x0A0B0C0D, ^uint32(0)}
	for _, vni := range cases {
		gid := GroupID(vni)
		got, err := VNIOfGroupID(gid)
		if err != nil {
			t.Fatalf("VNIOfGroupID(GroupID(%#x)): %v", vni, err)
		}
		if got != vni {
			t.Fatalf("round-trip(%#x): got %#x", vni, got)
		}
	}
}

func TestGroupIDDistinct(t *testing.T) {
	a := GroupID(0x0001)
	b := GroupID(0x0002)
	if bytes.Equal(a, b) {
		t.Fatal("distinct VNIs produced equal GroupIDs")
	}
}

func TestVNIOfGroupIDErrors(t *testing.T) {
	// Wrong length (too short).
	if _, err := VNIOfGroupID([]byte("short")); err == nil {
		t.Fatal("expected error for short input, got nil")
	}
	// Correct length but wrong tag.
	wrong := make([]byte, len(groupIDTag)+4)
	copy(wrong, "WRONG1")
	if _, err := VNIOfGroupID(wrong); err == nil {
		t.Fatal("expected error for wrong tag, got nil")
	}
	// Tag only, no VNI bytes (truncated).
	if _, err := VNIOfGroupID(groupIDTag); err == nil {
		t.Fatal("expected error for truncated id, got nil")
	}
}
