package keyschedule

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/tree"
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
