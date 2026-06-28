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
