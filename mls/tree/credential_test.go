package tree

import (
	"bytes"
	"testing"
)

func TestCredentialBasicRoundTrip(t *testing.T) {
	in := Credential{CredentialType: CredentialTypeBasic, Identity: []byte("alice@example.com")}
	enc, err := in.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	var out Credential
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if out.CredentialType != CredentialTypeBasic || !bytes.Equal(out.Identity, in.Identity) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", out, in)
	}
}

func TestCredentialX509RoundTrip(t *testing.T) {
	in := Credential{
		CredentialType: CredentialTypeX509,
		Certificates:   []Certificate{{CertData: []byte("der0")}, {CertData: []byte("der1")}},
	}
	enc, err := in.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	var out Credential
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if out.CredentialType != CredentialTypeX509 || len(out.Certificates) != 2 ||
		!bytes.Equal(out.Certificates[0].CertData, []byte("der0")) ||
		!bytes.Equal(out.Certificates[1].CertData, []byte("der1")) {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestCredentialRejectsTrailingBytes(t *testing.T) {
	in := Credential{CredentialType: CredentialTypeBasic, Identity: []byte("x")}
	enc, _ := in.MarshalMLS()
	var out Credential
	if err := out.UnmarshalMLS(append(enc, 0x00)); err == nil {
		t.Fatal("expected trailing-byte error")
	}
}
