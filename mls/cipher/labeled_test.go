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
