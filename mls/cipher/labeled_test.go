package cipher

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
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

func TestSignaturePublicKey(t *testing.T) {
	msg := []byte("test-payload")
	tests := []struct {
		name string
		id   CipherSuite
	}{
		{"Ed25519", X25519_AES128GCM_SHA256_Ed25519},
		{"ECDSA-P256", P256_AES128GCM_SHA256_P256},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			suite, ok := Lookup(tt.id)
			if !ok {
				t.Skipf("suite %#x not registered", tt.id)
			}
			var signer crypto.Signer
			switch tt.id {
			case X25519_AES128GCM_SHA256_Ed25519:
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer = priv
			case P256_AES128GCM_SHA256_P256:
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer = priv
			}
			pub, err := suite.SignaturePublicKey(signer)
			if err != nil {
				t.Fatalf("SignaturePublicKey: %v", err)
			}
			if len(pub) == 0 {
				t.Fatal("SignaturePublicKey returned empty bytes")
			}
			sig, err := suite.SignWithLabel(signer, "TestLabel", msg)
			if err != nil {
				t.Fatalf("SignWithLabel: %v", err)
			}
			if !suite.VerifyWithLabel(pub, "TestLabel", msg, sig) {
				t.Fatal("VerifyWithLabel rejected a valid signature after SignaturePublicKey")
			}
		})
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
	if cs.VerifyWithLabel(pub, "OtherLabel", content, sig) {
		t.Fatal("VerifyWithLabel accepted signature under wrong label")
	}
}
