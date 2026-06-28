package cipher_test

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
)

func TestXWingSuiteRoundTrip(t *testing.T) {
	cs, ok := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("X-Wing suite 0xF001 not registered")
	}
	if cs.HashLen() != 32 {
		t.Fatalf("HashLen=%d, want 32", cs.HashLen())
	}

	priv, pub, err := cs.GenerateHPKEKeyPair()
	if err != nil {
		t.Fatalf("GenerateHPKEKeyPair: %v", err)
	}
	// X-Wing public key = ML-KEM-768 enc key (1184) + X25519 (32) = 1216 bytes.
	if len(pub) != 1216 {
		t.Fatalf("X-Wing public key len=%d, want 1216", len(pub))
	}

	label := "pq label"
	context := []byte("ctx")
	plaintext := []byte("post-quantum secret")

	kemOut, ct, err := cs.EncryptWithLabel(pub, label, context, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithLabel: %v", err)
	}
	// X-Wing KEM output = ML-KEM-768 ciphertext (1088) + X25519 (32) = 1120 bytes;
	// confirms ML-KEM is actually engaged, not just X25519.
	if len(kemOut) != 1120 {
		t.Fatalf("X-Wing kem_output len=%d, want 1120", len(kemOut))
	}

	got, err := cs.DecryptWithLabel(priv, label, context, kemOut, ct)
	if err != nil {
		t.Fatalf("DecryptWithLabel: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip: got %q, want %q", got, plaintext)
	}

	// Wrong context must fail to decrypt (HPKE info is authenticated).
	if _, err := cs.DecryptWithLabel(priv, label, []byte("other"), kemOut, ct); err == nil {
		t.Fatal("X-Wing: decrypt with wrong context should fail")
	}
}
