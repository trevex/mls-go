package cipher

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	for _, id := range []CipherSuite{X25519_AES128GCM_SHA256_Ed25519, P256_AES128GCM_SHA256_P256} {
		s, ok := Lookup(id)
		if !ok {
			t.Fatalf("suite %#x not registered", id)
		}
		key := make([]byte, s.AEADKeySize())
		nonce := make([]byte, s.AEADNonceSize())
		for i := range key {
			key[i] = byte(i)
		}
		for i := range nonce {
			nonce[i] = byte(0x40 + i)
		}
		aad := []byte("aad")
		pt := []byte("the quick brown fox")
		ct, err := s.Seal(key, nonce, aad, pt)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Open(key, nonce, aad, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round-trip mismatch: %x != %x", got, pt)
		}
		// Tamper detection: a flipped AAD must fail to open.
		if _, err := s.Open(key, nonce, []byte("bad"), ct); err == nil {
			t.Fatal("expected open failure with wrong aad")
		}
	}
}
