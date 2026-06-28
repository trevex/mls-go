package cipher_test

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
)

func TestEncryptDecryptWithLabelRoundTrip(t *testing.T) {
	for _, id := range []cipher.CipherSuite{
		cipher.X25519_AES128GCM_SHA256_Ed25519,
		cipher.P256_AES128GCM_SHA256_P256,
	} {
		cs, ok := cipher.Lookup(id)
		if !ok {
			t.Fatalf("suite %#x not registered", id)
		}
		priv, pub, err := cs.GenerateHPKEKeyPair()
		if err != nil {
			t.Fatalf("suite %#x GenerateHPKEKeyPair: %v", id, err)
		}
		label := "test label"
		context := []byte("some context")
		plaintext := []byte("attack at dawn")

		kemOut, ct, err := cs.EncryptWithLabel(pub, label, context, plaintext)
		if err != nil {
			t.Fatalf("suite %#x EncryptWithLabel: %v", id, err)
		}
		got, err := cs.DecryptWithLabel(priv, label, context, kemOut, ct)
		if err != nil {
			t.Fatalf("suite %#x DecryptWithLabel: %v", id, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("suite %#x round-trip: got %q, want %q", id, got, plaintext)
		}
		if _, err := cs.DecryptWithLabel(priv, label, []byte("other"), kemOut, ct); err == nil {
			t.Fatalf("suite %#x: decrypt with wrong context should fail", id)
		}
	}
}
