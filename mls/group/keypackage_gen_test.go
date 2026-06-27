package group_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

func TestNewKeyPackage(t *testing.T) {
	suites := []cipher.CipherSuite{
		cipher.X25519_AES128GCM_SHA256_Ed25519,
	}
	executed := 0
	for _, csID := range suites {
		csID := csID
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			_, signer, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cred := tree.Credential{
				CredentialType: tree.CredentialTypeBasic,
				Identity:       []byte("alice@example.com"),
			}
			lifetime := tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)}

			kp, initPriv, leafPriv, err := group.NewKeyPackage(suite, cred, signer, lifetime)
			if err != nil {
				t.Fatalf("NewKeyPackage: %v", err)
			}
			if len(initPriv) == 0 {
				t.Fatal("initPriv is empty")
			}
			if len(leafPriv) == 0 {
				t.Fatal("leafPriv is empty")
			}

			// KeyPackage signature must verify.
			ok, err := kp.VerifySignature(suite)
			if err != nil {
				t.Fatalf("VerifySignature err: %v", err)
			}
			if !ok {
				t.Fatal("VerifySignature returned false")
			}

			// LeafNode signature must verify in a single-leaf tree.
			rt := tree.NewRatchetTree(suite, kp.LeafNode)
			if err := rt.VerifyLeafSignatures(nil); err != nil {
				t.Fatalf("VerifyLeafSignatures: %v", err)
			}

			// EncodeKeyPackageMessage → DecodeKeyPackageMessage round-trip.
			msg, err := group.EncodeKeyPackageMessage(kp)
			if err != nil {
				t.Fatalf("EncodeKeyPackageMessage: %v", err)
			}
			kp2, err := group.DecodeKeyPackageMessage(msg)
			if err != nil {
				t.Fatalf("DecodeKeyPackageMessage: %v", err)
			}
			msg2, err := group.EncodeKeyPackageMessage(kp2)
			if err != nil {
				t.Fatalf("EncodeKeyPackageMessage (kp2): %v", err)
			}
			if !bytes.Equal(msg, msg2) {
				t.Fatalf("round-trip mismatch: len %d vs %d", len(msg), len(msg2))
			}
		})
	}
	if executed == 0 {
		t.Fatal("no suites executed (all skipped)")
	}
}
