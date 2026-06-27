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

// testSuites are the cipher suites exercised in active tests.
var testSuites = []cipher.CipherSuite{
	cipher.X25519_AES128GCM_SHA256_Ed25519,
}

// makeSigner generates a fresh Ed25519 signer.
func makeSigner(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// makeCred builds a basic credential.
func makeCred(identity string) tree.Credential {
	return tree.Credential{
		CredentialType: tree.CredentialTypeBasic,
		Identity:       []byte(identity),
	}
}

// makeLifetime returns a max-span Lifetime suitable for tests.
func makeLifetime() tree.Lifetime {
	return tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)}
}

// assertConverged asserts byte-equal epoch_authenticator and MLSExporter output.
func assertConverged(t *testing.T, tag string, suite cipher.Suite, members ...*group.Group) {
	t.Helper()
	refEA := members[0].EpochAuthenticator()
	refExp, err := members[0].Exporter("zz", []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("%s: Exporter[0]: %v", tag, err)
	}
	for i, m := range members[1:] {
		ea := m.EpochAuthenticator()
		if !bytes.Equal(ea, refEA) {
			t.Fatalf("%s: member[%d] epoch_authenticator mismatch\n  got  %x\n  want %x",
				tag, i+1, ea, refEA)
		}
		exp, err := m.Exporter("zz", []byte("ctx"), 32)
		if err != nil {
			t.Fatalf("%s: Exporter[%d]: %v", tag, i+1, err)
		}
		if !bytes.Equal(exp, refExp) {
			t.Fatalf("%s: member[%d] Exporter mismatch\n  got  %x\n  want %x",
				tag, i+1, exp, refExp)
		}
	}
}

// TestNewGroup verifies that NewGroup creates a single-member group at epoch 0.
func TestNewGroup(t *testing.T) {
	executed := 0
	for _, csID := range testSuites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			signer := makeSigner(t)
			g, err := group.NewGroup(suite, []byte("test-group-001"), makeCred("alice@example.com"), signer, makeLifetime())
			if err != nil {
				t.Fatalf("NewGroup: %v", err)
			}
			if g.Epoch() != 0 {
				t.Fatalf("expected epoch 0, got %d", g.Epoch())
			}
			ea := g.EpochAuthenticator()
			if len(ea) != suite.HashLen() {
				t.Fatalf("epoch_authenticator len %d, want %d", len(ea), suite.HashLen())
			}
			out, err := g.Exporter("test-label", []byte("test-ctx"), 32)
			if err != nil {
				t.Fatalf("Exporter: %v", err)
			}
			if len(out) != 32 {
				t.Fatalf("Exporter output len %d, want 32", len(out))
			}
		})
	}
	if executed == 0 {
		t.Fatal("no suites executed (all skipped)")
	}
}
