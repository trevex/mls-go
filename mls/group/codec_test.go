package group

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// minimalLeafNode returns a minimal key_package-source LeafNode for tests.
func minimalLeafNode() tree.LeafNode {
	return tree.LeafNode{
		EncryptionKey:  []byte{0x01, 0x02, 0x03},
		SignatureKey:   []byte{0x04, 0x05, 0x06},
		Credential:     tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte("test")},
		Capabilities:   tree.Capabilities{},
		LeafNodeSource: tree.LeafNodeSourceKeyPackage,
		Lifetime:       &tree.Lifetime{NotBefore: 0, NotAfter: 0xffffffffffffffff},
		Extensions:     nil,
		Signature:      []byte{0xde, 0xad},
	}
}

// minimalKeyPackage returns a minimal KeyPackage for tests.
func minimalKeyPackage() KeyPackage {
	return KeyPackage{
		Version:     tree.ProtocolVersionMLS10,
		CipherSuite: cipher.X25519_AES128GCM_SHA256_Ed25519,
		InitKey:     []byte{0xab, 0xcd, 0xef},
		LeafNode:    minimalLeafNode(),
		Extensions:  nil,
		Signature:   []byte{0xbe, 0xef},
	}
}

func TestKeyPackageRoundTrip(t *testing.T) {
	kp := minimalKeyPackage()

	raw, err := kp.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}

	var kp2 KeyPackage
	if err := kp2.UnmarshalMLS(raw); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}

	raw2, err := kp2.MarshalMLS()
	if err != nil {
		t.Fatalf("re-MarshalMLS: %v", err)
	}

	if !bytes.Equal(raw, raw2) {
		t.Fatalf("round-trip mismatch:\n  first:  %x\n  second: %x", raw, raw2)
	}
}

func TestKeyPackageRefLength(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not found")
	}
	kp := minimalKeyPackage()
	ref, err := kp.Ref(suite)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if len(ref) != suite.HashLen() {
		t.Fatalf("Ref length %d, want %d", len(ref), suite.HashLen())
	}
}
