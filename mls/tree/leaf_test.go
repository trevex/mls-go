package tree

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

func sampleCapabilities() Capabilities {
	return Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMLS10},
		CipherSuites: []cipher.CipherSuite{cipher.X25519_AES128GCM_SHA256_Ed25519},
		Extensions:   []ExtensionType{},
		Proposals:    []ProposalType{},
		Credentials:  []CredentialType{CredentialTypeBasic},
	}
}

func TestLeafNodeKeyPackageRoundTrip(t *testing.T) {
	in := LeafNode{
		EncryptionKey:  []byte("enc-pub"),
		SignatureKey:   []byte("sig-pub"),
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("a")},
		Capabilities:   sampleCapabilities(),
		LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime:       &Lifetime{NotBefore: 1, NotAfter: 2},
		Extensions:     []Extension{{ExtensionType: 5, ExtensionData: []byte("x")}},
		Signature:      []byte("sig"),
	}
	enc, err := in.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	var out LeafNode
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if out.LeafNodeSource != LeafNodeSourceKeyPackage || out.Lifetime == nil ||
		out.Lifetime.NotAfter != 2 || !bytes.Equal(out.EncryptionKey, in.EncryptionKey) ||
		len(out.Extensions) != 1 || !bytes.Equal(out.Signature, in.Signature) {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestLeafNodeCommitRoundTrip(t *testing.T) {
	in := LeafNode{
		EncryptionKey:  []byte("e"),
		SignatureKey:   []byte("s"),
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("a")},
		Capabilities:   sampleCapabilities(),
		LeafNodeSource: LeafNodeSourceCommit,
		ParentHash:     []byte("ph"),
		Extensions:     []Extension{},
		Signature:      []byte("sig"),
	}
	enc, _ := in.MarshalMLS()
	var out LeafNode
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if out.LeafNodeSource != LeafNodeSourceCommit || !bytes.Equal(out.ParentHash, []byte("ph")) {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestLeafNodeSignVerify(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	pub, priv, _ := ed25519.GenerateKey(nil)
	groupID := []byte("group")
	leafIndex := uint32(3)

	leaf := LeafNode{
		EncryptionKey:  []byte("e"),
		SignatureKey:   []byte(pub),
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("a")},
		Capabilities:   sampleCapabilities(),
		LeafNodeSource: LeafNodeSourceCommit,
		ParentHash:     []byte("ph"),
		Extensions:     []Extension{},
	}
	tbs, err := leaf.tbs(groupID, leafIndex)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := suite.SignWithLabel(priv, "LeafNodeTBS", tbs)
	if err != nil {
		t.Fatal(err)
	}
	leaf.Signature = sig

	ok, err := leaf.verifySignature(suite, groupID, leafIndex)
	if err != nil || !ok {
		t.Fatalf("verify failed: ok=%v err=%v", ok, err)
	}
	// Wrong group context must fail.
	if ok, _ := leaf.verifySignature(suite, []byte("other"), leafIndex); ok {
		t.Fatal("verify should fail with wrong group_id")
	}
}
