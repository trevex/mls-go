package group

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
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

func proposalRoundTrip(t *testing.T, p Proposal) {
	t.Helper()
	raw, err := p.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	var p2 Proposal
	if err := p2.UnmarshalMLS(raw); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	raw2, err := p2.MarshalMLS()
	if err != nil {
		t.Fatalf("re-MarshalMLS: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("round-trip mismatch:\n  first:  %x\n  second: %x", raw, raw2)
	}
}

func TestProposalAddRoundTrip(t *testing.T) {
	kp := minimalKeyPackage()
	proposalRoundTrip(t, Proposal{Type: ProposalTypeAdd, Add: &Add{KeyPackage: kp}})
}

func TestProposalUpdateRoundTrip(t *testing.T) {
	ln := minimalLeafNode()
	proposalRoundTrip(t, Proposal{Type: ProposalTypeUpdate, Update: &Update{LeafNode: ln}})
}

func TestProposalRemoveRoundTrip(t *testing.T) {
	proposalRoundTrip(t, Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 42}})
}

func TestProposalPreSharedKeyRoundTrip(t *testing.T) {
	psk := keyschedule.PreSharedKeyID{
		PSKType:  keyschedule.PSKTypeExternal,
		PSKID:    []byte("mypsk"),
		PSKNonce: []byte("nonce"),
	}
	proposalRoundTrip(t, Proposal{Type: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{PSK: psk}})
}

func TestProposalReInitRoundTrip(t *testing.T) {
	proposalRoundTrip(t, Proposal{
		Type: ProposalTypeReInit,
		ReInit: &ReInit{
			GroupID:     []byte("gid"),
			Version:     tree.ProtocolVersionMLS10,
			CipherSuite: cipher.X25519_AES128GCM_SHA256_Ed25519,
			Extensions:  nil,
		},
	})
}

func TestProposalExternalInitRoundTrip(t *testing.T) {
	proposalRoundTrip(t, Proposal{Type: ProposalTypeExternalInit, ExternalInit: &ExternalInit{KemOutput: []byte{0x01, 0x02}}})
}

func TestProposalGroupContextExtensionsRoundTrip(t *testing.T) {
	proposalRoundTrip(t, Proposal{
		Type:                   ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensions{Extensions: nil},
	})
}

func TestProposalRefLength(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not found")
	}
	p := Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 2}}
	ref, err := p.Ref(suite)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if len(ref) != suite.HashLen() {
		t.Fatalf("Ref length %d, want %d", len(ref), suite.HashLen())
	}
}

func proposalOrRefRoundTrip(t *testing.T, por ProposalOrRef) {
	t.Helper()
	raw, err := por.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	var por2 ProposalOrRef
	if err := por2.UnmarshalMLS(raw); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	raw2, err := por2.MarshalMLS()
	if err != nil {
		t.Fatalf("re-MarshalMLS: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("round-trip mismatch:\n  first:  %x\n  second: %x", raw, raw2)
	}
}

func TestProposalOrRefByValue(t *testing.T) {
	p := Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 7}}
	proposalOrRefRoundTrip(t, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: &p})
}

func TestProposalOrRefByReference(t *testing.T) {
	ref := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	proposalOrRefRoundTrip(t, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: ref})
}

func commitRoundTrip(t *testing.T, cm Commit) {
	t.Helper()
	raw, err := cm.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	var cm2 Commit
	if err := cm2.UnmarshalMLS(raw); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	raw2, err := cm2.MarshalMLS()
	if err != nil {
		t.Fatalf("re-MarshalMLS: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("round-trip mismatch:\n  first:  %x\n  second: %x", raw, raw2)
	}
}

func TestCommitEmptyNoPath(t *testing.T) {
	commitRoundTrip(t, Commit{})
}

func TestCommitMixedProposalsNoPath(t *testing.T) {
	ref := []byte{0x01, 0x02, 0x03, 0x04}
	removeProposal := Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 3}}
	cm := Commit{
		Proposals: []ProposalOrRef{
			{Type: ProposalOrRefTypeReference, Reference: ref},
			{Type: ProposalOrRefTypeProposal, Proposal: &removeProposal},
		},
		Path: nil,
	}
	commitRoundTrip(t, cm)
}

func TestCommitWithPath(t *testing.T) {
	ln := minimalLeafNode()
	up := tree.UpdatePath{
		LeafNode: ln,
		Nodes:    nil,
	}
	cm := Commit{
		Proposals: nil,
		Path:      &up,
	}
	commitRoundTrip(t, cm)
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
