package group

import (
	"bytes"
	"crypto/ed25519"
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

func minimalGroupContext() keyschedule.GroupContext {
	return keyschedule.GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:                 []byte("test-group"),
		Epoch:                   0,
		TreeHash:                []byte{0x01, 0x02},
		ConfirmedTranscriptHash: []byte{0x03, 0x04},
		Extensions:              nil,
	}
}

func TestGroupInfoRoundTrip(t *testing.T) {
	gi := GroupInfo{
		GroupContext: minimalGroupContext(),
		Extensions: []tree.Extension{
			{ExtensionType: 0x0002, ExtensionData: []byte("ratchet_tree_data")},
		},
		ConfirmationTag: []byte{0xaa, 0xbb},
		Signer:          0,
		Signature:       []byte{0xde, 0xad, 0xbe, 0xef},
	}

	raw, err := gi.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}

	var gi2 GroupInfo
	if err := gi2.UnmarshalMLS(raw); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}

	raw2, err := gi2.MarshalMLS()
	if err != nil {
		t.Fatalf("re-MarshalMLS: %v", err)
	}

	if !bytes.Equal(raw, raw2) {
		t.Fatalf("round-trip mismatch:\n  first:  %x\n  second: %x", raw, raw2)
	}
}

func TestGroupInfoSignVerify(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not found")
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	gi := GroupInfo{
		GroupContext:    minimalGroupContext(),
		Extensions:      nil,
		ConfirmationTag: []byte{0x01},
		Signer:          0,
	}

	if err := gi.Sign(suite, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok2, err := gi.VerifySignature(suite, []byte(pub))
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if !ok2 {
		t.Fatal("VerifySignature returned false, want true")
	}

	// Flip a byte in the signature to check false negative.
	gi.Signature[0] ^= 0xff
	ok3, err := gi.VerifySignature(suite, []byte(pub))
	if err != nil {
		t.Fatalf("VerifySignature (flipped): %v", err)
	}
	if ok3 {
		t.Fatal("VerifySignature returned true after byte flip, want false")
	}
}

func TestGroupInfoRatchetTreeExtension(t *testing.T) {
	data := []byte("tree_bytes")
	gi := GroupInfo{
		GroupContext:    minimalGroupContext(),
		Extensions:      []tree.Extension{{ExtensionType: 0x0002, ExtensionData: data}},
		ConfirmationTag: []byte{0x01},
		Signer:          0,
		Signature:       []byte{0x02},
	}

	got := gi.RatchetTreeExtension()
	if !bytes.Equal(got, data) {
		t.Fatalf("RatchetTreeExtension = %x, want %x", got, data)
	}

	gi2 := GroupInfo{
		GroupContext:    minimalGroupContext(),
		Extensions:      nil,
		ConfirmationTag: []byte{0x01},
		Signer:          0,
		Signature:       []byte{0x02},
	}
	if gi2.RatchetTreeExtension() != nil {
		t.Fatal("expected nil for missing ratchet_tree extension")
	}
}

// ─── Welcome family tests ────────────────────────────────────────────────────

func TestPathSecretRoundTrip(t *testing.T) {
	ps := PathSecret{PathSecret: []byte{0x01, 0x02, 0x03}}
	raw, err := ps.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	var ps2 PathSecret
	if err := ps2.UnmarshalMLS(raw); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	raw2, err := ps2.MarshalMLS()
	if err != nil {
		t.Fatalf("re-MarshalMLS: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("PathSecret round-trip mismatch: %x vs %x", raw, raw2)
	}
}

func TestGroupSecretsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		gs   GroupSecrets
	}{
		{
			name: "no_path_no_psk",
			gs: GroupSecrets{
				JoinerSecret: []byte{0xaa, 0xbb},
				PathSecret:   nil,
				PSKs:         nil,
			},
		},
		{
			name: "with_path",
			gs: GroupSecrets{
				JoinerSecret: []byte{0xcc, 0xdd},
				PathSecret:   &PathSecret{PathSecret: []byte{0x11, 0x22}},
				PSKs:         nil,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.gs.MarshalMLS()
			if err != nil {
				t.Fatalf("MarshalMLS: %v", err)
			}
			var gs2 GroupSecrets
			if err := gs2.UnmarshalMLS(raw); err != nil {
				t.Fatalf("UnmarshalMLS: %v", err)
			}
			raw2, err := gs2.MarshalMLS()
			if err != nil {
				t.Fatalf("re-MarshalMLS: %v", err)
			}
			if !bytes.Equal(raw, raw2) {
				t.Fatalf("round-trip mismatch: %x vs %x", raw, raw2)
			}
		})
	}
}

func TestWelcomeRoundTrip(t *testing.T) {
	w := Welcome{
		CipherSuite: cipher.X25519_AES128GCM_SHA256_Ed25519,
		Secrets: []EncryptedGroupSecrets{
			{
				NewMember: []byte{0x01, 0x02, 0x03, 0x04},
				EncryptedGroupSecrets: tree.HPKECiphertext{
					KemOutput:  []byte{0x05, 0x06},
					Ciphertext: []byte{0x07, 0x08},
				},
			},
		},
		EncryptedGroupInfo: []byte{0x09, 0x0a, 0x0b},
	}

	raw, err := w.MarshalMLS()
	if err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	var w2 Welcome
	if err := w2.UnmarshalMLS(raw); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	raw2, err := w2.MarshalMLS()
	if err != nil {
		t.Fatalf("re-MarshalMLS: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("Welcome round-trip mismatch: %x vs %x", raw, raw2)
	}
}

func TestMLSMessageEnvelopes(t *testing.T) {
	kp := minimalKeyPackage()
	kpEnv, err := EncodeKeyPackageMessage(kp)
	if err != nil {
		t.Fatalf("EncodeKeyPackageMessage: %v", err)
	}
	kp2, err := DecodeKeyPackageMessage(kpEnv)
	if err != nil {
		t.Fatalf("DecodeKeyPackageMessage: %v", err)
	}
	kpEnv2, err := EncodeKeyPackageMessage(kp2)
	if err != nil {
		t.Fatalf("EncodeKeyPackageMessage round2: %v", err)
	}
	if !bytes.Equal(kpEnv, kpEnv2) {
		t.Fatalf("KeyPackage envelope round-trip mismatch: %x vs %x", kpEnv, kpEnv2)
	}

	gi := GroupInfo{
		GroupContext:    minimalGroupContext(),
		Extensions:      nil,
		ConfirmationTag: []byte{0x01},
		Signer:          0,
		Signature:       []byte{0x02},
	}
	giEnv, err := EncodeGroupInfoMessage(gi)
	if err != nil {
		t.Fatalf("EncodeGroupInfoMessage: %v", err)
	}
	gi2, err := DecodeGroupInfoMessage(giEnv)
	if err != nil {
		t.Fatalf("DecodeGroupInfoMessage: %v", err)
	}
	giEnv2, err := EncodeGroupInfoMessage(gi2)
	if err != nil {
		t.Fatalf("EncodeGroupInfoMessage round2: %v", err)
	}
	if !bytes.Equal(giEnv, giEnv2) {
		t.Fatalf("GroupInfo envelope round-trip mismatch: %x vs %x", giEnv, giEnv2)
	}

	w := Welcome{
		CipherSuite:        cipher.X25519_AES128GCM_SHA256_Ed25519,
		Secrets:            nil,
		EncryptedGroupInfo: []byte{0x0a, 0x0b},
	}
	wEnv, err := EncodeWelcomeMessage(w)
	if err != nil {
		t.Fatalf("EncodeWelcomeMessage: %v", err)
	}
	w2, err := DecodeWelcomeMessage(wEnv)
	if err != nil {
		t.Fatalf("DecodeWelcomeMessage: %v", err)
	}
	wEnv2, err := EncodeWelcomeMessage(w2)
	if err != nil {
		t.Fatalf("EncodeWelcomeMessage round2: %v", err)
	}
	if !bytes.Equal(wEnv, wEnv2) {
		t.Fatalf("Welcome envelope round-trip mismatch: %x vs %x", wEnv, wEnv2)
	}
}
