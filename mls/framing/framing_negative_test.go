package framing

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/syntax"
	"github.com/trevex/mls-go/mls/tree"
)

// u16be returns the big-endian encoding of v, used to build raw proposal /
// field prefixes for the negative-path skimmer tests.
func u16be(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

// wantSkimErr asserts that skimmer f rejects in without panicking.
func wantSkimErr(t *testing.T, f func(*syntax.Cursor) error, in []byte) {
	t.Helper()
	if err := f(syntax.NewCursor(in)); err == nil {
		t.Errorf("expected error, got nil for input %x", in)
	}
}

// validLeafNodeBytes builds the inline serialization of a minimal LeafNode so
// the KeyPackage skimmer tests can decode a real leaf node before truncating
// the surrounding fields.
func validLeafNodeBytes(t *testing.T) []byte {
	t.Helper()
	ln := tree.LeafNode{
		EncryptionKey:  []byte{0x01, 0x02, 0x03},
		SignatureKey:   []byte{0x04, 0x05, 0x06},
		Credential:     tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte("test")},
		Capabilities:   tree.Capabilities{},
		LeafNodeSource: tree.LeafNodeSourceKeyPackage,
		Lifetime:       &tree.Lifetime{NotBefore: 0, NotAfter: 0xffffffffffffffff},
		Extensions:     nil,
		Signature:      []byte{0xde, 0xad},
	}
	b, err := ln.MarshalMLS()
	if err != nil {
		t.Fatalf("LeafNode.MarshalMLS: %v", err)
	}
	return b
}

// TestSkimProposalRejects feeds skimProposal a truncated msg_type, a truncated
// body for every proposal type, and an unknown proposal type, asserting each is
// rejected with an error rather than a panic (framing.go:226).
func TestSkimProposalRejects(t *testing.T) {
	initKey, _ := syntax.WriteOpaqueV([]byte{0xab, 0xcd})
	kpHeader := append(append(u16be(1), u16be(1)...), initKey...) // version + cipher_suite + init_key

	cases := []struct {
		name string
		in   []byte
	}{
		{"truncated msg_type (empty)", nil},
		{"add truncated KeyPackage", u16be(proposalTypeAdd)},
		{"add KeyPackage truncated mid-fields", append(u16be(proposalTypeAdd), kpHeader...)},
		{"update truncated LeafNode", u16be(proposalTypeUpdate)},
		{"remove <4 bytes", append(u16be(proposalTypeRemove), 0x00, 0x00)},
		{"presharedkey truncated", u16be(proposalTypePreSharedKey)},
		{"reinit truncated group_id", u16be(proposalTypeReInit)},
		{"reinit truncated version", append(u16be(proposalTypeReInit), 0x00)},
		{"reinit truncated cipher_suite", append(append(u16be(proposalTypeReInit), 0x00), u16be(1)...)},
		{"reinit truncated extensions", append(append(u16be(proposalTypeReInit), 0x00), append(u16be(1), u16be(1)...)...)},
		{"externalinit truncated kem_output", u16be(proposalTypeExternalInit)},
		{"groupcontextextensions truncated", u16be(proposalTypeGroupContextExtensions)},
		{"unknown proposal type 0", u16be(0)},
		{"unknown proposal type 9999", u16be(9999)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { wantSkimErr(t, skimProposal, tc.in) })
	}
}

// TestSkimPreSharedKeyIDRejects exercises every truncation point of
// skimPreSharedKeyID (psktype, the external / resumption arms, psk_nonce) plus
// an invalid psktype (framing.go:288).
func TestSkimPreSharedKeyIDRejects(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"truncated psktype (empty)", nil},
		{"external truncated psk_id", []byte{0x01}},
		{"external truncated psk_nonce", []byte{0x01, 0x00}}, // psk_id empty, no nonce
		{"resumption truncated usage", []byte{0x02}},
		{"resumption truncated psk_group_id", []byte{0x02, 0x00}},                              // usage, no group_id
		{"resumption truncated psk_epoch", []byte{0x02, 0x00, 0x00}},                           // group_id empty, no epoch
		{"resumption truncated psk_nonce", []byte{0x02, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}}, // epoch, no nonce
		{"invalid psktype", []byte{0x09}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { wantSkimErr(t, skimPreSharedKeyID, tc.in) })
	}
}

// TestSkimCommitRejects feeds skimCommit a truncated proposals<V> vector, an
// invalid optional<UpdatePath> presence byte, and a present=1 path with a
// truncated UpdatePath (framing.go:204).
func TestSkimCommitRejects(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"truncated proposals<V>", []byte{0x01}},               // claims 1-byte body, none present
		{"invalid optional presence byte", []byte{0x00, 0x02}}, // proposals empty, presence=2
		{"present=1 truncated UpdatePath", []byte{0x00, 0x01}}, // proposals empty, present but no path
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { wantSkimErr(t, skimCommit, tc.in) })
	}
}

// TestSkimKeyPackageRejects truncates a KeyPackage at each of its fields
// (version, cipher_suite, init_key, leaf_node, extensions, signature) and
// asserts skimKeyPackage rejects each (framing.go:267).
func TestSkimKeyPackageRejects(t *testing.T) {
	ln := validLeafNodeBytes(t)
	initKey, _ := syntax.WriteOpaqueV([]byte{0xab, 0xcd})
	ext, _ := syntax.WriteOpaqueV(nil)            // extensions<V> empty
	header := append(append(u16be(1), u16be(1)...), initKey...) // version + cipher_suite + init_key

	cases := []struct {
		name string
		in   []byte
	}{
		{"truncated version", nil},
		{"version only, truncated cipher_suite", u16be(1)},
		{"truncated init_key", append(u16be(1), u16be(1)...)},
		{"truncated leaf_node", header},
		{"truncated extensions", append(append([]byte(nil), header...), ln...)},
		{"truncated signature", append(append(append([]byte(nil), header...), ln...), ext...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { wantSkimErr(t, skimKeyPackage, tc.in) })
	}
}

// TestDecodeSenderRejects feeds decodeSender a truncated encoding for each
// sender arm and an unknown sender type (framing.go:82).
func TestDecodeSenderRejects(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"truncated sender type (empty)", nil},
		{"member truncated leaf_index", []byte{0x01, 0x00}},     // SenderTypeMember, <4 bytes
		{"external truncated sender_index", []byte{0x02, 0x00}}, // SenderTypeExternal, <4 bytes
		{"unknown sender type", []byte{0x09}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeSender(syntax.NewCursor(tc.in)); err == nil {
				t.Errorf("expected error, got nil for input %x", tc.in)
			}
		})
	}
}

// TestDecodeFramedContentRejects feeds decodeFramedContent inputs that truncate
// at its leading fields and one with an invalid content type (framing.go:135).
func TestDecodeFramedContentRejects(t *testing.T) {
	// group_id empty + epoch(8) + sender(member,leaf 0) + auth_data empty + bad content_type.
	badContentType := []byte{0x00}                          // group_id<V> empty
	badContentType = append(badContentType, make([]byte, 8)...) // epoch
	badContentType = append(badContentType, 0x01, 0, 0, 0, 0)   // sender: member, leaf_index 0
	badContentType = append(badContentType, 0x00)               // authenticated_data<V> empty
	badContentType = append(badContentType, 0x09)               // invalid content_type

	cases := []struct {
		name string
		in   []byte
	}{
		{"truncated group_id (empty)", nil},
		{"truncated epoch", []byte{0x00}}, // group_id empty, no epoch
		{"invalid content_type", badContentType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeFramedContent(syntax.NewCursor(tc.in)); err == nil {
				t.Errorf("expected error, got nil for input %x", tc.in)
			}
		})
	}
}

// TestUnprotectPublicRejectsTampering builds a valid PublicMessage, then
// corrupts the membership_tag and (separately) the signature, asserting
// UnprotectPublic returns the corresponding verification error (public.go:93).
func TestUnprotectPublicRejectsTampering(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}
	gc := buildCase0GC(t)
	membershipKey := mustHex(t, c0MembershipKey)
	proposal := mustHex(t, c0ProposalHex)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fc := FramedContent{
		GroupID:     mustHex(t, c0GroupID),
		Epoch:       c0Epoch,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 1},
		ContentType: ContentTypeProposal,
		Content:     proposal,
	}
	pm, err := ProtectPublic(suite, priv, gc, membershipKey, fc, nil)
	if err != nil {
		t.Fatalf("ProtectPublic: %v", err)
	}
	// Sanity: untouched message verifies.
	if _, err := UnprotectPublic(suite, pub, gc, membershipKey, pm); err != nil {
		t.Fatalf("UnprotectPublic on valid message: %v", err)
	}

	t.Run("corrupt membership_tag", func(t *testing.T) {
		bad := pm
		bad.MembershipTag = append([]byte(nil), pm.MembershipTag...)
		bad.MembershipTag[0] ^= 0xff
		_, err := UnprotectPublic(suite, pub, gc, membershipKey, bad)
		if err == nil || !strings.Contains(err.Error(), "membership_tag") {
			t.Fatalf("expected membership_tag error, got %v", err)
		}
	})

	t.Run("corrupt signature", func(t *testing.T) {
		bad := pm
		bad.Auth.Signature = append([]byte(nil), pm.Auth.Signature...)
		bad.Auth.Signature[0] ^= 0xff
		// Recompute the membership_tag over the corrupted auth so the tag passes
		// and verification fails specifically at the signature step.
		tbm, err := authenticatedContentTBM(WireFormatPublicMessage, bad.Content, bad.Auth, gc)
		if err != nil {
			t.Fatalf("authenticatedContentTBM: %v", err)
		}
		bad.MembershipTag = suite.MAC(membershipKey, tbm)
		_, err = UnprotectPublic(suite, pub, gc, membershipKey, bad)
		if err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("expected signature error, got %v", err)
		}
	})
}

// TestUnprotectPrivateRejectsCiphertextTamper builds a valid PrivateMessage via
// ProtectPrivate, flips a ciphertext byte, and asserts UnprotectPrivate fails to
// decrypt (private.go:234).
func TestUnprotectPrivateRejectsCiphertextTamper(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite not registered")
	}
	gc := buildCase0GC(t)
	encryptionSecret := mustHex(t, c0EncryptionSecret)
	senderDataSecret := mustHex(t, c0SenderDataSecret)
	application := mustHex(t, c0ApplicationHex)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fc := FramedContent{
		GroupID:     mustHex(t, c0GroupID),
		Epoch:       c0Epoch,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 1},
		ContentType: ContentTypeApplication,
		Content:     application,
	}
	var reuseGuard [4]byte
	stProtect, err := keyschedule.NewSecretTree(suite, 2, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree (protect): %v", err)
	}
	pm, err := ProtectPrivate(suite, priv, gc, stProtect, senderDataSecret, fc, 0, reuseGuard, 0, nil)
	if err != nil {
		t.Fatalf("ProtectPrivate: %v", err)
	}

	// Flip a byte in the middle of the content ciphertext.
	bad := pm
	bad.Ciphertext = append([]byte(nil), pm.Ciphertext...)
	bad.Ciphertext[len(bad.Ciphertext)/2] ^= 0xff

	stUnprotect, err := keyschedule.NewSecretTree(suite, 2, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree (unprotect): %v", err)
	}
	pubOf := func(uint32) ([]byte, error) { return pub, nil }
	if _, err := UnprotectPrivate(suite, pubOf, gc, stUnprotect, senderDataSecret, bad); err == nil {
		t.Fatal("expected AEAD/decrypt error after ciphertext tamper, got nil")
	}
}
