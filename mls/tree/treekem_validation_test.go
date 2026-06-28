package tree

import (
	"strings"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
)

// TestProcessUpdatePathRejectsDerivedKeyMismatch corrupts an UpdatePath node's
// EncryptionKey and verifies ProcessUpdatePath rejects it with the
// "derived public key mismatch" error (RFC 9420 §7.6: each derived public key
// must match the one advertised in the UpdatePath).
//
// The EncryptionKey is not used during decryption (which uses the receiver's
// private key against EncryptedPathSecret), so corrupting it does not break the
// decrypt step first — the mismatch is detected only in the key-derivation loop
// (treekem.go:271), which is exactly the security branch under test.
func TestProcessUpdatePathRejectsDerivedKeyMismatch(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	c := loadTreeKEM(t)[0]
	up := c.UpdatePaths[0] // sender 0
	var path UpdatePath
	if err := path.UnmarshalMLS(hx(t, up.UpdatePath)); err != nil {
		t.Fatal(err)
	}

	// Sender 0's filtered direct path is [1]; receiver leaf 1 decrypts at node 1
	// (foundK == 0) and derives through up.Nodes[0].
	if len(path.Nodes) == 0 {
		t.Fatalf("update path has no nodes")
	}
	fdp := func() []uint32 {
		rt, _ := ParseRatchetTree(suite, hx(t, c.RatchetTree))
		return rt.filteredDirectPath(up.Sender)
	}()
	if len(fdp) != len(path.Nodes) {
		t.Fatalf("fdp len %d != nodes len %d", len(fdp), len(path.Nodes))
	}

	// Build the GENUINE provisional group context (HPKE AAD) from the merge of the
	// untouched path, so decryption authenticates correctly. Only AFTER this do we
	// corrupt the node key, ensuring the failure is the derivation mismatch and not
	// an HPKE authentication failure.
	merged, _ := ParseRatchetTree(suite, hx(t, c.RatchetTree))
	if err := merged.Merge(up.Sender, &path); err != nil {
		t.Fatal(err)
	}
	mergedHash, _ := merged.RootTreeHash()
	gc := provisionalGroupContext(t, suite, c, mergedHash)

	// Corrupt the EncryptionKey of a node the receiver derives through (foundK..end).
	if len(path.Nodes[0].EncryptionKey) == 0 {
		t.Fatalf("node 0 has empty EncryptionKey")
	}
	path.Nodes[0].EncryptionKey[0] ^= 0xFF

	// Receiver = leaf 1, holding its leaf key plus the path secret at node 1.
	lp := c.LeavesPrivate[1]
	if lp.Index != 1 {
		t.Fatalf("expected leaves_private[1].index == 1, got %d", lp.Index)
	}
	priv := NewTreeKEMPrivate(lp.Index, hx(t, lp.EncryptionPriv))
	for _, ps := range lp.PathSecrets {
		if err := priv.AddPathSecret(suite, ps.Node, hx(t, ps.PathSecret)); err != nil {
			t.Fatal(err)
		}
	}
	rt, _ := ParseRatchetTree(suite, hx(t, c.RatchetTree))
	_, _, err := rt.ProcessUpdatePath(up.Sender, &path, priv, gc, nil)
	if err == nil {
		t.Fatal("ProcessUpdatePath accepted a corrupted EncryptionKey; want mismatch error")
	}
	if !strings.Contains(err.Error(), "derived public key mismatch") {
		t.Fatalf("error = %q, want substring %q", err.Error(), "derived public key mismatch")
	}
}
