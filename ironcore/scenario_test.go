package ironcore_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

// TestMultiNodeVNIScenario is the IronCore integration gate (design spec
// §10.3/§10.4/§10.5, plan N5). Under the X-Wing PQ suite 0xF001:
//
//  1. N=4 nodes form a VNI group; all derive byte-equal ESP SA Key and SPI;
//     per-sender GCM nonce salts over all live leaves are pairwise distinct.
//  2. A 5th node joins (membership change → new epoch); all members rekey
//     (Key/SPI rotate) and remain converged; the new node also matches.
//  3. An application/ESP-payload message protected by one node is unprotected
//     by another, producing the original plaintext.
//  4. (§8 authz path) A SPIFFEValidator + Authorizer pre-admission check runs
//     over a joiner's x509 SVID before the Add proposal.
func TestMultiNodeVNIScenario(t *testing.T) {
	suiteID := cipher.XWING_AES256GCM_SHA256_Ed25519
	suite, ok := cipher.Lookup(suiteID)
	if !ok {
		t.Skipf("suite %#x not registered", suiteID)
	}

	const vni = uint32(0xBEEF_0001)
	const n = 4

	// ── Step 1: Form a 4-node VNI group ──────────────────────────────────────

	nodes := buildVNIGroup(t, suite, vni, n)

	// All nodes derive byte-equal Key (32 bytes), equal SPI (> 255), equal Epoch.
	saRef, err := ironcore.DeriveSAKeys(nodes[0].Group(), vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(node-0): %v", err)
	}
	if len(saRef.Key) != 32 {
		t.Fatalf("SA Key len = %d, want 32", len(saRef.Key))
	}
	if saRef.SPI <= 255 {
		t.Fatalf("SPI %d not > 255 (RFC 4303 reserved range)", saRef.SPI)
	}
	for i := 1; i < n; i++ {
		sa, err := ironcore.DeriveSAKeys(nodes[i].Group(), vni)
		if err != nil {
			t.Fatalf("DeriveSAKeys(node-%d): %v", i, err)
		}
		if !bytes.Equal(saRef.Key, sa.Key) {
			t.Fatalf("Key mismatch at node %d\n  node-0 %x\n  node-%d %x", i, saRef.Key, i, sa.Key)
		}
		if saRef.SPI != sa.SPI {
			t.Fatalf("SPI mismatch at node %d: node-0=%d node-%d=%d", i, saRef.SPI, i, sa.SPI)
		}
		if saRef.Epoch != sa.Epoch {
			t.Fatalf("Epoch mismatch at node %d: node-0=%d node-%d=%d", i, saRef.Epoch, i, sa.Epoch)
		}
	}
	t.Logf("Step 1: all %d nodes converge; SPI=%#x Epoch=%d", n, saRef.SPI, saRef.Epoch)

	// Per-sender GCM nonce salts over all live leaf indices are pairwise distinct.
	saltsSeen := map[string]uint32{}
	for i := 0; i < n; i++ {
		leafIdx := nodes[i].Group().OwnLeaf()
		salt, err := saRef.SenderSalt(leafIdx)
		if err != nil {
			t.Fatalf("SenderSalt(leaf %d): %v", leafIdx, err)
		}
		if len(salt) != 4 {
			t.Fatalf("SenderSalt len = %d, want 4", len(salt))
		}
		key := string(salt)
		if prev, seen := saltsSeen[key]; seen {
			t.Fatalf("SenderSalt not pairwise distinct: leaf %d == leaf %d", leafIdx, prev)
		}
		saltsSeen[key] = leafIdx
		// All members derive the same salt for a given sender.
		for j := 1; j < n; j++ {
			sj, err := ironcore.DeriveSAKeys(nodes[j].Group(), vni)
			if err != nil {
				t.Fatalf("DeriveSAKeys(node-%d) for salt check: %v", j, err)
			}
			saltJ, err := sj.SenderSalt(leafIdx)
			if err != nil {
				t.Fatalf("node-%d.SenderSalt(leaf %d): %v", j, leafIdx, err)
			}
			if !bytes.Equal(salt, saltJ) {
				t.Fatalf("SenderSalt(leaf %d) differs: node-0=%x node-%d=%x", leafIdx, salt, j, saltJ)
			}
		}
	}
	t.Logf("Step 1: per-sender salts pairwise distinct (%d distinct values)", len(saltsSeen))

	// ── Step 4 (optional §8 authz path): SPIFFE pre-admission check ─────────
	// Demonstrate that a SPIFFEValidator + Authorizer can gate the Add of the
	// 5th node using its x509 SVID, before the actual MLS Add proposal.

	caPriv, caPool, caDER := makeTestCA(t)
	newNodeSigner := makeSigner(t)
	newNodePub := newNodeSigner.Public().(ed25519.PublicKey)
	svid := x509SVIDCred(t, caPriv, caDER, newNodePub, "spiffe://example.org/node/4")

	sv := ironcore.SPIFFEValidator{TrustDomain: "example.org", Roots: caPool}
	admitIdentity, err := sv.Validate(svid, []byte(newNodePub))
	if err != nil {
		t.Fatalf("§8 SPIFFE pre-admission check failed: %v", err)
	}
	authorizer := ironcore.Authorizer(func(identity []byte, v uint32) bool { return v == vni })
	if !authorizer(admitIdentity, vni) {
		t.Fatal("§8 Authorizer rejected valid VNI")
	}
	t.Logf("Step 4 (§8 optional): SPIFFE identity %q authorised for VNI %#x", admitIdentity, vni)

	// ── Step 2: Add 5th node → membership change, new epoch ─────────────────

	oldKey := make([]byte, len(saRef.Key))
	copy(oldKey, saRef.Key)
	oldSPI := saRef.SPI
	oldEpoch := saRef.Epoch

	newNode := addMember(t, nodes, suite, vni)
	nodes = append(nodes, newNode)

	// Key and SPI must have rotated.
	saNew, err := ironcore.DeriveSAKeys(nodes[0].Group(), vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(node-0) after join: %v", err)
	}
	if bytes.Equal(oldKey, saNew.Key) {
		t.Fatal("Key did not rotate after membership change")
	}
	if oldSPI == saNew.SPI {
		t.Fatal("SPI did not rotate after membership change")
	}
	if saNew.Epoch <= oldEpoch {
		t.Fatalf("Epoch did not advance: was %d, now %d", oldEpoch, saNew.Epoch)
	}

	// All n+1 nodes (including the new one) agree on Key, SPI, and Epoch.
	for i := 1; i <= n; i++ {
		sa, err := ironcore.DeriveSAKeys(nodes[i].Group(), vni)
		if err != nil {
			t.Fatalf("DeriveSAKeys(node-%d) after join: %v", i, err)
		}
		if !bytes.Equal(saNew.Key, sa.Key) {
			t.Fatalf("Key mismatch at node %d after join\n  node-0 %x\n  node-%d %x", i, saNew.Key, i, sa.Key)
		}
		if saNew.SPI != sa.SPI {
			t.Fatalf("SPI mismatch at node %d after join: node-0=%d node-%d=%d", i, saNew.SPI, i, sa.SPI)
		}
		if saNew.Epoch != sa.Epoch {
			t.Fatalf("Epoch mismatch at node %d after join: node-0=%d node-%d=%d", i, saNew.Epoch, i, sa.Epoch)
		}
	}
	t.Logf("Step 2: all %d nodes converge after join; SPI=%#x Epoch=%d",
		n+1, saNew.SPI, saNew.Epoch)

	// ── Step 3: ESP-payload round-trip ────────────────────────────────────────
	// node-0 encrypts (standing in for the ESP-protected data-plane payload);
	// node-n (the newly joined 5th node) decrypts and recovers the plaintext.

	payload := []byte("ironcore-esp-integration-gate")
	appMsg, err := nodes[0].Group().ProtectApplication(payload, nil)
	if err != nil {
		t.Fatalf("ProtectApplication: %v", err)
	}
	got, ad, err := nodes[n].Group().UnprotectApplication(appMsg)
	if err != nil {
		t.Fatalf("UnprotectApplication: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("plaintext mismatch:\n  got  %q\n  want %q", got, payload)
	}
	if len(ad) != 0 {
		t.Fatalf("authenticated_data expected empty, got %q", ad)
	}
	t.Logf("Step 3: ESP-payload round-trip OK (plaintext %q)", payload)
}
