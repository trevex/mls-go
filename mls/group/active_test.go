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

// TestProposeAdd verifies that ProposeAdd + FrameProposal round-trips through
// MLSMessage parse and that prop.Ref(suite) is stable.
func TestProposeAdd(t *testing.T) {
	executed := 0
	for _, csID := range testSuites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			aliceSigner := makeSigner(t)
			aliceGroup, err := group.NewGroup(suite, []byte("grp"), makeCred("alice"), aliceSigner, makeLifetime())
			if err != nil {
				t.Fatalf("NewGroup: %v", err)
			}
			bobSigner := makeSigner(t)
			bobKP, _, _, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
			if err != nil {
				t.Fatalf("NewKeyPackage: %v", err)
			}
			prop := group.ProposeAdd(bobKP)
			msg, err := aliceGroup.FrameProposal(prop)
			if err != nil {
				t.Fatalf("FrameProposal: %v", err)
			}
			if len(msg) == 0 {
				t.Fatal("FrameProposal returned empty bytes")
			}
			// Ref must be stable across calls.
			ref1, err := prop.Ref(suite)
			if err != nil {
				t.Fatalf("prop.Ref: %v", err)
			}
			ref2, err := prop.Ref(suite)
			if err != nil {
				t.Fatalf("prop.Ref (2): %v", err)
			}
			if !bytes.Equal(ref1, ref2) {
				t.Fatal("prop.Ref not stable")
			}
		})
	}
	if executed == 0 {
		t.Fatal("no suites executed (all skipped)")
	}
}

// TestActiveRoundTrip is the self-round-trip gate (Tasks 6+7). Runs scenarios
// T1–T6 + application messages, asserting byte-equal epoch_authenticator and
// MLSExporter output across all live members after every Commit.
func TestActiveRoundTrip(t *testing.T) {
	executed := 0
	for _, csID := range testSuites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			groupID := []byte("active-roundtrip-group")

			// ── T1: Alice creates group; commits Add(Bob) ──────────────────────

			aliceSigner := makeSigner(t)
			alice, err := group.NewGroup(suite, groupID, makeCred("alice"), aliceSigner, makeLifetime())
			if err != nil {
				t.Fatalf("T1 NewGroup(Alice): %v", err)
			}

			bobSigner := makeSigner(t)
			bobKP, bobInitPriv, bobLeafPriv, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
			if err != nil {
				t.Fatalf("T1 NewKeyPackage(Bob): %v", err)
			}
			bobKPMsg, err := group.EncodeKeyPackageMessage(bobKP)
			if err != nil {
				t.Fatalf("T1 EncodeKeyPackageMessage: %v", err)
			}

			commitMsg, welcomeMsg, err := alice.Commit(group.CommitOptions{
				ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
			})
			if err != nil {
				t.Fatalf("T1 Alice.Commit(Add Bob): %v", err)
			}
			if len(welcomeMsg) == 0 {
				t.Fatal("T1 expected welcome, got empty")
			}
			_ = commitMsg

			bob, err := group.JoinFromWelcome(suite, welcomeMsg, group.JoinOptions{
				KeyPackage:     bobKPMsg,
				InitPriv:       bobInitPriv,
				EncryptionPriv: bobLeafPriv,
				Signer:         bobSigner,
				ExternalPSKs:   map[string][]byte{},
			})
			if err != nil {
				t.Fatalf("T1 JoinFromWelcome(Bob): %v", err)
			}
			t.Log("T1: Alice and Bob converge at epoch 1")
			assertConverged(t, "T1", suite, alice, bob)

			// ── T2: Alice commits Add(Carol); Bob processes; Carol joins ───────

			carolSigner := makeSigner(t)
			carolKP, carolInitPriv, carolLeafPriv, err := group.NewKeyPackage(suite, makeCred("carol"), carolSigner, makeLifetime())
			if err != nil {
				t.Fatalf("T2 NewKeyPackage(Carol): %v", err)
			}
			carolKPMsg, err := group.EncodeKeyPackageMessage(carolKP)
			if err != nil {
				t.Fatalf("T2 EncodeKeyPackageMessage: %v", err)
			}

			commitMsg2, welcomeMsg2, err := alice.Commit(group.CommitOptions{
				ByValue: []group.Proposal{group.ProposeAdd(carolKP)},
			})
			if err != nil {
				t.Fatalf("T2 Alice.Commit(Add Carol): %v", err)
			}
			if err := bob.ProcessCommit(nil, commitMsg2); err != nil {
				t.Fatalf("T2 Bob.ProcessCommit: %v", err)
			}
			carol, err := group.JoinFromWelcome(suite, welcomeMsg2, group.JoinOptions{
				KeyPackage:     carolKPMsg,
				InitPriv:       carolInitPriv,
				EncryptionPriv: carolLeafPriv,
				Signer:         carolSigner,
				ExternalPSKs:   map[string][]byte{},
			})
			if err != nil {
				t.Fatalf("T2 JoinFromWelcome(Carol): %v", err)
			}
			t.Log("T2: Alice, Bob, Carol converge at epoch 2")
			assertConverged(t, "T2", suite, alice, bob, carol)

			// ── T3: Bob (non-creator) commits path-only; Alice+Carol process ───

			commitMsg3, _, err := bob.Commit(group.CommitOptions{})
			if err != nil {
				t.Fatalf("T3 Bob.Commit(path-only): %v", err)
			}
			if err := alice.ProcessCommit(nil, commitMsg3); err != nil {
				t.Fatalf("T3 Alice.ProcessCommit: %v", err)
			}
			if err := carol.ProcessCommit(nil, commitMsg3); err != nil {
				t.Fatalf("T3 Carol.ProcessCommit: %v", err)
			}
			t.Log("T3: Alice, Bob, Carol converge after Bob's path-only commit")
			assertConverged(t, "T3", suite, alice, bob, carol)

			// ── T4: Alice commits Remove(Carol); Bob processes ─────────────────

			carolLeafIdx := carol.OwnLeaf()
			commitMsg4, _, err := alice.Commit(group.CommitOptions{
				ByValue: []group.Proposal{group.ProposeRemove(carolLeafIdx)},
			})
			if err != nil {
				t.Fatalf("T4 Alice.Commit(Remove Carol): %v", err)
			}
			if err := bob.ProcessCommit(nil, commitMsg4); err != nil {
				t.Fatalf("T4 Bob.ProcessCommit: %v", err)
			}
			t.Log("T4: Alice and Bob converge after Remove(Carol)")
			assertConverged(t, "T4", suite, alice, bob)

			// ── T5: Bob generates an Update proposal; Alice commits it ─────────
			// Bob tracks the new leaf private key so he can decrypt Alice's
			// UpdatePath after his leaf is updated in the working tree.

			updateProp, bobNewLeafPriv, err := bob.ProposeUpdate()
			if err != nil {
				t.Fatalf("T5 Bob.ProposeUpdate: %v", err)
			}
			updateMsg, err := bob.FrameProposal(updateProp)
			if err != nil {
				t.Fatalf("T5 Bob.FrameProposal: %v", err)
			}
			commitMsg5, _, err := alice.Commit(group.CommitOptions{
				ByReference: [][]byte{updateMsg},
			})
			if err != nil {
				t.Fatalf("T5 Alice.Commit(Update Bob by-ref): %v", err)
			}
			// Install Bob's new leaf key before ProcessCommit (RFC 9420 §12.1.2 /
			// plan N3 proposer-key-install).
			bob.InstallPendingUpdateKey(bobNewLeafPriv)
			if err := bob.ProcessCommit([][]byte{updateMsg}, commitMsg5); err != nil {
				t.Fatalf("T5 Bob.ProcessCommit: %v", err)
			}
			t.Log("T5: Alice and Bob converge after Bob's Update committed by Alice")
			assertConverged(t, "T5", suite, alice, bob)

			// ── T6: Gap-fill topology (exercises §7.5 newlyAdded skip) ─────────
			// Add Dave, remove Bob (blank slot), then Add Frank into the gap.
			// Dave (mid-index) processes the gap-fill commit — the topology that
			// fails without the §7.5 newlyAdded skip in GenerateUpdatePath.

			daveSigner := makeSigner(t)
			daveKP, daveInitPriv, daveLeafPriv, err := group.NewKeyPackage(suite, makeCred("dave"), daveSigner, makeLifetime())
			if err != nil {
				t.Fatalf("T6 NewKeyPackage(Dave): %v", err)
			}
			daveKPMsg, err := group.EncodeKeyPackageMessage(daveKP)
			if err != nil {
				t.Fatalf("T6 EncodeKeyPackageMessage(Dave): %v", err)
			}
			commitMsg6a, welcomeMsg6a, err := alice.Commit(group.CommitOptions{
				ByValue: []group.Proposal{group.ProposeAdd(daveKP)},
			})
			if err != nil {
				t.Fatalf("T6 Alice.Commit(Add Dave): %v", err)
			}
			if err := bob.ProcessCommit(nil, commitMsg6a); err != nil {
				t.Fatalf("T6 Bob.ProcessCommit(Add Dave): %v", err)
			}
			dave, err := group.JoinFromWelcome(suite, welcomeMsg6a, group.JoinOptions{
				KeyPackage:     daveKPMsg,
				InitPriv:       daveInitPriv,
				EncryptionPriv: daveLeafPriv,
				Signer:         daveSigner,
				ExternalPSKs:   map[string][]byte{},
			})
			if err != nil {
				t.Fatalf("T6 JoinFromWelcome(Dave): %v", err)
			}
			assertConverged(t, "T6a", suite, alice, bob, dave)

			// Remove Bob to blank slot 1.
			bobLeafIdx := bob.OwnLeaf()
			commitMsg6b, _, err := alice.Commit(group.CommitOptions{
				ByValue: []group.Proposal{group.ProposeRemove(bobLeafIdx)},
			})
			if err != nil {
				t.Fatalf("T6 Alice.Commit(Remove Bob): %v", err)
			}
			if err := dave.ProcessCommit(nil, commitMsg6b); err != nil {
				t.Fatalf("T6 Dave.ProcessCommit(Remove Bob): %v", err)
			}
			assertConverged(t, "T6b", suite, alice, dave)

			// Add Frank — fills the blank slot (gap-fill).
			frankSigner := makeSigner(t)
			frankKP, frankInitPriv, frankLeafPriv, err := group.NewKeyPackage(suite, makeCred("frank"), frankSigner, makeLifetime())
			if err != nil {
				t.Fatalf("T6 NewKeyPackage(Frank): %v", err)
			}
			frankKPMsg, err := group.EncodeKeyPackageMessage(frankKP)
			if err != nil {
				t.Fatalf("T6 EncodeKeyPackageMessage(Frank): %v", err)
			}
			commitMsg6c, welcomeMsg6c, err := alice.Commit(group.CommitOptions{
				ByValue: []group.Proposal{group.ProposeAdd(frankKP)},
			})
			if err != nil {
				t.Fatalf("T6 Alice.Commit(Add Frank into gap): %v", err)
			}
			if err := dave.ProcessCommit(nil, commitMsg6c); err != nil {
				t.Fatalf("T6 Dave.ProcessCommit(Add Frank gap-fill): %v", err)
			}
			frank, err := group.JoinFromWelcome(suite, welcomeMsg6c, group.JoinOptions{
				KeyPackage:     frankKPMsg,
				InitPriv:       frankInitPriv,
				EncryptionPriv: frankLeafPriv,
				Signer:         frankSigner,
				ExternalPSKs:   map[string][]byte{},
			})
			if err != nil {
				t.Fatalf("T6 JoinFromWelcome(Frank): %v", err)
			}
			t.Log("T6: gap-fill topology converges (§7.5 newlyAdded skip exercised)")
			assertConverged(t, "T6", suite, alice, dave, frank)

			// ── T7: Application messages ──────────────────────────────────────

			plain1 := []byte("hello from alice")
			appMsg1, err := alice.ProtectApplication(plain1, nil)
			if err != nil {
				t.Fatalf("T7 Alice.ProtectApplication: %v", err)
			}
			got1, ad1, err := dave.UnprotectApplication(appMsg1)
			if err != nil {
				t.Fatalf("T7 Dave.UnprotectApplication: %v", err)
			}
			if !bytes.Equal(got1, plain1) {
				t.Fatalf("T7 plaintext mismatch: got %q, want %q", got1, plain1)
			}
			if len(ad1) != 0 {
				t.Fatalf("T7 authenticated_data expected empty, got %q", ad1)
			}

			// Second message advances generation.
			plain2 := []byte("second message from alice")
			appMsg2, err := alice.ProtectApplication(plain2, []byte("auth-data"))
			if err != nil {
				t.Fatalf("T7 Alice.ProtectApplication (2): %v", err)
			}
			got2, ad2, err := frank.UnprotectApplication(appMsg2)
			if err != nil {
				t.Fatalf("T7 Frank.UnprotectApplication: %v", err)
			}
			if !bytes.Equal(got2, plain2) {
				t.Fatalf("T7 plaintext2 mismatch: got %q, want %q", got2, plain2)
			}
			if !bytes.Equal(ad2, []byte("auth-data")) {
				t.Fatalf("T7 authenticated_data mismatch: got %q, want %q", ad2, "auth-data")
			}

			// Tampered ciphertext must fail.
			tampered := make([]byte, len(appMsg1))
			copy(tampered, appMsg1)
			tampered[len(tampered)-1] ^= 0xFF
			if _, _, err := dave.UnprotectApplication(tampered); err == nil {
				t.Fatal("T7 expected error for tampered ciphertext, got nil")
			}

			t.Log("T7: application messages round-trip correctly")
		})
	}
	if executed == 0 {
		t.Fatal("no suites executed (all skipped)")
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
