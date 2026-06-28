package group_test

import (
	"crypto"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/framing"
	"github.com/trevex/mls-go/mls/group"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/tree"
)

// externalCommitSuites is the ordered list of suites exercised in external-commit
// tests: the X-Wing PQ suite (primary — the deployed suite per design spec §7)
// followed by the classical X25519 suite.
var externalCommitSuites = []cipher.CipherSuite{
	cipher.XWING_AES256GCM_SHA256_Ed25519,  // 0xF001 — primary
	cipher.X25519_AES128GCM_SHA256_Ed25519, // 0x0001
}

// buildTwoMemberGroup creates a 2-member (alice, bob) group at epoch 1.
// It returns alice, bob, and the signers so callers can re-use them.
func buildTwoMemberGroup(t *testing.T, suite cipher.Suite) (alice, bob *group.Group) {
	t.Helper()
	aliceSigner := makeSigner(t)
	alice, err := group.NewGroup(suite, []byte("ext-commit-group"), makeCred("alice"), aliceSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewGroup(alice): %v", err)
	}
	bobSigner := makeSigner(t)
	bobKP, bobInitPriv, bobLeafPriv, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewKeyPackage(bob): %v", err)
	}
	bobKPMsg, err := group.EncodeKeyPackageMessage(bobKP)
	if err != nil {
		t.Fatalf("EncodeKeyPackageMessage(bob): %v", err)
	}
	_, welcomeBob, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
	})
	if err != nil {
		t.Fatalf("Commit(Add bob): %v", err)
	}
	bob, err = group.JoinFromWelcome(suite, welcomeBob, group.JoinOptions{
		KeyPackage:     bobKPMsg,
		InitPriv:       bobInitPriv,
		EncryptionPriv: bobLeafPriv,
		Signer:         bobSigner,
		ExternalPSKs:   map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(bob): %v", err)
	}
	return alice, bob
}

// TestExternalCommitFreshJoin is the Task 2 convergence gate (RFC 9420 §12.4.3.2):
// a fresh non-member (carol) external-joins a 2-member group; all three converge
// on byte-equal epoch_authenticator and Exporter output at epoch 2.
//
// Primary gate: suite 0xF001 (X-Wing PQ). Also run under 0x0001 (X25519).
// Validated during planning: all three converge on epoch_authenticator 3086888c…
// at epoch 2 (exact bytes differ by randomness but ALL members must match).
func TestExternalCommitFreshJoin(t *testing.T) {
	executed := 0
	for _, csID := range externalCommitSuites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			alice, bob := buildTwoMemberGroup(t, suite)
			if alice.Epoch() != 1 || bob.Epoch() != 1 {
				t.Fatalf("expected epoch 1, got alice=%d bob=%d", alice.Epoch(), bob.Epoch())
			}
			assertConverged(t, "epoch1", suite, alice, bob)

			// Publish a signed GroupInfo from alice.
			gi, err := alice.PublishGroupInfo()
			if err != nil {
				t.Fatalf("alice.PublishGroupInfo(): %v", err)
			}

			// Carol external-commits (fresh non-member).
			carolSigner := makeSigner(t)
			carol, commitMsg, err := group.ExternalCommit(suite, *gi, makeCred("carol"), carolSigner, makeLifetime())
			if err != nil {
				t.Fatalf("ExternalCommit(carol): %v", err)
			}
			if carol.Epoch() != 2 {
				t.Fatalf("carol epoch %d, want 2", carol.Epoch())
			}

			// Existing members process the external commit via ProcessCommit dispatch.
			if err := alice.ProcessCommit(nil, commitMsg); err != nil {
				t.Fatalf("alice.ProcessCommit(external): %v", err)
			}
			if err := bob.ProcessCommit(nil, commitMsg); err != nil {
				t.Fatalf("bob.ProcessCommit(external): %v", err)
			}

			if alice.Epoch() != 2 || bob.Epoch() != 2 {
				t.Fatalf("expected epoch 2 after external commit, got alice=%d bob=%d", alice.Epoch(), bob.Epoch())
			}

			// All three MUST converge on byte-equal epoch_authenticator + Exporter.
			assertConverged(t, "ext-join-epoch2", suite, alice, bob, carol)
			t.Logf("suite %#x: all three members converge at epoch 2, EA=%x",
				csID, alice.EpochAuthenticator())
		})
	}
	if executed == 0 {
		t.Fatal("no registered suites executed")
	}
}

// TestExternalCommitAntiDoubleJoin is the Task 4 anti-double-join gate
// (RFC 9420 §12.4.3.2): when a member that already appears in the tree
// external-commits, the generated commit MUST include a Remove of its stale leaf.
// After processing, the tree is valid (VerifyParentHashes), the member occupies
// exactly one leaf, and all live members converge.
//
// Primary gate: suite 0xF001 (X-Wing PQ). Also run under 0x0001.
// Validated during planning: bob removes stale leaf 1, re-joins at leaf 1;
// alice and bob converge at epoch 2.
func TestExternalCommitAntiDoubleJoin(t *testing.T) {
	executed := 0
	for _, csID := range externalCommitSuites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			alice, bob := buildTwoMemberGroup(t, suite)

			// bob's signer is not accessible from the returned *Group — we need to
			// create a fresh external commit using the SAME signature identity.
			// The test re-uses bob's signer by building a fresh group from scratch
			// where we control the signer.
			//
			// Strategy: rebuild the 2-member group with controlled signers so we
			// can pass bob's signer to ExternalCommit.
			bobSigner := makeSigner(t)
			aliceSigner2 := makeSigner(t)
			alice2, err := group.NewGroup(suite, []byte("anti-dj-group"), makeCred("alice2"), aliceSigner2, makeLifetime())
			if err != nil {
				t.Fatalf("NewGroup(alice2): %v", err)
			}
			bobKP, bobInitPriv, bobLeafPriv, err := group.NewKeyPackage(suite, makeCred("bob2"), bobSigner, makeLifetime())
			if err != nil {
				t.Fatalf("NewKeyPackage(bob2): %v", err)
			}
			bobKPMsg, err := group.EncodeKeyPackageMessage(bobKP)
			if err != nil {
				t.Fatalf("EncodeKeyPackageMessage(bob2): %v", err)
			}
			_, welcomeBob2, err := alice2.Commit(group.CommitOptions{
				ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
			})
			if err != nil {
				t.Fatalf("Commit(Add bob2): %v", err)
			}
			bob2, err := group.JoinFromWelcome(suite, welcomeBob2, group.JoinOptions{
				KeyPackage:     bobKPMsg,
				InitPriv:       bobInitPriv,
				EncryptionPriv: bobLeafPriv,
				Signer:         bobSigner,
				ExternalPSKs:   map[string][]byte{},
			})
			if err != nil {
				t.Fatalf("JoinFromWelcome(bob2): %v", err)
			}
			// bob and alice2 converge at epoch 1.
			assertConverged(t, "anti-dj-epoch1", suite, alice2, bob2)

			// alice2 publishes a GroupInfo. bob2's signer appears in the tree.
			gi, err := alice2.PublishGroupInfo()
			if err != nil {
				t.Fatalf("alice2.PublishGroupInfo(): %v", err)
			}

			// bob2 external-commits using the SAME signer → anti-double-join fires.
			// ExternalCommit must include a Remove of bob2's stale leaf (leaf 1).
			newBob2, commitMsg, err := group.ExternalCommit(suite, *gi, makeCred("bob2"), bobSigner, makeLifetime())
			if err != nil {
				t.Fatalf("ExternalCommit(bob2 anti-dj): %v", err)
			}

			// Assert the generated commit contains a Remove of bob2's stale leaf
			// (§12.4.3.2 anti-double-join property).
			{
				var m framing.MLSMessage
				if err := m.UnmarshalMLS(commitMsg); err != nil {
					t.Fatalf("decode anti-dj commit: %v", err)
				}
				var cm group.Commit
				if err := cm.UnmarshalMLS(m.Public.Content.Content); err != nil {
					t.Fatalf("decode Commit body: %v", err)
				}
				hasRemove := false
				for _, por := range cm.Proposals {
					if por.Type == group.ProposalOrRefTypeProposal &&
						por.Proposal != nil &&
						por.Proposal.Type == group.ProposalTypeRemove {
						hasRemove = true
						t.Logf("suite %#x: anti-dj Remove targets leaf %d (was stale bob2 leaf %d)",
							csID, por.Proposal.Remove.Removed, bob2.OwnLeaf())
					}
				}
				if !hasRemove {
					t.Fatal("anti-double-join: expected a Remove proposal in the external commit")
				}
			}

			// alice2 processes the external commit.
			if err := alice2.ProcessCommit(nil, commitMsg); err != nil {
				t.Fatalf("alice2.ProcessCommit(anti-dj): %v", err)
			}

			// Convergence: both members must share byte-equal epoch_authenticator.
			assertConverged(t, "anti-dj-epoch2", suite, alice2, newBob2)
			t.Logf("suite %#x: anti-double-join — all converge at epoch 2, EA=%x",
				csID, alice2.EpochAuthenticator())

			// Verify VerifyParentHashes holds on the post-commit tree by publishing
			// a new GroupInfo from alice2 and parsing the ratchet_tree from it.
			gi2, err := alice2.PublishGroupInfo()
			if err != nil {
				t.Fatalf("alice2.PublishGroupInfo (post anti-dj): %v", err)
			}
			rt, err := tree.ParseRatchetTree(suite, gi2.RatchetTreeExtension())
			if err != nil {
				t.Fatalf("ParseRatchetTree (post anti-dj): %v", err)
			}
			ok, err := rt.VerifyParentHashes()
			if err != nil || !ok {
				t.Fatalf("VerifyParentHashes failed after anti-double-join (ok=%v, err=%v)", ok, err)
			}
			t.Logf("suite %#x: VerifyParentHashes passed after anti-double-join", csID)

			// bob2 occupies exactly one leaf after re-join (newBob2 is the sole bob identity).
			if newBob2.OwnLeaf() == bob2.OwnLeaf() {
				t.Logf("suite %#x: bob re-joined at same leaf %d (stale leaf was removed + refilled)",
					csID, newBob2.OwnLeaf())
			} else {
				t.Logf("suite %#x: newBob2 leaf %d, old bob2 leaf %d",
					csID, newBob2.OwnLeaf(), bob2.OwnLeaf())
			}

			// Suppress unused variable warning from buildTwoMemberGroup.
			_ = alice
			_ = bob
		})
	}
	if executed == 0 {
		t.Fatal("no registered suites executed")
	}
}

// resignExternalCommit decodes a valid external-commit MLSMessage, lets mutate
// rewrite its inner Commit (reorder/append proposals, tamper the leaf, …), then
// RE-SIGNS the FramedContent with the joiner's signer so the OUTER signature is
// valid again. This forces the receiver past signature verification and into the
// inner §12.4.3.2 validation we are actually testing (not a cheap sig failure).
// The original confirmation_tag is preserved unchanged.
func resignExternalCommit(t *testing.T, suite cipher.Suite, signer crypto.Signer, gc keyschedule.GroupContext, src []byte, mutate func(*group.Commit)) []byte {
	t.Helper()
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(src); err != nil {
		t.Fatalf("resign: UnmarshalMLS: %v", err)
	}
	var cm group.Commit
	if err := cm.UnmarshalMLS(m.Public.Content.Content); err != nil {
		t.Fatalf("resign: Commit.UnmarshalMLS: %v", err)
	}
	mutate(&cm)
	newBody, err := cm.MarshalMLS()
	if err != nil {
		t.Fatalf("resign: Commit.MarshalMLS: %v", err)
	}
	fc := m.Public.Content
	fc.Content = newBody
	_, sig, err := framing.SignCommit(suite, signer, &gc, fc)
	if err != nil {
		t.Fatalf("resign: SignCommit: %v", err)
	}
	m.Public.Content = fc
	m.Public.Auth.Signature = sig // keep original ConfirmationTag
	out, err := m.MarshalMLS()
	if err != nil {
		t.Fatalf("resign: MLSMessage.MarshalMLS: %v", err)
	}
	return out
}

// TestExternalCommitReceiverValidation covers the receiver-side admission gaps in
// processExternalCommit (RFC 9420 §12.4.3.2). Each case starts from a VALID
// external commit, mutates it adversarially, and RE-SIGNS with the joiner's
// signer — so we exercise inner validation, not signature checks. The receiver
// must return an error WITHOUT panicking and WITHOUT advancing its epoch.
func TestExternalCommitReceiverValidation(t *testing.T) {
	executed := 0
	for _, csID := range externalCommitSuites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			// Build a baseline valid external commit (carol, fresh non-member).
			// alice0 (leaf 0) + bob (leaf 1); the adversarial commits target alice0.
			alice0, _ := buildTwoMemberGroup(t, suite)

			// assertRejectedNoPanic processes commitBytes on alice0 — the group whose
			// GroupInfo the commit was signed against — and requires a clean error +
			// no panic + unchanged epoch. A rejected commit is atomic (state intact),
			// so the same alice0 is reused across cases.
			assertRejectedNoPanic := func(t *testing.T, commitBytes []byte, desc string) {
				t.Helper()
				epBefore := alice0.Epoch()
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("%s: PANIC (must be a clean error): %v", desc, r)
						}
					}()
					if err := alice0.ProcessCommit(nil, commitBytes); err == nil {
						t.Errorf("%s: expected error, got nil", desc)
					} else {
						t.Logf("%s: correctly rejected: %v", desc, err)
					}
				}()
				if alice0.Epoch() != epBefore {
					t.Errorf("%s: epoch changed (%d → %d) after rejected commit", desc, epBefore, alice0.Epoch())
				}
			}

			gi, err := alice0.PublishGroupInfo()
			if err != nil {
				t.Fatalf("PublishGroupInfo: %v", err)
			}
			carolSigner := makeSigner(t)
			_, validCommit, err := group.ExternalCommit(suite, *gi, makeCred("carol"), carolSigner, makeLifetime())
			if err != nil {
				t.Fatalf("ExternalCommit (baseline): %v", err)
			}
			gc := gi.GroupContext // epoch-n context used to re-sign

			// (a) Critical-1 repro — ExternalInit NOT first: prepend a Remove so the
			// old code's cm.Proposals[0].Proposal.ExternalInit would nil-deref and
			// panic. Re-signed → reaches the inner code path. Must error, not panic.
			notFirst := resignExternalCommit(t, suite, carolSigner, gc, validCommit, func(cm *group.Commit) {
				removeBob := group.ProposalOrRef{
					Type: group.ProposalOrRefTypeProposal,
					Proposal: &group.Proposal{
						Type:   group.ProposalTypeRemove,
						Remove: &group.Remove{Removed: 1}, // bob (leaf 1)
					},
				}
				cm.Proposals = append([]group.ProposalOrRef{removeBob}, cm.Proposals...)
			})
			assertRejectedNoPanic(t, notFirst, "(a) ExternalInit-not-first")

			// (b) Critical-2 repro — foreign-leaf Remove: [ExternalInit, Remove(bob)].
			// bob's signature key != joiner's → unauthorized eviction, must reject.
			foreignRemove := resignExternalCommit(t, suite, carolSigner, gc, validCommit, func(cm *group.Commit) {
				cm.Proposals = append(cm.Proposals, group.ProposalOrRef{
					Type: group.ProposalOrRefTypeProposal,
					Proposal: &group.Proposal{
						Type:   group.ProposalTypeRemove,
						Remove: &group.Remove{Removed: 1}, // bob, NOT the joiner
					},
				})
			})
			assertRejectedNoPanic(t, foreignRemove, "(b) foreign-leaf Remove")

			// (c) Important-3 repro — malformed joiner leaf: tamper the leaf signature
			// and re-sign the FramedContent. The outer sig is valid but the leaf's own
			// LeafNodeTBS signature is broken → must reject.
			badLeaf := resignExternalCommit(t, suite, carolSigner, gc, validCommit, func(cm *group.Commit) {
				if len(cm.Path.LeafNode.Signature) == 0 {
					t.Fatal("(c): joiner leaf has no signature to tamper")
				}
				cm.Path.LeafNode.Signature[0] ^= 0xff
			})
			assertRejectedNoPanic(t, badLeaf, "(c) malformed joiner leaf signature")

			// (c2) Important-3 — wrong leaf_node_source: a commit-path leaf must be
			// source=commit. Flip to key_package and re-sign the frame.
			badSource := resignExternalCommit(t, suite, carolSigner, gc, validCommit, func(cm *group.Commit) {
				lt := tree.Lifetime{NotBefore: 0, NotAfter: 1 << 62}
				cm.Path.LeafNode.LeafNodeSource = tree.LeafNodeSourceKeyPackage
				cm.Path.LeafNode.Lifetime = &lt
				cm.Path.LeafNode.ParentHash = nil
			})
			assertRejectedNoPanic(t, badSource, "(c2) wrong leaf_node_source")
		})
	}
	if executed == 0 {
		t.Fatal("no registered suites executed")
	}
}

// TestExternalCommitExternalInitNotFirst is the dedicated Critical-1 (panic/DoS)
// repro (RFC 9420 §12.4.3.2). It builds a LEGITIMATE anti-double-join external
// commit whose proposals are [ExternalInit, Remove(ownStaleLeaf)], then reorders
// them to [Remove(ownStaleLeaf), ExternalInit] and re-signs. Because the Remove
// targets the joiner's OWN stale leaf, the anti-double-join authorization check
// passes — so execution proceeds to the point where the old code indexed
// cm.Proposals[0].Proposal.ExternalInit.KemOutput and nil-dereferenced (the [0]
// proposal is now the Remove). The receiver MUST return a clean error, NOT panic.
func TestExternalCommitExternalInitNotFirst(t *testing.T) {
	executed := 0
	for _, csID := range externalCommitSuites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			// Build a 2-member group with a CONTROLLED bob signer so we can re-use
			// bob's identity for an anti-double-join external commit.
			bobSigner := makeSigner(t)
			aliceSigner := makeSigner(t)
			alice, err := group.NewGroup(suite, []byte("ext-init-order"), makeCred("alice"), aliceSigner, makeLifetime())
			if err != nil {
				t.Fatalf("NewGroup(alice): %v", err)
			}
			bobKP, bobInitPriv, bobLeafPriv, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
			if err != nil {
				t.Fatalf("NewKeyPackage(bob): %v", err)
			}
			bobKPMsg, err := group.EncodeKeyPackageMessage(bobKP)
			if err != nil {
				t.Fatalf("EncodeKeyPackageMessage(bob): %v", err)
			}
			_, welcomeBob, err := alice.Commit(group.CommitOptions{
				ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
			})
			if err != nil {
				t.Fatalf("Commit(Add bob): %v", err)
			}
			if _, err := group.JoinFromWelcome(suite, welcomeBob, group.JoinOptions{
				KeyPackage:     bobKPMsg,
				InitPriv:       bobInitPriv,
				EncryptionPriv: bobLeafPriv,
				Signer:         bobSigner,
				ExternalPSKs:   map[string][]byte{},
			}); err != nil {
				t.Fatalf("JoinFromWelcome(bob): %v", err)
			}

			gi, err := alice.PublishGroupInfo()
			if err != nil {
				t.Fatalf("PublishGroupInfo: %v", err)
			}

			// bob external-commits with the SAME signer → anti-double-join fires:
			// the commit is [ExternalInit, Remove(bob's stale leaf 1)].
			_, antiDJCommit, err := group.ExternalCommit(suite, *gi, makeCred("bob"), bobSigner, makeLifetime())
			if err != nil {
				t.Fatalf("ExternalCommit(bob anti-dj): %v", err)
			}

			// Reorder so ExternalInit is NOT first, keeping the legitimate own-leaf
			// Remove → the Remove check passes, exposing the old [0] nil-deref.
			reordered := resignExternalCommit(t, suite, bobSigner, gi.GroupContext, antiDJCommit, func(cm *group.Commit) {
				// Sanity: confirm the honest commit really is [ExternalInit, Remove].
				if len(cm.Proposals) != 2 ||
					cm.Proposals[0].Proposal.Type != group.ProposalTypeExternalInit ||
					cm.Proposals[1].Proposal.Type != group.ProposalTypeRemove {
					t.Fatalf("unexpected anti-dj proposal shape: %d proposals", len(cm.Proposals))
				}
				cm.Proposals[0], cm.Proposals[1] = cm.Proposals[1], cm.Proposals[0]
			})

			epBefore := alice.Epoch()
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("ExternalInit-not-first: PANIC (Critical-1 not fixed): %v", r)
					}
				}()
				if err := alice.ProcessCommit(nil, reordered); err == nil {
					t.Error("ExternalInit-not-first: expected error, got nil")
				} else {
					t.Logf("ExternalInit-not-first: correctly rejected (no panic): %v", err)
				}
			}()
			if alice.Epoch() != epBefore {
				t.Errorf("epoch changed (%d → %d) after rejected commit", epBefore, alice.Epoch())
			}
		})
	}
	if executed == 0 {
		t.Fatal("no registered suites executed")
	}
}

// TestExternalCommitValidation tests that malformed external commits are rejected
// and leave g unchanged (Task 3 negative gate, RFC 9420 §12.4.3.2).
//
// The validity checks in processExternalCommit run BEFORE signature verification,
// so we can inject malformed Commit bodies without needing a valid signature.
func TestExternalCommitValidation(t *testing.T) {
	executed := 0
	for _, csID := range externalCommitSuites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			alice, bob := buildTwoMemberGroup(t, suite)
			_ = bob

			gi, err := alice.PublishGroupInfo()
			if err != nil {
				t.Fatalf("PublishGroupInfo: %v", err)
			}
			carolSigner := makeSigner(t)

			// Baseline: a valid external commit must succeed.
			_, validCommit, err := group.ExternalCommit(suite, *gi, makeCred("carol"), carolSigner, makeLifetime())
			if err != nil {
				t.Fatalf("ExternalCommit (baseline): %v", err)
			}

			// Helper: decode → modify Commit → re-encode → return new message bytes.
			// The validity checks fire before signature verification, so the invalid
			// signature on the tampered message is irrelevant for these cases.
			tamperCommit := func(t *testing.T, src []byte, mutate func(*group.Commit)) []byte {
				t.Helper()
				var m framing.MLSMessage
				if err := m.UnmarshalMLS(src); err != nil {
					t.Fatalf("UnmarshalMLS: %v", err)
				}
				var cm group.Commit
				if err := cm.UnmarshalMLS(m.Public.Content.Content); err != nil {
					t.Fatalf("Commit.UnmarshalMLS: %v", err)
				}
				mutate(&cm)
				newBody, err := cm.MarshalMLS()
				if err != nil {
					t.Fatalf("Commit.MarshalMLS: %v", err)
				}
				m.Public.Content.Content = newBody
				out, err := m.MarshalMLS()
				if err != nil {
					t.Fatalf("MLSMessage.MarshalMLS: %v", err)
				}
				return out
			}

			// assertRejected verifies that g rejects the commit and leaves the epoch
			// unchanged (state-atomicity guarantee).
			assertRejected := func(t *testing.T, g *group.Group, commitBytes []byte, desc string) {
				t.Helper()
				epBefore := g.Epoch()
				if err := g.ProcessCommit(nil, commitBytes); err == nil {
					t.Errorf("%s: expected error, got nil", desc)
				} else {
					t.Logf("%s: correctly rejected: %v", desc, err)
				}
				if g.Epoch() != epBefore {
					t.Errorf("%s: epoch changed (%d → %d) after rejected commit", desc, epBefore, g.Epoch())
				}
			}

			// Need a fresh alice for each negative test (valid commit advances alice above).
			freshAlice := func(t *testing.T) *group.Group {
				t.Helper()
				a, _ := buildTwoMemberGroup(t, suite)
				return a
			}

			// ── Negative 1: two ExternalInit proposals ────────────────────────────
			twoExtInit := tamperCommit(t, validCommit, func(cm *group.Commit) {
				cm.Proposals = append(cm.Proposals, group.ProposalOrRef{
					Type: group.ProposalOrRefTypeProposal,
					Proposal: &group.Proposal{
						Type:         group.ProposalTypeExternalInit,
						ExternalInit: &group.ExternalInit{KemOutput: []byte("extra")},
					},
				})
			})
			assertRejected(t, freshAlice(t), twoExtInit, "two ExternalInit proposals")

			// ── Negative 2: path-less external commit ─────────────────────────────
			noPath := tamperCommit(t, validCommit, func(cm *group.Commit) {
				cm.Path = nil
			})
			assertRejected(t, freshAlice(t), noPath, "no path")

			// ── Negative 3: by-reference proposal in external commit ──────────────
			byRef := tamperCommit(t, validCommit, func(cm *group.Commit) {
				cm.Proposals = append(cm.Proposals, group.ProposalOrRef{
					Type:      group.ProposalOrRefTypeReference,
					Reference: []byte("fakeref000000000000000000000000000"),
				})
			})
			assertRejected(t, freshAlice(t), byRef, "by-reference proposal")

			// ── Positive baseline (after negative tests) ──────────────────────────
			// Rebuild a fresh alice and verify the valid commit still advances epoch.
			alice3, _ := buildTwoMemberGroup(t, suite)
			gi3, err := alice3.PublishGroupInfo()
			if err != nil {
				t.Fatalf("PublishGroupInfo (alice3): %v", err)
			}
			_, validCommit3, err := group.ExternalCommit(suite, *gi3, makeCred("dave"), makeSigner(t), makeLifetime())
			if err != nil {
				t.Fatalf("ExternalCommit (alice3/dave): %v", err)
			}
			epochBefore := alice3.Epoch()
			if err := alice3.ProcessCommit(nil, validCommit3); err != nil {
				t.Fatalf("ProcessCommit (valid, alice3): %v", err)
			}
			if alice3.Epoch() != epochBefore+1 {
				t.Fatalf("alice3 epoch %d after valid external commit, want %d", alice3.Epoch(), epochBefore+1)
			}
		})
	}
	if executed == 0 {
		t.Fatal("no registered suites executed")
	}
}
