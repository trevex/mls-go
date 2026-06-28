package group_test

import (
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
)

// byrefAddSuites are the suites exercised by the by-reference-Add regression:
// the classical Ed25519 suite (0x0001) and the post-quantum X-Wing suite
// (0xF001). Both use Ed25519 signatures so makeSigner works unchanged.
var byrefAddSuites = []cipher.CipherSuite{
	cipher.XWING_AES256GCM_SHA256_Ed25519,  // 0xF001
	cipher.X25519_AES128GCM_SHA256_Ed25519, // 0x0001
}

// TestByReferenceAddBuildsWelcome is a regression test for the bug surfaced by
// cross-implementation interop testing against OpenMLS: when the committer
// commits an Add proposal BY REFERENCE (the Add was delivered as a separate
// PublicMessage proposal and the Commit references it by ProposalRef rather
// than inlining it by value), Commit must still build a Welcome for the newly
// added member (RFC 9420 §12.4.3.1 — a Welcome is produced for every
// newly-added member regardless of how the Add was framed).
//
// Before the fix, Commit collected addedKPs only from opt.ByValue, so a
// by-reference Add produced addedKPs len 0 while newlyAdded len 1, and
// buildWelcome aborted with "newlyAdded len 1 != addedKPs len 0".
//
// This mirrors exactly how the interop server's Commit RPC maps proto
// by_reference proposals: alice ProposeAdd(bobKP) → FrameProposal → Commit
// with CommitOptions.ByReference (NOT ByValue).
func TestByReferenceAddBuildsWelcome(t *testing.T) {
	executed := 0
	for _, csID := range byrefAddSuites {
		csID := csID
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		t.Run("suite", func(t *testing.T) {
			groupID := []byte("byref-add-group")

			// Alice creates the group.
			aliceSigner := makeSigner(t)
			alice, err := group.NewGroup(suite, groupID, makeCred("alice"), aliceSigner, makeLifetime())
			if err != nil {
				t.Fatalf("NewGroup(Alice): %v", err)
			}

			// Bob publishes a KeyPackage.
			bobSigner := makeSigner(t)
			bobKP, bobInitPriv, bobLeafPriv, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
			if err != nil {
				t.Fatalf("NewKeyPackage(Bob): %v", err)
			}
			bobKPMsg, err := group.EncodeKeyPackageMessage(bobKP)
			if err != nil {
				t.Fatalf("EncodeKeyPackageMessage(Bob): %v", err)
			}

			// Alice proposes Add(Bob) and frames it as a standalone PublicMessage
			// proposal — this is what gets committed BY REFERENCE.
			addProp := group.ProposeAdd(bobKP)
			addMsg, err := alice.FrameProposal(addProp)
			if err != nil {
				t.Fatalf("FrameProposal(Add Bob): %v", err)
			}

			// Alice commits the staged Add BY REFERENCE (ProposalRef), not inline.
			commitMsg, welcomeMsg, err := alice.Commit(group.CommitOptions{
				ByReference: [][]byte{addMsg},
			})
			if err != nil {
				t.Fatalf("Alice.Commit(Add Bob by-ref): %v", err)
			}
			if len(welcomeMsg) == 0 {
				t.Fatal("expected non-nil Welcome for by-reference Add, got empty")
			}
			_ = commitMsg

			// Bob joins from the Welcome and must converge with Alice.
			bob, err := group.JoinFromWelcome(suite, welcomeMsg, group.JoinOptions{
				KeyPackage:     bobKPMsg,
				InitPriv:       bobInitPriv,
				EncryptionPriv: bobLeafPriv,
				Signer:         bobSigner,
				ExternalPSKs:   map[string][]byte{},
			})
			if err != nil {
				t.Fatalf("JoinFromWelcome(Bob): %v", err)
			}

			assertConverged(t, "byref-add", suite, alice, bob)
		})
	}
	if executed == 0 {
		t.Fatal("no suites executed (all skipped)")
	}
}
