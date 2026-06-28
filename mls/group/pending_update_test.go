package group_test

import (
	"fmt"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
)

// pendingUpdateSuites exercises both the standard suite and the X-Wing PQ suite.
var pendingUpdateSuites = []cipher.CipherSuite{
	cipher.X25519_AES128GCM_SHA256_Ed25519, // 0x0001
	cipher.XWING_AES256GCM_SHA256_Ed25519,  // 0xF001
}

// buildThreeMemberGroup creates a converged 3-member (Alice, Bob, Carol) group
// at epoch 2.
func buildThreeMemberGroup(t *testing.T, suite cipher.Suite) (alice, bob, carol *group.Group) {
	t.Helper()
	groupID := []byte("pending-update-test-group")

	// Alice creates.
	aliceSigner := makeSigner(t)
	alice, err := group.NewGroup(suite, groupID, makeCred("alice"), aliceSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewGroup(Alice): %v", err)
	}

	// Alice commits Add(Bob).
	bobSigner := makeSigner(t)
	bobKP, bobInitPriv, bobLeafPriv, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewKeyPackage(Bob): %v", err)
	}
	bobKPMsg, err := group.EncodeKeyPackageMessage(bobKP)
	if err != nil {
		t.Fatalf("EncodeKeyPackageMessage(Bob): %v", err)
	}
	_, welcomeBob, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
	})
	if err != nil {
		t.Fatalf("Commit(Add Bob): %v", err)
	}
	bob, err = group.JoinFromWelcome(suite, welcomeBob, group.JoinOptions{
		KeyPackage:     bobKPMsg,
		InitPriv:       bobInitPriv,
		EncryptionPriv: bobLeafPriv,
		Signer:         bobSigner,
		ExternalPSKs:   map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(Bob): %v", err)
	}

	// Alice commits Add(Carol); Bob processes.
	carolSigner := makeSigner(t)
	carolKP, carolInitPriv, carolLeafPriv, err := group.NewKeyPackage(suite, makeCred("carol"), carolSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewKeyPackage(Carol): %v", err)
	}
	carolKPMsg, err := group.EncodeKeyPackageMessage(carolKP)
	if err != nil {
		t.Fatalf("EncodeKeyPackageMessage(Carol): %v", err)
	}
	commitAddCarol, welcomeCarol, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(carolKP)},
	})
	if err != nil {
		t.Fatalf("Commit(Add Carol): %v", err)
	}
	if err := bob.ProcessCommit(nil, commitAddCarol); err != nil {
		t.Fatalf("Bob.ProcessCommit(Add Carol): %v", err)
	}
	carol, err = group.JoinFromWelcome(suite, welcomeCarol, group.JoinOptions{
		KeyPackage:     carolKPMsg,
		InitPriv:       carolInitPriv,
		EncryptionPriv: carolLeafPriv,
		Signer:         carolSigner,
		ExternalPSKs:   map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(Carol): %v", err)
	}
	assertConverged(t, "setup", suite, alice, bob, carol)
	return alice, bob, carol
}

// TestPendingUpdateConvergesDifferentCommitter: Bob proposes Update; Alice
// commits it by reference; Bob processes with NO manual key install and
// still converges (atomic pending-update tracking).
func TestPendingUpdateConvergesDifferentCommitter(t *testing.T) {
	executed := 0
	for _, csID := range pendingUpdateSuites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		csID := csID
		t.Run(fmt.Sprintf("suite_%#x", csID), func(t *testing.T) {
			alice, bob, carol := buildThreeMemberGroup(t, suite)

			// Bob proposes Update — atomic pending-update: no second return value.
			updateProp, err := bob.ProposeUpdate()
			if err != nil {
				t.Fatalf("Bob.ProposeUpdate: %v", err)
			}
			updateMsg, err := bob.FrameProposal(updateProp)
			if err != nil {
				t.Fatalf("Bob.FrameProposal: %v", err)
			}

			// Alice commits Bob's Update by reference.
			commitMsg, _, err := alice.Commit(group.CommitOptions{
				ByReference: [][]byte{updateMsg},
			})
			if err != nil {
				t.Fatalf("Alice.Commit(Update Bob by-ref): %v", err)
			}

			// Bob processes — no manual install needed; the engine handles it atomically.
			if err := bob.ProcessCommit([][]byte{updateMsg}, commitMsg); err != nil {
				t.Fatalf("Bob.ProcessCommit: %v", err)
			}
			if err := carol.ProcessCommit([][]byte{updateMsg}, commitMsg); err != nil {
				t.Fatalf("Carol.ProcessCommit: %v", err)
			}

			assertConverged(t, "update-by-different-committer", suite, alice, bob, carol)
		})
	}
	if executed == 0 {
		t.Fatal("no suites executed (all skipped)")
	}
}

// TestSupersededUpdateOldKeyStillUsable: Bob proposes Update (pending stored,
// g.priv untouched), then Carol commits a path-only commit that does NOT
// include Bob's Update. Bob must successfully process Carol's commit using
// his OLD leaf key, and all members must converge.
func TestSupersededUpdateOldKeyStillUsable(t *testing.T) {
	executed := 0
	for _, csID := range pendingUpdateSuites {
		suite, ok := cipher.Lookup(csID)
		if !ok {
			t.Logf("suite %#x not registered, skipping", csID)
			continue
		}
		executed++
		csID := csID
		t.Run(fmt.Sprintf("suite_%#x", csID), func(t *testing.T) {
			alice, bob, carol := buildThreeMemberGroup(t, suite)

			// Bob proposes Update — pending stored in g.pendingUpdates, g.priv NOT mutated.
			if _, err := bob.ProposeUpdate(); err != nil {
				t.Fatalf("Bob.ProposeUpdate: %v", err)
			}

			// Carol commits path-only (does NOT include Bob's Update).
			carolCommit, _, err := carol.Commit(group.CommitOptions{})
			if err != nil {
				t.Fatalf("Carol.Commit(path-only): %v", err)
			}

			// Bob processes Carol's commit using his OLD leaf key (pending superseded).
			// This must NOT error; g.priv is intact since ProposeUpdate no longer mutates it.
			if err := bob.ProcessCommit(nil, carolCommit); err != nil {
				t.Fatalf("Bob.ProcessCommit(superseded): %v", err)
			}
			if err := alice.ProcessCommit(nil, carolCommit); err != nil {
				t.Fatalf("Alice.ProcessCommit(superseded): %v", err)
			}

			assertConverged(t, "superseded-update-old-key", suite, alice, bob, carol)
		})
	}
	if executed == 0 {
		t.Fatal("no suites executed (all skipped)")
	}
}
