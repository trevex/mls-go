package ironcore_test

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// x509SVIDCred builds an MLS x509 Credential for leafPub with a SPIFFE URI SAN,
// signed by the given CA (caPriv, caDER). Used to demonstrate the §8 authz path
// in the scenario gate. Delegates to makeLeafCert + makeX509Cred from
// credential_test.go (same package).
func x509SVIDCred(t *testing.T, caPriv ed25519.PrivateKey, caDER []byte, leafPub ed25519.PublicKey, spiffeURI string) tree.Credential {
	t.Helper()
	return makeX509Cred(makeLeafCert(t, leafPub, spiffeURI, caDER, caPriv))
}

// buildVNIGroup creates a converged N-member VNI group under suite, with the
// given VNI encoded as the MLS GroupID (design spec §10.1). Member 0 is the
// creator; members 1..n-1 join via Commit(Add)+JoinFromWelcome in order.
// Returns one *ironcore.VNIGroup per member (all at the same epoch).
func buildVNIGroup(t *testing.T, suite cipher.Suite, vni uint32, n int) []*ironcore.VNIGroup {
	t.Helper()
	if n < 1 {
		t.Fatal("buildVNIGroup: n must be >= 1")
	}

	groupID := ironcore.GroupID(vni)

	// Member 0 — the creator.
	signer0 := makeSigner(t)
	g0, err := group.NewGroup(suite, groupID, makeCred("node-0"), signer0, makeLifetime())
	if err != nil {
		t.Fatalf("buildVNIGroup: NewGroup(node-0): %v", err)
	}

	groups := []*group.Group{g0}

	// Add members 1..n-1 one by one. Member 0 always commits the Add.
	for i := 1; i < n; i++ {
		si := makeSigner(t)
		kp, initPriv, leafPriv, err := group.NewKeyPackage(suite, makeCred(fmt.Sprintf("node-%d", i)), si, makeLifetime())
		if err != nil {
			t.Fatalf("buildVNIGroup: NewKeyPackage(node-%d): %v", i, err)
		}
		kpMsg, err := group.EncodeKeyPackageMessage(kp)
		if err != nil {
			t.Fatalf("buildVNIGroup: EncodeKeyPackageMessage(node-%d): %v", i, err)
		}

		// Member 0 commits the Add; welcome is sent to the new member.
		commitMsg, welcomeMsg, err := groups[0].Commit(group.CommitOptions{
			ByValue: []group.Proposal{group.ProposeAdd(kp)},
		})
		if err != nil {
			t.Fatalf("buildVNIGroup: Commit(Add node-%d): %v", i, err)
		}

		// All existing members except 0 process the commit.
		for j := 1; j < i; j++ {
			if err := groups[j].ProcessCommit(nil, commitMsg); err != nil {
				t.Fatalf("buildVNIGroup: node-%d.ProcessCommit(Add node-%d): %v", j, i, err)
			}
		}

		// New member joins.
		gi, err := group.JoinFromWelcome(suite, welcomeMsg, group.JoinOptions{
			KeyPackage:     kpMsg,
			InitPriv:       initPriv,
			EncryptionPriv: leafPriv,
			Signer:         si,
			ExternalPSKs:   map[string][]byte{},
		})
		if err != nil {
			t.Fatalf("buildVNIGroup: JoinFromWelcome(node-%d): %v", i, err)
		}
		groups = append(groups, gi)
	}

	// Wrap each *group.Group in a *VNIGroup.
	vniGroups := make([]*ironcore.VNIGroup, len(groups))
	for i, g := range groups {
		vniGroups[i] = ironcore.NewVNIGroup(vni, g)
	}
	return vniGroups
}

// addMember adds a new member to an existing set of VNIGroups (membership
// change → new epoch). Member 0 commits the Add; all existing members
// ProcessCommit; the new member JoinFromWelcome. Returns the new VNIGroup
// (all existing VNIGroups have been advanced to the new epoch via their
// underlying *group.Group).
func addMember(t *testing.T, nodes []*ironcore.VNIGroup, suite cipher.Suite, vni uint32) *ironcore.VNIGroup {
	t.Helper()
	newIdx := len(nodes)
	si := makeSigner(t)
	kp, initPriv, leafPriv, err := group.NewKeyPackage(suite, makeCred(fmt.Sprintf("node-%d", newIdx)), si, makeLifetime())
	if err != nil {
		t.Fatalf("addMember: NewKeyPackage(node-%d): %v", newIdx, err)
	}
	kpMsg, err := group.EncodeKeyPackageMessage(kp)
	if err != nil {
		t.Fatalf("addMember: EncodeKeyPackageMessage: %v", err)
	}

	// Member 0 commits the Add.
	commitMsg, welcomeMsg, err := nodes[0].Group().Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(kp)},
	})
	if err != nil {
		t.Fatalf("addMember: Commit(Add node-%d): %v", newIdx, err)
	}

	// All existing members except 0 process the commit.
	for i := 1; i < len(nodes); i++ {
		if err := nodes[i].Group().ProcessCommit(nil, commitMsg); err != nil {
			t.Fatalf("addMember: node-%d.ProcessCommit: %v", i, err)
		}
	}

	// New member joins.
	newGroup, err := group.JoinFromWelcome(suite, welcomeMsg, group.JoinOptions{
		KeyPackage:     kpMsg,
		InitPriv:       initPriv,
		EncryptionPriv: leafPriv,
		Signer:         si,
		ExternalPSKs:   map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("addMember: JoinFromWelcome(node-%d): %v", newIdx, err)
	}
	return ironcore.NewVNIGroup(vni, newGroup)
}
