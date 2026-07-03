package ironcore_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/trevex/mls-go/ironcore"
	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
	"github.com/trevex/mls-go/mls/tree"
)

// ─── local test helpers ───────────────────────────────────────────────────────

func makeSigner(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func makeCred(identity string) tree.Credential {
	return tree.Credential{
		CredentialType: tree.CredentialTypeBasic,
		Identity:       []byte(identity),
	}
}

func makeLifetime() tree.Lifetime {
	return tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)}
}

// build3MemberGroup returns alice, bob, carol as a converged 3-member group
// under suite with the given groupID bytes.
func build3MemberGroup(t *testing.T, suite cipher.Suite, groupID []byte) (alice, bob, carol *group.Group) {
	t.Helper()

	aliceSigner := makeSigner(t)
	alice, err := group.NewGroup(suite, groupID, makeCred("alice"), aliceSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewGroup(alice): %v", err)
	}

	// Add Bob
	bobSigner := makeSigner(t)
	bobKP, bobInitPriv, bobLeafPriv, err := group.NewKeyPackage(suite, makeCred("bob"), bobSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewKeyPackage(bob): %v", err)
	}
	bobKPMsg, err := group.EncodeKeyPackageMessage(bobKP)
	if err != nil {
		t.Fatalf("EncodeKeyPackageMessage(bob): %v", err)
	}
	commitMsg, welcomeMsg, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(bobKP)},
	})
	if err != nil {
		t.Fatalf("Commit(Add Bob): %v", err)
	}
	_ = commitMsg
	bob, err = group.JoinFromWelcome(suite, welcomeMsg, group.JoinOptions{
		KeyPackage:     bobKPMsg,
		InitPriv:       bobInitPriv,
		EncryptionPriv: bobLeafPriv,
		Signer:         bobSigner,
		ExternalPSKs:   map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(bob): %v", err)
	}

	// Add Carol
	carolSigner := makeSigner(t)
	carolKP, carolInitPriv, carolLeafPriv, err := group.NewKeyPackage(suite, makeCred("carol"), carolSigner, makeLifetime())
	if err != nil {
		t.Fatalf("NewKeyPackage(carol): %v", err)
	}
	carolKPMsg, err := group.EncodeKeyPackageMessage(carolKP)
	if err != nil {
		t.Fatalf("EncodeKeyPackageMessage(carol): %v", err)
	}
	commitMsg2, welcomeMsg2, err := alice.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(carolKP)},
	})
	if err != nil {
		t.Fatalf("Commit(Add Carol): %v", err)
	}
	if err := bob.ProcessCommit(nil, commitMsg2); err != nil {
		t.Fatalf("bob.ProcessCommit(Add Carol): %v", err)
	}
	carol, err = group.JoinFromWelcome(suite, welcomeMsg2, group.JoinOptions{
		KeyPackage:     carolKPMsg,
		InitPriv:       carolInitPriv,
		EncryptionPriv: carolLeafPriv,
		Signer:         carolSigner,
		ExternalPSKs:   map[string][]byte{},
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(carol): %v", err)
	}

	return alice, bob, carol
}

// ─── SA derivation tests ──────────────────────────────────────────────────────

func TestDeriveSAKeys(t *testing.T) {
	suiteID := cipher.XWING_AES256GCM_SHA256_Ed25519
	suite, ok := cipher.Lookup(suiteID)
	if !ok {
		t.Skipf("suite %#x not registered", suiteID)
	}

	const vni = uint32(0xF001)
	alice, bob, carol := build3MemberGroup(t, suite, ironcore.GroupID(vni))

	// (a) All members derive byte-equal Key (len 32), equal SPI (> 255), equal Epoch.
	saAlice, err := ironcore.DeriveSAKeys(alice, vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(alice): %v", err)
	}
	saBob, err := ironcore.DeriveSAKeys(bob, vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(bob): %v", err)
	}
	saCarol, err := ironcore.DeriveSAKeys(carol, vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(carol): %v", err)
	}

	if len(saAlice.Key) != 32 {
		t.Fatalf("Key len = %d, want 32", len(saAlice.Key))
	}
	if !bytes.Equal(saAlice.Key, saBob.Key) {
		t.Fatalf("alice/bob Key mismatch:\n  alice %x\n  bob   %x", saAlice.Key, saBob.Key)
	}
	if !bytes.Equal(saAlice.Key, saCarol.Key) {
		t.Fatalf("alice/carol Key mismatch:\n  alice %x\n  carol %x", saAlice.Key, saCarol.Key)
	}
	if saAlice.SPI <= 255 {
		t.Fatalf("SPI %d not > 255 (RFC 4303 reserved range)", saAlice.SPI)
	}
	if saAlice.SPI != saBob.SPI || saAlice.SPI != saCarol.SPI {
		t.Fatalf("SPI mismatch: alice=%d bob=%d carol=%d", saAlice.SPI, saBob.SPI, saCarol.SPI)
	}
	if saAlice.Epoch != saBob.Epoch || saAlice.Epoch != saCarol.Epoch {
		t.Fatalf("Epoch mismatch: alice=%d bob=%d carol=%d", saAlice.Epoch, saBob.Epoch, saCarol.Epoch)
	}

	// (b) SenderSalt(0/1/2) pairwise distinct, len 4, equal across members per sender.
	salts := [3][]byte{}
	for i, leafIdx := range []uint32{0, 1, 2} {
		saltA, err := saAlice.SenderSalt(leafIdx)
		if err != nil {
			t.Fatalf("alice.SenderSalt(%d): %v", leafIdx, err)
		}
		saltB, err := saBob.SenderSalt(leafIdx)
		if err != nil {
			t.Fatalf("bob.SenderSalt(%d): %v", leafIdx, err)
		}
		saltC, err := saCarol.SenderSalt(leafIdx)
		if err != nil {
			t.Fatalf("carol.SenderSalt(%d): %v", leafIdx, err)
		}
		if len(saltA) != 4 {
			t.Fatalf("SenderSalt(%d) len = %d, want 4", leafIdx, len(saltA))
		}
		if !bytes.Equal(saltA, saltB) || !bytes.Equal(saltA, saltC) {
			t.Fatalf("SenderSalt(%d) mismatch: alice=%x bob=%x carol=%x", leafIdx, saltA, saltB, saltC)
		}
		salts[i] = saltA
	}
	// Pairwise distinct.
	if bytes.Equal(salts[0], salts[1]) || bytes.Equal(salts[0], salts[2]) || bytes.Equal(salts[1], salts[2]) {
		t.Fatalf("SenderSalt not pairwise distinct: 0=%x 1=%x 2=%x", salts[0], salts[1], salts[2])
	}

	// (b2) Injectivity over a large leaf range: salts for 0..4095 must all be distinct.
	// This proves the bijection guarantee — every distinct leaf → distinct salt.
	const largeCount = 4096
	saltSet := make(map[[4]byte]struct{}, largeCount)
	for i := uint32(0); i < largeCount; i++ {
		s, err := saAlice.SenderSalt(i)
		if err != nil {
			t.Fatalf("SenderSalt(%d): %v", i, err)
		}
		var k [4]byte
		copy(k[:], s)
		if _, dup := saltSet[k]; dup {
			t.Fatalf("SenderSalt not injective: duplicate salt %x at leaf %d", s, i)
		}
		saltSet[k] = struct{}{}
	}
	if len(saltSet) != largeCount {
		t.Fatalf("injectivity: expected %d distinct salts, got %d", largeCount, len(saltSet))
	}

	// (c) After a path-only commit (epoch++), Key and SPI both change; members still agree.
	commitMsg, _, err := alice.Commit(group.CommitOptions{})
	if err != nil {
		t.Fatalf("alice.Commit (epoch++): %v", err)
	}
	if err := bob.ProcessCommit(nil, commitMsg); err != nil {
		t.Fatalf("bob.ProcessCommit: %v", err)
	}
	if err := carol.ProcessCommit(nil, commitMsg); err != nil {
		t.Fatalf("carol.ProcessCommit: %v", err)
	}

	saAlice2, err := ironcore.DeriveSAKeys(alice, vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(alice) epoch+1: %v", err)
	}
	saBob2, err := ironcore.DeriveSAKeys(bob, vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(bob) epoch+1: %v", err)
	}
	saCarol2, err := ironcore.DeriveSAKeys(carol, vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(carol) epoch+1: %v", err)
	}

	if bytes.Equal(saAlice.Key, saAlice2.Key) {
		t.Fatal("Key did not change after epoch++")
	}
	if saAlice.SPI == saAlice2.SPI {
		t.Fatal("SPI did not change after epoch++")
	}
	if !bytes.Equal(saAlice2.Key, saBob2.Key) || !bytes.Equal(saAlice2.Key, saCarol2.Key) {
		t.Fatalf("Key mismatch after epoch++: alice=%x bob=%x carol=%x", saAlice2.Key, saBob2.Key, saCarol2.Key)
	}
	if saAlice2.SPI != saBob2.SPI || saAlice2.SPI != saCarol2.SPI {
		t.Fatalf("SPI mismatch after epoch++: alice=%d bob=%d carol=%d", saAlice2.SPI, saBob2.SPI, saCarol2.SPI)
	}
}

func TestSenderSPIPerSender(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("suite not registered")
	}
	const vni = uint32(0xF001)
	alice, bob, carol := build3MemberGroup(t, suite, ironcore.GroupID(vni))
	sa, err := ironcore.DeriveSAKeys(alice, vni)
	if err != nil {
		t.Fatal(err)
	}
	spis := map[uint32]uint32{}
	for _, leaf := range []uint32{0, 1, 2} {
		s, err := sa.SenderSPI(leaf)
		if err != nil {
			t.Fatalf("SenderSPI(%d): %v", leaf, err)
		}
		if s <= 255 {
			t.Fatalf("SenderSPI(%d)=%d not > 255", leaf, s)
		}
		if uint8(s) != uint8(sa.Epoch) {
			t.Fatalf("SenderSPI(%d) low byte %d != epoch low byte %d", leaf, uint8(s), uint8(sa.Epoch))
		}
		spis[leaf] = s
	}
	if spis[0] == spis[1] || spis[0] == spis[2] || spis[1] == spis[2] {
		t.Fatalf("SenderSPI not distinct across senders: %v", spis)
	}
	saBob, _ := ironcore.DeriveSAKeys(bob, vni)
	saCarol, _ := ironcore.DeriveSAKeys(carol, vni)
	for _, leaf := range []uint32{0, 1, 2} {
		b, _ := saBob.SenderSPI(leaf)
		c, _ := saCarol.SenderSPI(leaf)
		if b != spis[leaf] || c != spis[leaf] {
			t.Fatalf("SenderSPI(%d) disagrees across members: alice=%d bob=%d carol=%d", leaf, spis[leaf], b, c)
		}
	}
	own, _ := sa.SenderSPI(sa.OwnLeaf)
	if sa.OwnSPI != own {
		t.Fatalf("OwnSPI=%d != SenderSPI(OwnLeaf)=%d", sa.OwnSPI, own)
	}
	if sa.SPI <= 255 {
		t.Fatalf("group SPI %d not > 255", sa.SPI)
	}
}

func TestSenderSPIChangesWithEpoch(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	const vni = uint32(7)
	alice, bob, carol := build3MemberGroup(t, suite, ironcore.GroupID(vni))
	sa1, _ := ironcore.DeriveSAKeys(alice, vni)
	s1, _ := sa1.SenderSPI(1)
	commit, _, _ := alice.Commit(group.CommitOptions{})
	_ = bob.ProcessCommit(nil, commit)
	_ = carol.ProcessCommit(nil, commit)
	sa2, _ := ironcore.DeriveSAKeys(alice, vni)
	s2, _ := sa2.SenderSPI(1)
	if s1 == s2 {
		t.Fatal("SenderSPI did not change across epochs")
	}
}
