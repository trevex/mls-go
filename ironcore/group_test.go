package ironcore_test

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

func TestVNIGroup(t *testing.T) {
	suiteID := cipher.XWING_AES256GCM_SHA256_Ed25519
	suite, ok := cipher.Lookup(suiteID)
	if !ok {
		t.Skipf("suite %#x not registered", suiteID)
	}

	const vni = uint32(0xBEEF)
	alice, _, _ := build3MemberGroup(t, suite, ironcore.GroupID(vni))

	vg := ironcore.NewVNIGroup(vni, alice)

	// VNI() delegates to the stored VNI.
	if vg.VNI() != vni {
		t.Fatalf("VNI() = %#x, want %#x", vg.VNI(), vni)
	}

	// GroupID() returns GroupID(vni).
	if !bytes.Equal(vg.GroupID(), ironcore.GroupID(vni)) {
		t.Fatalf("GroupID() = %x, want %x", vg.GroupID(), ironcore.GroupID(vni))
	}

	// Epoch() tracks the underlying group.
	if vg.Epoch() != alice.Epoch() {
		t.Fatalf("Epoch() = %d, want %d", vg.Epoch(), alice.Epoch())
	}

	// Group() returns the exact pointer.
	if vg.Group() != alice {
		t.Fatal("Group() returned different pointer than the one passed to NewVNIGroup")
	}

	// DeriveSA() byte-equals DeriveSAKeys(g, vni).
	sa1, err := vg.DeriveSA()
	if err != nil {
		t.Fatalf("DeriveSA(): %v", err)
	}
	sa2, err := ironcore.DeriveSAKeys(alice, vni)
	if err != nil {
		t.Fatalf("DeriveSAKeys(): %v", err)
	}
	if !bytes.Equal(sa1.Key, sa2.Key) {
		t.Fatalf("DeriveSA().Key != DeriveSAKeys().Key:\n  DeriveSA:     %x\n  DeriveSAKeys: %x", sa1.Key, sa2.Key)
	}
}
