package bench

import (
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
)

func classical(t *testing.T) cipher.Suite {
	t.Helper()
	s, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("classical suite not registered")
	}
	return s
}

func TestBuildGroupHasMMembers(t *testing.T) {
	s := classical(t)
	for _, M := range []int{1, 2, 8, 32} {
		g, err := BuildGroup(s, M)
		if err != nil {
			t.Fatalf("BuildGroup(M=%d): %v", M, err)
		}
		if got := len(g.ActiveLeaves()); got != M {
			t.Fatalf("M=%d: ActiveLeaves=%d, want %d", M, got, M)
		}
	}
}

func TestCommitBytesPositiveAndGrows(t *testing.T) {
	s := classical(t)
	small, err := MeasureCommitBytes(s, 4, OpUpdate)
	if err != nil {
		t.Fatal(err)
	}
	large, err := MeasureCommitBytes(s, 64, OpUpdate)
	if err != nil {
		t.Fatal(err)
	}
	if small <= 0 || large <= 0 {
		t.Fatalf("non-positive commit bytes: small=%d large=%d", small, large)
	}
	// TreeKEM UpdatePath grows with tree depth ⇒ a 64-member commit is larger
	// than a 4-member one (monotone; not asserting the exact log constant).
	if large <= small {
		t.Fatalf("expected commit bytes to grow with M: M=4 -> %d, M=64 -> %d", small, large)
	}
}

func TestWelcomeBytesPositive(t *testing.T) {
	s := classical(t)
	b, err := MeasureWelcomeBytes(s, 16)
	if err != nil {
		t.Fatal(err)
	}
	if b <= 0 {
		t.Fatalf("welcome bytes = %d, want > 0", b)
	}
}
