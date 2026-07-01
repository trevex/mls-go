package bench

import (
	"fmt"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
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

// benchSuites are the suites we characterize: classical (0x0001) and PQ X-Wing.
func benchSuites(b *testing.B) map[string]cipher.Suite {
	b.Helper()
	out := map[string]cipher.Suite{}
	for name, id := range map[string]cipher.CipherSuite{
		"classical": cipher.X25519_AES128GCM_SHA256_Ed25519,
		"xwing":     cipher.XWING_AES256GCM_SHA256_Ed25519,
	} {
		s, ok := cipher.Lookup(id)
		if !ok {
			b.Fatalf("suite %s not registered", name)
		}
		out[name] = s
	}
	return out
}

// BenchmarkCommitUpdate measures committer cpu_per_commit(M) for an empty PCS
// rekey across suites and sizes. Machine-dependent; reporting only.
func BenchmarkCommitUpdate(b *testing.B) {
	for name, s := range benchSuites(b) {
		for _, M := range []int{2, 8, 32, 128} {
			b.Run(fmt.Sprintf("%s/M=%d", name, M), func(b *testing.B) {
				g, err := BuildGroup(s, M)
				if err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, _, err := g.Commit(group.CommitOptions{}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// buildCommitterFollower returns a committer (the founder) and a real follower
// that are both genuine members of the SAME M-member group at the same epoch.
//
// This differs from the naive "two independent BuildGroup results" approach:
// BuildGroup returns only a committer and discards the added members' private
// keys, so two separate BuildGroup groups have unrelated membership/signature
// keys and every ProcessCommit fails membership_tag verification (a cheap,
// meaningless early exit that never reaches the TreeKEM UpdatePath decrypt).
// Here the follower joins from the committer's Welcome, so it can actually apply
// the committer's commits. M must be >= 2.
func buildCommitterFollower(s cipher.Suite, M int) (committer, follower *group.Group, err error) {
	if M < 2 {
		return nil, nil, fmt.Errorf("M must be >= 2, got %d", M)
	}
	committer, err = group.NewGroup(s, []byte("bench-group"), cred("founder"), newSigner(), life())
	if err != nil {
		return nil, nil, err
	}
	// The follower is a real member whose private key material we retain so it
	// can join from the Welcome and subsequently apply commits.
	followerSigner := newSigner()
	followerKP, followerInit, followerLeaf, err := group.NewKeyPackage(s, cred("follower"), followerSigner, life())
	if err != nil {
		return nil, nil, err
	}
	followerKPMsg, err := group.EncodeKeyPackageMessage(followerKP)
	if err != nil {
		return nil, nil, err
	}
	adds := make([]group.Proposal, 0, M-1)
	adds = append(adds, group.ProposeAdd(followerKP))
	for i := 2; i < M; i++ { // M-2 filler members (private material discarded)
		adds = append(adds, group.ProposeAdd(keyPackage(s, fmt.Sprintf("m-%d", i))))
	}
	_, welcome, err := committer.Commit(group.CommitOptions{ByValue: adds})
	if err != nil {
		return nil, nil, err
	}
	follower, err = group.JoinFromWelcome(s, welcome, group.JoinOptions{
		KeyPackage: followerKPMsg, InitPriv: followerInit, EncryptionPriv: followerLeaf,
		Signer: followerSigner, ExternalPSKs: map[string][]byte{},
	})
	if err != nil {
		return nil, nil, err
	}
	return committer, follower, nil
}

// BenchmarkApply measures cpu_per_apply(M): a member processing one empty Update
// commit. Committer and follower are genuine members of the same group and are
// kept in lockstep — the committer produces one commit (untimed) and the
// follower applies it (timed) each iteration, so both advance together and every
// iteration is a real TreeKEM apply. Machine-dependent; reporting only.
func BenchmarkApply(b *testing.B) {
	for name, s := range benchSuites(b) {
		for _, M := range []int{2, 8, 32, 128} {
			b.Run(fmt.Sprintf("%s/M=%d", name, M), func(b *testing.B) {
				committer, follower, err := buildCommitterFollower(s, M)
				if err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					commit, _, err := committer.Commit(group.CommitOptions{})
					if err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
					if err := follower.ProcessCommit(nil, commit); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
