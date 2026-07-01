// Package bench measures deterministic per-event MLS size constants (commit and
// welcome bytes as a function of members-per-VNI M) and provides testing.B CPU
// benchmarks. The byte measurements are deterministic and feed the scaling
// model (see scaling/); the CPU benchmarks are machine-dependent and reporting
// only. Stdlib-only.
package bench

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
	"github.com/trevex/mls-go/mls/tree"
)

// Op selects which membership operation's commit to size.
type Op int

const (
	OpUpdate Op = iota // empty PCS rekey commit
	OpAdd              // commit adding one member
	OpRemove           // commit removing one member
)

func life() tree.Lifetime { return tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)} }

func cred(id string) tree.Credential {
	return tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte(id)}
}

func newSigner() crypto.Signer {
	_, s, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return s
}

func keyPackage(s cipher.Suite, id string) group.KeyPackage {
	kp, _, _, err := group.NewKeyPackage(s, cred(id), newSigner(), life())
	if err != nil {
		panic(err)
	}
	return kp
}

// BuildGroup returns a committer's Group whose ratchet tree holds exactly M
// members (founder + M-1 added in a single commit, applied to the committer's
// own state). M must be >= 1.
func BuildGroup(s cipher.Suite, M int) (*group.Group, error) {
	if M < 1 {
		return nil, fmt.Errorf("M must be >= 1, got %d", M)
	}
	g, err := group.NewGroup(s, []byte("bench-group"), cred("founder"), newSigner(), life())
	if err != nil {
		return nil, err
	}
	if M == 1 {
		return g, nil
	}
	adds := make([]group.Proposal, 0, M-1)
	for i := 1; i < M; i++ {
		adds = append(adds, group.ProposeAdd(keyPackage(s, fmt.Sprintf("m-%d", i))))
	}
	if _, _, err := g.Commit(group.CommitOptions{ByValue: adds}); err != nil {
		return nil, err
	}
	return g, nil
}

// MeasureCommitBytes returns the wire size of the named op's commit on a fresh
// M-member group.
func MeasureCommitBytes(s cipher.Suite, M int, op Op) (int, error) {
	g, err := BuildGroup(s, M)
	if err != nil {
		return 0, err
	}
	var opts group.CommitOptions
	switch op {
	case OpUpdate:
		// empty commit
	case OpAdd:
		opts.ByValue = []group.Proposal{group.ProposeAdd(keyPackage(s, "joiner"))}
	case OpRemove:
		leaves := g.ActiveLeaves()
		if len(leaves) < 2 {
			return 0, fmt.Errorf("need >=2 members to remove, have %d", len(leaves))
		}
		// leaves[0] is the founder/committer; remove another.
		opts.ByValue = []group.Proposal{group.ProposeRemove(leaves[1])}
	default:
		return 0, fmt.Errorf("unknown op %d", op)
	}
	commit, _, err := g.Commit(opts)
	if err != nil {
		return 0, err
	}
	return len(commit), nil
}

// MeasureWelcomeBytes returns the wire size of the Welcome produced when adding
// one member to an M-member group — a proxy for a joiner's imported group state.
func MeasureWelcomeBytes(s cipher.Suite, M int) (int, error) {
	g, err := BuildGroup(s, M)
	if err != nil {
		return 0, err
	}
	_, welcome, err := g.Commit(group.CommitOptions{
		ByValue: []group.Proposal{group.ProposeAdd(keyPackage(s, "joiner"))},
	})
	if err != nil {
		return 0, err
	}
	return len(welcome), nil
}
