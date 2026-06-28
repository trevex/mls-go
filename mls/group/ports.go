package group

import (
	"context"
	"errors"
	"time"

	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// GroupID identifies a group on the delivery service (opaque to mls/).
type GroupID []byte

// CommitRef is an opaque, collision-resistant reference to one Commit (e.g.
// RefHash over the framed commit, or Hash(commit-message-bytes)). The ordering
// authority treats it as opaque and compares it only by bytes (design spec
// §5.1/§5.6, §10.2 — the sequencer holds no group secrets).
type CommitRef []byte

// Ordering is the single-linearization-point contract (design spec §5.1/§5.5):
// the map (group_id, epoch) → accepted Commit as a single-valued, linearizable
// register ("first valid writer per epoch wins"). Implementations: B1 fenced
// single-writer per VNI (default) and B2 consensus register; both are CP and
// provably satisfy §5.1. metalbond selects an implementation in its own repo.
type Ordering interface {
	// AcceptCommit returns ok=true iff commit is accepted as the decided Commit
	// for (group, epoch): true for the first valid commit, and idempotently true
	// when the SAME commit is re-submitted for an already-decided (group, epoch).
	// It returns ok=false for any DIFFERENT commit once (group, epoch) is decided.
	AcceptCommit(ctx context.Context, group GroupID, epoch uint64, commit CommitRef) (ok bool, err error)
}

// CredentialValidator validates an identity<->signature-key binding (AS role,
// design spec §4/§8) and returns the verified identity for the authz hook.
type CredentialValidator interface {
	Validate(cred tree.Credential, sigPub []byte) (identity []byte, err error)
}

// Clock supplies the current time for KeyPackage lifetime checks (injectable).
type Clock interface{ Now() time.Time }

// ─── defaults ────────────────────────────────────────────────────────────────

// BasicCredentialValidator accepts basic credentials whose identity is non-empty
// and returns that identity. It performs NO PKI/SPIFFE checks — adapters live in
// ironcore/.
type BasicCredentialValidator struct{}

// Validate returns the credential's identity for a non-empty basic credential,
// or an error for any other credential type or empty identity.
func (BasicCredentialValidator) Validate(cred tree.Credential, sigPub []byte) ([]byte, error) {
	if cred.CredentialType != tree.CredentialTypeBasic || len(cred.Identity) == 0 {
		return nil, errors.New("group: BasicCredentialValidator requires a non-empty basic credential")
	}
	return cred.Identity, nil
}

// SystemClock implements Clock via time.Now.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }
