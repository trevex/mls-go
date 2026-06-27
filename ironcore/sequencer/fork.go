package sequencer

import (
	"bytes"
	"sync"

	"github.com/trevex/mls-mlkem-go/mls/group"
)

// EpochAuthenticatorRegistry records the epoch_authenticator(s) reported for each
// (group, epoch) and flags divergence — active fork detection (design spec §5.6
// item 1; the authenticator is DeriveSecret(epoch_secret, "authentication"),
// RFC 9420 §8.7). Two distinct authenticators for the same (group, epoch) is a
// detected fork (§5.2: incompatible epoch n+1 states ⇒ different authenticators).
type EpochAuthenticatorRegistry struct {
	mu   sync.Mutex
	seen map[string][][]byte // seqKey → set of distinct authenticators
}

// NewEpochAuthenticatorRegistry returns a ready, empty registry.
func NewEpochAuthenticatorRegistry() *EpochAuthenticatorRegistry {
	return &EpochAuthenticatorRegistry{seen: map[string][][]byte{}}
}

// Report records auth for (group, epoch) and returns fork=true iff more than one
// DISTINCT authenticator has now been reported for that (group, epoch). Reporting
// the same authenticator repeatedly never flags a fork (idempotent).
func (r *EpochAuthenticatorRegistry) Report(g group.GroupID, epoch uint64, auth []byte) (fork bool) {
	key := seqKey(g, epoch)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.seen[key] {
		if bytes.Equal(a, auth) {
			return len(r.seen[key]) > 1 // already known; fork iff set already diverged
		}
	}
	cp := make([]byte, len(auth))
	copy(cp, auth)
	r.seen[key] = append(r.seen[key], cp)
	return len(r.seen[key]) > 1
}

// Divergent reports whether a fork has been detected for (group, epoch).
func (r *EpochAuthenticatorRegistry) Divergent(g group.GroupID, epoch uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen[seqKey(g, epoch)]) > 1
}
