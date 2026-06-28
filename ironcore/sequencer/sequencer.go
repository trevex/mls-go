// Package sequencer is the IronCore ordering authority (design spec §5):
// single-linearizable-register, B1 fencing, fork detection, tie-break.
// It imports only mls/group (for GroupID/CommitRef/Ordering/Clock) and
// mls/cipher (for the tie-break Hash) — no import cycle, no group secrets.
package sequencer

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"

	"github.com/trevex/mls-go/mls/group"
)

// seqKey encodes (group, epoch) into a collision-free map key: an 8-byte
// big-endian epoch prefix followed by the raw group bytes (injective).
func seqKey(g group.GroupID, epoch uint64) string {
	b := make([]byte, 8+len(g))
	binary.BigEndian.PutUint64(b[:8], epoch)
	copy(b[8:], g)
	return string(b)
}

// cloneRef returns a defensive copy so a caller mutating its slice cannot alter
// a decided value (the register must be immutable once written).
func cloneRef(r group.CommitRef) group.CommitRef {
	c := make(group.CommitRef, len(r))
	copy(c, r)
	return c
}

// MemorySequencer is the reference in-process single-linearizable-register
// implementation of group.Ordering (design spec §5.1/§5.5): the map
// (group, epoch) → CommitRef under a mutex, with first-valid-writer-wins CAS
// and idempotent re-accept. It is the canonical correct CP register; B1/B2
// exist to guarantee only ONE such register is live per VNI (§5.3/§5.5).
type MemorySequencer struct {
	mu      sync.Mutex
	decided map[string]group.CommitRef
}

// NewMemorySequencer returns a ready, empty MemorySequencer.
func NewMemorySequencer() *MemorySequencer {
	return &MemorySequencer{decided: map[string]group.CommitRef{}}
}

var _ group.Ordering = (*MemorySequencer)(nil)

// AcceptCommit implements group.Ordering (design spec §5.1). It is linearizable:
// all calls are serialized by the mutex; the first valid commit for a fresh
// (group, epoch) wins; re-submitting the SAME commit returns true; any DIFFERENT
// commit for a decided (group, epoch) returns false.
func (s *MemorySequencer) AcceptCommit(ctx context.Context, g group.GroupID, epoch uint64, commit group.CommitRef) (bool, error) {
	key := seqKey(g, epoch)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ex, ok := s.decided[key]; ok {
		return bytes.Equal(ex, commit), nil // idempotent if same; reject if different
	}
	s.decided[key] = cloneRef(commit)
	return true, nil
}

// Decided returns the decided CommitRef for (group, epoch) and whether one
// exists. Exposed for fork-detection / monitoring (read-only; copies out).
func (s *MemorySequencer) Decided(g group.GroupID, epoch uint64) (group.CommitRef, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.decided[seqKey(g, epoch)]
	if !ok {
		return nil, false
	}
	return cloneRef(r), true
}
