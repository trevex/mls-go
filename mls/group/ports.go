package group

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/trevex/mls-mlkem-go/mls/framing"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// GroupID identifies a group on the delivery service (opaque to mls/).
type GroupID []byte

// Incoming is one ordered handshake message from the delivery service.
type Incoming struct {
	Epoch   uint64
	Message *framing.MLSMessage
}

// DeliveryService fans out handshake messages and delivers the ordered stream
// (design spec §4; UNTRUSTED for confidentiality — RFC 9750 §5).
type DeliveryService interface {
	Send(ctx context.Context, group GroupID, msg *framing.MLSMessage) error
	Receive(ctx context.Context, group GroupID) (<-chan Incoming, error)
	PublishGroupInfo(ctx context.Context, group GroupID, gi *GroupInfo) error
	FetchGroupInfo(ctx context.Context, group GroupID) (*GroupInfo, error)
}

// CredentialValidator validates an identity<->signature-key binding (AS role,
// design spec §4/§8) and returns the verified identity for the authz hook.
type CredentialValidator interface {
	Validate(cred tree.Credential, sigPub []byte) (identity []byte, err error)
}

// EpochState is the persistable snapshot of a group at one epoch.
type EpochState struct {
	Epoch      uint64
	GroupID    []byte
	Serialized []byte // opaque engine-defined encoding (see Group.Export/Import — optional)
}

// StateStore persists per-group epoch state (design spec §4/§9; default = in-memory).
type StateStore interface {
	Save(group GroupID, st EpochState) error
	Load(group GroupID) (EpochState, bool, error)
	Wipe(group GroupID) error
}

// Clock supplies the current time for KeyPackage lifetime checks (injectable).
type Clock interface{ Now() time.Time }

// ─── defaults ────────────────────────────────────────────────────────────────

// InMemoryStateStore is the default ephemeral StateStore (keys never persisted).
type InMemoryStateStore struct {
	mu sync.Mutex
	m  map[string]EpochState
}

// NewInMemoryStateStore returns a ready-to-use in-memory StateStore.
func NewInMemoryStateStore() *InMemoryStateStore {
	return &InMemoryStateStore{m: map[string]EpochState{}}
}

// Save stores the epoch state for the given group, replacing any prior state.
func (s *InMemoryStateStore) Save(group GroupID, st EpochState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[string(group)] = st
	return nil
}

// Load retrieves the epoch state for the given group. ok is false if absent.
func (s *InMemoryStateStore) Load(group GroupID) (EpochState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[string(group)]
	return st, ok, nil
}

// Wipe removes all stored state for the given group.
func (s *InMemoryStateStore) Wipe(group GroupID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, string(group))
	return nil
}

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
