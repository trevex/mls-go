package sequencer_test

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-go/ironcore/sequencer"
	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
)

func TestTieBreakDeterministic(t *testing.T) {
	suite, ok := cipher.Lookup(cipher.XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite 0xF001 not registered")
	}

	// Three candidate refs.
	candidates := []group.CommitRef{
		group.CommitRef([]byte("candidate-alpha")),
		group.CommitRef([]byte("candidate-beta")),
		group.CommitRef([]byte("candidate-gamma")),
	}

	// Compute the winner from the canonical ordering.
	winner := sequencer.CanonicalCommit(suite, candidates)
	if winner == nil {
		t.Fatal("CanonicalCommit returned nil for non-empty set")
	}

	// All permutations must return the byte-equal winner.
	perms := [][]group.CommitRef{
		{candidates[0], candidates[1], candidates[2]},
		{candidates[0], candidates[2], candidates[1]},
		{candidates[1], candidates[0], candidates[2]},
		{candidates[1], candidates[2], candidates[0]},
		{candidates[2], candidates[0], candidates[1]},
		{candidates[2], candidates[1], candidates[0]},
	}
	for i, perm := range perms {
		got := sequencer.CanonicalCommit(suite, perm)
		if !bytes.Equal(got, winner) {
			t.Errorf("permutation %d: got %x, want %x", i, got, winner)
		}
	}

	// The winner must have the minimum Hash among candidates.
	winnerHash := suite.Hash(winner)
	for _, c := range candidates {
		if bytes.Equal(c, winner) {
			continue
		}
		h := suite.Hash(c)
		if bytes.Compare(h, winnerHash) < 0 {
			t.Errorf("candidate %x has lower hash than winner %x", c, winner)
		}
	}

	// Empty set → nil.
	if got := sequencer.CanonicalCommit(suite, nil); got != nil {
		t.Fatalf("empty set: got %x, want nil", got)
	}
	if got := sequencer.CanonicalCommit(suite, []group.CommitRef{}); got != nil {
		t.Fatalf("empty slice: got %x, want nil", got)
	}

	// Single element → that element.
	single := group.CommitRef([]byte("only"))
	if got := sequencer.CanonicalCommit(suite, []group.CommitRef{single}); !bytes.Equal(got, single) {
		t.Fatalf("single element: got %x, want %x", got, single)
	}
}
