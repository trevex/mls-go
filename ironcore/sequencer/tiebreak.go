package sequencer

import (
	"bytes"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

// CanonicalCommit returns the canonical branch reference for recovery: the
// candidate with the lowest Hash(commitRef) (design spec §5.6 tie-break). The
// result is independent of candidate order, so every losing member selects the
// same branch. Comparison key = Hash(ref) ‖ ref (a strict total order even under
// a hypothetical hash collision). Returns nil for an empty candidate set.
func CanonicalCommit(suite cipher.Suite, candidates []group.CommitRef) group.CommitRef {
	var best group.CommitRef
	var bestKey []byte
	for _, c := range candidates {
		key := append(suite.Hash(c), c...)
		if best == nil || bytes.Compare(key, bestKey) < 0 {
			best, bestKey = c, key
		}
	}
	return best
}
