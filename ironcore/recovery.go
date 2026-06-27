package ironcore

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// ErrRecoverySuperseded is returned by RecoverViaExternalCommit when another
// recovery already won the (group, epoch) linearization slot. The caller can
// errors.Is-check to drive the retry loop (re-fetch the decided GroupInfo and
// retry against the new canonical epoch).
var ErrRecoverySuperseded = errors.New("ironcore: recovery superseded by a concurrent winner")

// RecoverViaExternalCommit re-converges a stale/losing VNIGroup onto the
// canonical branch after a fork (design spec §5.6). It picks the canonical
// branch deterministically (lowest Hash(CommitRef), Plan 11 tie-break), builds
// an external Commit from that branch's signed GroupInfo (anti-double-join
// Remove of the loser's stale leaf is handled by group.ExternalCommit), and
// routes the recovery commit through the SINGLE Ordering linearization point so
// the recovery itself cannot fork. On success the VNIGroup adopts the new group
// state at the recovered epoch, and the returned commit bytes must be broadcast
// to all canonical-branch members (who apply it via ProcessExternalCommit).
//
// fetchGI maps a candidate branch CommitRef to that branch's signed GroupInfo
// at the contested epoch (provided by the delivery service / out-of-band).
func RecoverViaExternalCommit(
	ctx context.Context,
	v *VNIGroup,
	suite cipher.Suite,
	candidates []group.CommitRef,
	fetchGI func(group.CommitRef) (*group.GroupInfo, error),
	ordering group.Ordering,
	cred tree.Credential,
	signer crypto.Signer,
	lifetime tree.Lifetime,
) ([]byte, error) {
	canonical := sequencer.CanonicalCommit(suite, candidates)
	if canonical == nil {
		return nil, fmt.Errorf("ironcore: RecoverViaExternalCommit: no candidate branches")
	}
	gi, err := fetchGI(canonical)
	if err != nil {
		return nil, fmt.Errorf("ironcore: RecoverViaExternalCommit: fetch canonical GroupInfo: %w", err)
	}
	newGroup, commitMsg, err := group.ExternalCommit(suite, *gi, cred, signer, lifetime)
	if err != nil {
		return nil, fmt.Errorf("ironcore: RecoverViaExternalCommit: ExternalCommit: %w", err)
	}
	ref := group.CommitRef(suite.Hash(commitMsg))
	ok, err := ordering.AcceptCommit(ctx, group.GroupID(v.GroupID()), gi.GroupContext.Epoch, ref)
	if err != nil {
		return nil, fmt.Errorf("ironcore: RecoverViaExternalCommit: AcceptCommit: %w", err)
	}
	if !ok {
		// Another recovery already won this (group, epoch). Caller re-fetches the
		// now-decided GroupInfo and retries against the next epoch.
		return nil, ErrRecoverySuperseded
	}
	v.g = newGroup // adopt the canonical-branch state; caller broadcasts commitMsg.
	return commitMsg, nil
}
