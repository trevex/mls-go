package sim

import (
	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

// InvariantChecker evaluates the §3.5 invariants. inv. 5 is checked continuously
// (via packetLoss); inv. 1–4 at quiescence (via Evaluate).
type InvariantChecker struct {
	far        *sequencer.EpochAuthenticatorRegistry
	diverged   map[string]bool // vniKey(vni,base) -> a fork was observed
	lossEvents []LossEvent
}

// LossEvent is one undecryptable-packet observation (inv. 5 failure).
type LossEvent struct {
	VNI       uint32
	SentEpoch uint64
	RecvEpoch uint64
	At        uint64
}

func newInvariantChecker() *InvariantChecker {
	return &InvariantChecker{
		far:      sequencer.NewEpochAuthenticatorRegistry(),
		diverged: map[string]bool{},
	}
}

func (k *InvariantChecker) reportAuth(vni uint32, epoch uint64, auth []byte) {
	k.far.Report(group.GroupID(ironcore.GroupID(vni)), epoch, auth)
}

func (k *InvariantChecker) markDivergence(vni uint32, base uint64) {
	k.diverged[vniKey(vni, base)] = true
}

func (k *InvariantChecker) packetLoss(vni, sentEpoch, recvEpoch, at uint64) {
	k.lossEvents = append(k.lossEvents, LossEvent{vni32(vni), sentEpoch, recvEpoch, at})
}
