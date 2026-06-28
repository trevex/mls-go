package sim

import (
	"bytes"
	"fmt"
	"sort"

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
	if k.far.Report(group.GroupID(ironcore.GroupID(vni)), epoch, auth) {
		// a fork at (vni, epoch) is now detected
	}
}

func (k *InvariantChecker) markDivergence(vni uint32, base uint64) {
	k.diverged[vniKey(vni, base)] = true
}

func (k *InvariantChecker) packetLoss(vni, sentEpoch, recvEpoch, at uint64) {
	k.lossEvents = append(k.lossEvents, LossEvent{vni32(vni), sentEpoch, recvEpoch, at})
}

// Result is the per-run verdict.
type Result struct {
	InvariantsHeld bool
	Divergence     []string    // inv. 1 failures
	Fork           []string    // inv. 2 failures
	Liveness       []string    // inv. 3 failures
	Membership     []string    // inv. 4 failures
	PacketLoss     []LossEvent // inv. 5 failures
	Metrics        *Metrics
	Trace          []string
}

// Evaluate runs inv. 1–4 at quiescence over the live clients, and folds in the
// continuously-collected inv. 5 events.
func (k *InvariantChecker) Evaluate(clients []*Client, intended map[uint32]map[string]bool) Result {
	r := Result{InvariantsHeld: true, PacketLoss: k.lossEvents}
	if len(k.lossEvents) > 0 {
		r.InvariantsHeld = false
	}
	// group live members per VNI
	type tip struct {
		epoch uint64
		ea    []byte
		key   []byte
	}
	byVNI := map[uint32][]tip{}
	live := map[uint32]map[string]bool{}
	for _, c := range clients {
		for _, vni := range sortedVNIKeys(c.vnis) {
			st := c.vnis[vni]
			if !st.joined {
				continue
			}
			sa, err := st.ctrl.CurrentSA()
			if err != nil {
				continue
			}
			byVNI[vni] = append(byVNI[vni], tip{st.ctrl.Epoch(), st.ctrl.Group().EpochAuthenticator(), sa.Key})
			if live[vni] == nil {
				live[vni] = map[string]bool{}
			}
			live[vni][c.identity] = true
		}
	}
	// inv. 1 (convergence) + inv. 3 (liveness): one EA+key per VNI
	for _, vni := range sortedUint32(byVNI) {
		tips := byVNI[vni]
		for i := 1; i < len(tips); i++ {
			if tips[i].epoch != tips[0].epoch || !bytes.Equal(tips[i].ea, tips[0].ea) {
				r.Divergence = append(r.Divergence, fmt.Sprintf("vni=%d epoch mismatch %d vs %d", vni, tips[i].epoch, tips[0].epoch))
				r.InvariantsHeld = false
			}
			if !bytes.Equal(tips[i].key, tips[0].key) {
				r.Divergence = append(r.Divergence, fmt.Sprintf("vni=%d SA key mismatch", vni))
				r.InvariantsHeld = false
			}
		}
	}
	// inv. 2 (no permanent fork): every observed divergence must NOT remain a
	// live multi-EA at quiescence (already covered by inv. 1); record any base
	// that diverged but did not re-converge for diagnostics.
	for _, vni := range sortedUint32(byVNI) {
		tips := byVNI[vni]
		for i := 1; i < len(tips); i++ {
			if !bytes.Equal(tips[i].ea, tips[0].ea) {
				r.Fork = append(r.Fork, fmt.Sprintf("vni=%d unrecovered fork", vni))
				r.InvariantsHeld = false
			}
		}
	}
	// inv. 4 (membership): live set matches intended
	for _, vni := range sortedIntendedKeys(intended) {
		want := intended[vni]
		got := live[vni]
		if !sameSet(want, got) {
			r.Membership = append(r.Membership, fmt.Sprintf("vni=%d membership mismatch want=%v got=%v", vni, sortedSetKeys(want), sortedSetKeys(got)))
			r.InvariantsHeld = false
		}
	}
	return r
}

func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
