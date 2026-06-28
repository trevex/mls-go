package sim

import (
	"bytes"
	"fmt"
	"sort"
)

// InvariantChecker evaluates the rev 5 §0 invariants for the dual-group
// pure-redundancy model:
//
//	(1) per-replica convergence (live members agree on EpochAuthenticator + SA key)
//	(2) data-plane zero key-loss (every non-dropped data packet decryptable) — the headline
//	(3) membership correctness per replica (liveness is folded in: a member that did
//	    not catch up will be absent from the live set and trigger a membership failure)
//
// There is NO "no-permanent-fork" invariant: a single reflector ordering a group
// via its own accept-once register is a true total order, so no replica ever forks.
// Inv. 2 is checked continuously (packetLoss); 1/3 at quiescence (Evaluate).
type InvariantChecker struct {
	lossEvents []LossEvent
}

// LossEvent is one undecryptable-packet observation (inv. 2 failure).
type LossEvent struct {
	VNI       uint32 // channel = saVNI(tenant, replica)
	SentEpoch uint64
	RecvEpoch uint64
	At        uint64
}

func newInvariantChecker() *InvariantChecker { return &InvariantChecker{} }

func (k *InvariantChecker) packetLoss(vni, sentEpoch, recvEpoch, at uint64) {
	k.lossEvents = append(k.lossEvents, LossEvent{vni32(vni), sentEpoch, recvEpoch, at})
}

// Result is the per-run verdict.
type Result struct {
	InvariantsHeld bool
	Divergence     []string    // inv. 1 failures (per-replica convergence)
	Fork           []string    // always nil in this model (no forks) — kept for report shape
	Membership     []string    // inv. 3 failures (membership; liveness folded in)
	PacketLoss     []LossEvent // inv. 2 failures
	Metrics        *Metrics
	Trace          []string
}

// Evaluate runs inv. 1/3 at quiescence over the live clients (per replica
// channel) and folds in the continuously-collected inv. 2 events.
func (k *InvariantChecker) Evaluate(clients []*Client, intended map[uint32]map[string]bool) Result {
	r := Result{InvariantsHeld: true, PacketLoss: k.lossEvents}
	if len(k.lossEvents) > 0 {
		r.InvariantsHeld = false
	}
	type tip struct {
		epoch uint64
		ea    []byte
		key   []byte
	}
	byCh := map[uint32][]tip{}
	live := map[uint32]map[string]bool{}
	for _, c := range clients {
		for _, ch := range sortedVNIKeys(c.vnis) {
			st := c.vnis[ch]
			if !st.joined {
				continue
			}
			sa, err := st.ctrl.CurrentSA()
			if err != nil {
				continue
			}
			byCh[ch] = append(byCh[ch], tip{st.ctrl.Epoch(), st.ctrl.Group().EpochAuthenticator(), sa.Key})
			if live[ch] == nil {
				live[ch] = map[string]bool{}
			}
			live[ch][c.identity] = true
		}
	}
	// inv. 1 (per-replica convergence): one (epoch, EA, SA key) per channel.
	for _, ch := range sortedUint32(byCh) {
		tips := byCh[ch]
		for i := 1; i < len(tips); i++ {
			if tips[i].epoch != tips[0].epoch || !bytes.Equal(tips[i].ea, tips[0].ea) {
				r.Divergence = append(r.Divergence,
					fmt.Sprintf("ch=%d (vni=%d r=%d) epoch/EA mismatch %d vs %d",
						ch, tenantOf(ch), replicaOf(ch), tips[i].epoch, tips[0].epoch))
				r.InvariantsHeld = false
			}
			if !bytes.Equal(tips[i].key, tips[0].key) {
				r.Divergence = append(r.Divergence,
					fmt.Sprintf("ch=%d (vni=%d r=%d) SA key mismatch", ch, tenantOf(ch), replicaOf(ch)))
				r.InvariantsHeld = false
			}
		}
	}
	// inv. 3 (membership / liveness folded in): the live set per replica channel
	// matches the intended set after churn settles.
	for _, ch := range sortedIntendedKeys(intended) {
		want := intended[ch]
		got := live[ch]
		if !sameSet(want, got) {
			r.Membership = append(r.Membership,
				fmt.Sprintf("ch=%d (vni=%d r=%d) membership mismatch want=%v got=%v",
					ch, tenantOf(ch), replicaOf(ch), sortedSetKeys(want), sortedSetKeys(got)))
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
