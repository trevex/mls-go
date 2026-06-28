package sim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// fixedClock is an inert injectable clock (lifetimes are infinite; time never
// drives control flow — determinism rule).
type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func maxLifetime() tree.Lifetime { return tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)} }

func isSelfRemoved(err error) bool { return errors.Is(err, ironcore.ErrSelfRemoved) }

// kpEntry is one identity's published KeyPackage material per VNI.
type kpEntry struct {
	kpMsg, initPriv, leafPriv []byte
}

// kpDirectory maps identity → credential/signer and (identity,vni) → KeyPackage
// material (design spec §10.3).
type kpDirectory struct {
	creds   map[string]tree.Credential
	signers map[string]crypto.Signer
	kps     map[string]map[uint32]kpEntry // identity -> vni -> material
}

func newKPDirectory() *kpDirectory {
	return &kpDirectory{
		creds:   map[string]tree.Credential{},
		signers: map[string]crypto.Signer{},
		kps:     map[string]map[uint32]kpEntry{},
	}
}

func (d *kpDirectory) register(identity string, signer crypto.Signer) {
	d.creds[identity] = tree.Credential{
		CredentialType: tree.CredentialTypeBasic,
		Identity:       []byte(identity),
	}
	d.signers[identity] = signer
}

func (d *kpDirectory) cred(identity string) tree.Credential { return d.creds[identity] }

func (d *kpDirectory) newFounderGroup(suite cipher.Suite, vni uint32, identity string, signer crypto.Signer) *group.Group {
	g, err := group.NewGroup(suite, ironcore.GroupID(vni), d.cred(identity), signer, maxLifetime())
	if err != nil {
		panic(err)
	}
	return g
}

func (d *kpDirectory) publishKeyPackage(suite cipher.Suite, vni uint32, identity string, signer crypto.Signer) {
	kp, ip, lp, err := group.NewKeyPackage(suite, d.cred(identity), signer, maxLifetime())
	if err != nil {
		panic(err)
	}
	kpMsg, err := group.EncodeKeyPackageMessage(kp)
	if err != nil {
		panic(err)
	}
	if d.kps[identity] == nil {
		d.kps[identity] = map[uint32]kpEntry{}
	}
	d.kps[identity][vni] = kpEntry{kpMsg, ip, lp}
}

func (d *kpDirectory) resolver(vni uint32) ironcore.KeyPackageResolver {
	return func(identity []byte) ([]byte, bool) {
		if e, ok := d.kps[string(identity)][vni]; ok {
			return e.kpMsg, true
		}
		return nil, false
	}
}

func (d *kpDirectory) joinerMaterial(vni uint32, identity string) (kp, ip, lp []byte) {
	e := d.kps[identity][vni]
	return e.kpMsg, e.initPriv, e.leafPriv
}

// ─── determinism helpers (never range a map in control flow) ──────────────────

func sortedVNIKeys(m map[uint32]*vniState) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedEpochs(m map[uint64]ironcore.SA) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedActorEpochs(m map[ActorID]uint64) []ActorID {
	out := make([]ActorID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func vni32(v uint64) uint32 { return uint32(v) }

func sortedUint32[T any](m map[uint32]T) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedIntendedKeys(m map[uint32]map[string]bool) []uint32 { return sortedUint32(m) }

func sameSet(want, got map[string]bool) bool {
	if len(want) != len(got) {
		return false
	}
	for k := range want {
		if !got[k] {
			return false
		}
	}
	return true
}

func makeSigner() crypto.Signer {
	_, s, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return s
}

// ─── world: the per-run simulation universe ────────────────────────────────────

// world holds all mutable simulation state for one Run.
type world struct {
	sc             Scenario
	s              *Scheduler
	bus            *Bus
	faults         *faultState
	metrics        *Metrics
	checker        *InvariantChecker
	dir            *kpDirectory
	clients        []*Client
	dss            []*DS
	suite          cipher.Suite
	numReplicas    int
	intended       map[uint32]map[string]bool // channel(saVNI) -> intended member set
	desired        map[uint32]map[string]bool // channel(saVNI) -> desired member set
	settleDeadline uint64
	faultsLifted   bool
	// timer intervals (logical ticks)
	rekeyInterval     uint64
	heartbeatInterval uint64
	reconcileInterval uint64
	dataInterval      uint64
}

const (
	defaultRekeyInterval     = 20
	defaultHeartbeatInterval = 5
	defaultReconcileInterval = 15
	defaultDataInterval      = 3
)

// bootstrap sets up the initial world state: founder groups, subscriptions,
// scripted faults/churn, and periodic timers.
func (w *world) bootstrap() {
	w.rekeyInterval = defaultRekeyInterval
	w.heartbeatInterval = defaultHeartbeatInterval
	w.reconcileInterval = defaultReconcileInterval
	w.dataInterval = defaultDataInterval
	w.settleDeadline = w.sc.SettleRounds
	w.numReplicas = numDS
	if w.sc.SingleReplica {
		w.numReplicas = 1 // negative control: model only ONE replica
	}

	// Per tenant VNI run numReplicas independent groups on channels saVNI(v,r).
	// Client 0 founds every channel; clients 1..N-1 are prospective joiners of
	// both replicas (every host is a member of BOTH groups, rev 5 §0).
	const founderID = "client-0"
	for v := 0; v < w.sc.VNIs; v++ {
		for r := 0; r < w.numReplicas; r++ {
			ch := saVNI(uint32(v), r)
			w.clients[0].foundVNI(ch)
			if w.intended[ch] == nil {
				w.intended[ch] = map[string]bool{}
			}
			if w.desired[ch] == nil {
				w.desired[ch] = map[string]bool{}
			}
			w.intended[ch][founderID] = true
			w.desired[ch][founderID] = true
			for _, c := range w.clients[1:] {
				c.prospectiveVNI(ch)
			}
		}
	}

	// Schedule scripted faults.
	for _, p := range w.sc.Partitions {
		w.s.Schedule(p.At, Event{Kind: KindFault, Fault: FaultOp{
			Kind: faultPartition, On: true,
			SideA: p.SideA, SideB: p.SideB,
		}})
		w.s.Schedule(p.Until, Event{Kind: KindFault, Fault: FaultOp{
			Kind: faultPartition, On: false,
		}})
	}
	for _, d := range w.sc.DSDowns {
		w.s.Schedule(d.At, Event{Kind: KindFault, Fault: FaultOp{
			Kind: faultDSDown, On: true, DS: d.DS,
		}})
		w.s.Schedule(d.Until, Event{Kind: KindFault, Fault: FaultOp{
			Kind: faultDSDown, On: false, DS: d.DS,
		}})
	}

	// Schedule churn ops spread across the first half of the scenario.
	spread := w.sc.SettleRounds / 2
	if spread < 10 {
		spread = 10
	}
	for i, op := range w.sc.Churn {
		at := uint64(i+1) * (spread / uint64(len(w.sc.Churn)+1))
		if at == 0 {
			at = 1
		}
		ev := Event{Kind: KindChurn, Churn: op}
		w.s.Schedule(at, ev)
	}

	// Schedule periodic timers. rekey/heartbeat/reconcile are per channel (replica);
	// data is per tenant VNI (the sender picks the best replica per receiver).
	for i, c := range w.clients {
		base := uint64(i) + 1 // stagger by client index
		for v := 0; v < w.sc.VNIs; v++ {
			w.s.Schedule(base+w.dataInterval, Event{Kind: KindTimer, Actor: c.id,
				Timer: TimerData, Env: Envelope{VNI: uint32(v)}})
			for r := 0; r < w.numReplicas; r++ {
				ch := saVNI(uint32(v), r)
				w.s.Schedule(base+w.rekeyInterval, Event{Kind: KindTimer, Actor: c.id,
					Timer: TimerRekey, Env: Envelope{VNI: ch}})
				w.s.Schedule(base+w.heartbeatInterval, Event{Kind: KindTimer, Actor: c.id,
					Timer: TimerHeartbeat, Env: Envelope{VNI: ch}})
				w.s.Schedule(base+w.reconcileInterval, Event{Kind: KindTimer, Actor: c.id,
					Timer: TimerReconcile, Env: Envelope{VNI: ch}})
			}
		}
	}
}

// dispatch handles one event and returns a deterministic trace line.
func (w *world) dispatch(e Event) string {
	switch e.Kind {
	case KindDeliver:
		return w.dispatchDeliver(e)
	case KindTimer:
		return w.dispatchTimer(e)
	case KindFault:
		return w.dispatchFault(e)
	case KindChurn:
		return w.dispatchChurn(e)
	}
	return fmt.Sprintf("%d|unknown|a=%d", e.At, e.Actor)
}

func (w *world) dispatchDeliver(e Event) string {
	a := int(e.Actor)
	if a >= 0 && a < len(w.clients) {
		w.clients[a].onDeliver(e.Env)
		return fmt.Sprintf("%d|deliver|a=%d|vni=%d|type=%s", e.At, e.Actor, e.Env.VNI, e.Env.Type)
	}
	// DS actors
	for _, ds := range w.dss {
		if ds.id == e.Actor {
			ds.handle(e.Env, w.metrics)
			return fmt.Sprintf("%d|deliver|a=%d|vni=%d|type=%s", e.At, e.Actor, e.Env.VNI, e.Env.Type)
		}
	}
	return fmt.Sprintf("%d|deliver|a=%d|vni=%d|type=%s|dropped", e.At, e.Actor, e.Env.VNI, e.Env.Type)
}

func (w *world) dispatchTimer(e Event) string {
	vni := e.Env.VNI
	a := int(e.Actor)
	deadline := w.settleDeadline + w.sc.SettleRounds // timers fire through the settle window

	switch e.Timer {
	case TimerRekey:
		if a >= 0 && a < len(w.clients) {
			w.clients[a].rekey(vni)
		}
		if e.At < deadline {
			w.s.Schedule(e.At+w.rekeyInterval, Event{Kind: KindTimer, Actor: e.Actor,
				Timer: TimerRekey, Env: e.Env})
		}
	case TimerHeartbeat:
		if a >= 0 && a < len(w.clients) {
			w.clients[a].emitHeartbeat(vni)
		}
		if e.At < deadline {
			w.s.Schedule(e.At+w.heartbeatInterval, Event{Kind: KindTimer, Actor: e.Actor,
				Timer: TimerHeartbeat, Env: e.Env})
		}
	case TimerReconcile:
		if a >= 0 && a < len(w.clients) {
			desired := w.desiredSlice(vni)
			w.clients[a].reconcile(vni, desired)
		}
		if e.At < deadline {
			w.s.Schedule(e.At+w.reconcileInterval, Event{Kind: KindTimer, Actor: e.Actor,
				Timer: TimerReconcile, Env: e.Env})
		}
	case TimerData:
		if a >= 0 && a < len(w.clients) {
			w.clients[a].sendData(vni)
		}
		if e.At < deadline {
			w.s.Schedule(e.At+w.dataInterval, Event{Kind: KindTimer, Actor: e.Actor,
				Timer: TimerData, Env: e.Env})
		}
	}
	return fmt.Sprintf("%d|timer|a=%d|vni=%d|t=%d", e.At, e.Actor, vni, e.Timer)
}

func (w *world) dispatchFault(e Event) string {
	w.faults.applyFault(e.Fault)
	detail := "on"
	if !e.Fault.On {
		detail = "off"
	}
	return fmt.Sprintf("%d|fault|kind=%d|%s", e.At, e.Fault.Kind, detail)
}

func (w *world) dispatchChurn(e Event) string {
	op := e.Churn
	tenant := op.VNI
	c := int(op.Client)
	if c < 0 || c >= len(w.clients) {
		return fmt.Sprintf("%d|churn|a=%d|vni=%d|noop", e.At, op.Client, tenant)
	}
	id := w.clients[c].identity

	// A churn applies to BOTH replicas — each replica's committer converges its own
	// group via its own reflector; the two may transiently differ in membership.
	for r := 0; r < w.numReplicas; r++ {
		ch := saVNI(tenant, r)
		if op.Join {
			if w.desired[ch] == nil {
				w.desired[ch] = map[string]bool{}
			}
			if w.intended[ch] == nil {
				w.intended[ch] = map[string]bool{}
			}
			w.desired[ch][id] = true
			w.intended[ch][id] = true
		} else {
			delete(w.desired[ch], id)
			delete(w.intended[ch], id)
		}
		// Trigger a reconcile at the committer (client 0) for this replica.
		w.s.Schedule(w.s.Now()+1, Event{Kind: KindTimer, Actor: w.clients[0].id,
			Timer: TimerReconcile, Env: Envelope{VNI: ch}})
	}
	return fmt.Sprintf("%d|churn|a=%d|vni=%d|join=%v", e.At, op.Client, tenant, op.Join)
}

// desiredSlice returns the desired membership for a channel as a sorted [][]byte.
func (w *world) desiredSlice(ch uint32) [][]byte {
	m := w.desired[ch]
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][]byte, len(keys))
	for i, k := range keys {
		out[i] = []byte(k)
	}
	return out
}

// Run executes one (scenario, seed) deterministically and returns the verdict.
func Run(sc Scenario, seed int64) Result {
	s := NewScheduler(seed)
	metrics := newMetrics()
	faults := newFaultState(sc.Faults)
	bus := newBus(s, faults, metrics)
	checker := newInvariantChecker()
	dir := newKPDirectory()

	nClients := sc.Clients
	dsIDs := []ActorID{ActorID(nClients), ActorID(nClients + 1)}
	suite, ok := cipher.Lookup(sc.Suite)
	if !ok {
		panic(fmt.Sprintf("suite %#x not registered", sc.Suite))
	}

	clients := make([]*Client, nClients)
	for i := 0; i < nClients; i++ {
		id := fmt.Sprintf("client-%d", i)
		signer := makeSigner()
		dir.register(id, signer)
		clients[i] = newClient(ActorID(i), suite, signer, id, bus, s, dir, dsIDs, metrics, checker, sc.W)
		clients[i].mbbDisabled = sc.MBBDisabled
	}
	dss := []*DS{newDS(dsIDs[0], 0, bus, faults), newDS(dsIDs[1], 1, bus, faults)}

	w := &world{
		sc: sc, s: s, bus: bus, faults: faults, metrics: metrics,
		checker: checker, dir: dir, clients: clients, dss: dss, suite: suite,
		intended: map[uint32]map[string]bool{}, desired: map[uint32]map[string]bool{},
	}
	w.bootstrap()

	// Main loop: process until queue empty (settle window is scheduled events).
	var trace []string
	for {
		e, ok := s.Pop()
		if !ok {
			break
		}
		trace = append(trace, w.dispatch(e))
		if s.Now() >= w.settleDeadline && !w.faultsLifted {
			w.faults.liftAll()
			w.faultsLifted = true
		}
	}

	// There are no forks in the dual single-sequencer model (each replica is a true
	// total order); the invariant checker confirms this via Result.Fork staying nil.
	r := checker.Evaluate(clients, w.intended)
	r.Metrics = metrics
	r.Trace = trace
	return r
}
