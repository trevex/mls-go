package sim

import (
	"context"
	"crypto"
	"sort"
	"time"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/ironcore/sequencer"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

// optimisticOrdering is the AP "no register" adapter (design spec §7 / N1).
type optimisticOrdering struct{}

func (optimisticOrdering) AcceptCommit(_ context.Context, _ group.GroupID, _ uint64, _ group.CommitRef) (bool, error) {
	return true, nil
}

// vniState is one client's per-VNI state.
type vniState struct {
	ctrl      *ironcore.Controller
	joined    bool
	seen      map[string][][]byte    // vniKey(vni,base) -> competing commit refs
	giByRef   map[string][]byte      // ref(hash) -> GroupInfo bytes (for recovery)
	applied   map[uint64][]byte      // base -> the ref this client applied at base
	recovered map[uint64]bool        // base -> already recovered
	saCache   map[uint64]ironcore.SA // epoch -> SA (derive-time cache; never re-derive)
	peerEpoch map[ActorID]uint64     // last heartbeat epoch per co-VNI member
}

func newVNIState() *vniState {
	return &vniState{
		seen:      map[string][][]byte{},
		giByRef:   map[string][]byte{},
		applied:   map[uint64][]byte{},
		recovered: map[uint64]bool{},
		saCache:   map[uint64]ironcore.SA{},
		peerEpoch: map[ActorID]uint64{},
	}
}

// Client is one metalnet host actor (design spec §3.3).
type Client struct {
	id          ActorID
	suite       cipher.Suite
	signer      crypto.Signer
	identity    string
	vnis        map[uint32]*vniState
	bus         *Bus
	sched       *Scheduler
	dir         *kpDirectory
	dsIDs       []ActorID
	metrics     *Metrics
	checker     *InvariantChecker
	W           int  // SA-overlap depth
	mbbDisabled bool // negative control: W=0 + no sender-lag
}

func newClient(id ActorID, suite cipher.Suite, signer crypto.Signer, identity string,
	bus *Bus, s *Scheduler, dir *kpDirectory, dsIDs []ActorID, m *Metrics, ck *InvariantChecker, W int) *Client {
	return &Client{
		id: id, suite: suite, signer: signer, identity: identity,
		vnis: map[uint32]*vniState{}, bus: bus, sched: s, dir: dir,
		dsIDs: dsIDs, metrics: m, checker: ck, W: W,
	}
}

func ctx() context.Context { return context.Background() }

// foundVNI makes this client the founder of vni (epoch 0 group).
func (c *Client) foundVNI(vni uint32) {
	st := newVNIState()
	g := c.dir.newFounderGroup(c.suite, vni, c.identity, c.signer)
	cfg := c.controllerCfg(vni)
	ctrl, err := ironcore.NewController(cfg, g)
	if err != nil {
		panic(err)
	}
	st.ctrl, st.joined = ctrl, true
	c.vnis[vni] = st
	c.bus.Subscribe(vni, c.id)
	c.cacheCurrentSA(vni)
}

// prospectiveVNI registers this client as a prospective joiner of vni.
func (c *Client) prospectiveVNI(vni uint32) {
	st := newVNIState()
	cfg := c.controllerCfg(vni)
	ctrl, _ := ironcore.NewController(cfg, nil) // g=nil until welcome
	st.ctrl = ctrl
	c.vnis[vni] = st
	c.dir.publishKeyPackage(c.suite, vni, c.identity, c.signer)
	c.bus.Subscribe(vni, c.id)
}

func (c *Client) controllerCfg(vni uint32) ironcore.ControllerConfig {
	return ironcore.ControllerConfig{
		VNI:       vni,
		Suite:     c.suite,
		Ordering:  optimisticOrdering{},
		Clock:     fixedClock{},
		Validator: group.BasicCredentialValidator{},
		Cred:      c.dir.cred(c.identity),
		Signer:    c.signer,
		Lifetime:  maxLifetime(),
		Resolve:   c.dir.resolver(vni),
	}
}

// reconcile is invoked on the TimerReconcile: the committer drives the desired
// membership set toward reality (design spec §3.3 / §10.3).
func (c *Client) reconcile(vni uint32, desired [][]byte) {
	st := c.vnis[vni]
	if st == nil || !st.joined || !st.ctrl.IsCommitter() {
		return
	}
	t0 := time.Now()
	res, err := st.ctrl.Reconcile(ctx(), desired)
	c.metrics.cpu("Reconcile", time.Since(t0))
	if err != nil && !isLostRace(err) {
		return
	}
	if !res.Committed {
		return
	}
	c.cacheCurrentSA(vni)
	c.broadcastCommit(vni, st.ctrl.Epoch()-1, false, res.CommitMsg)
	if len(res.WelcomeMsg) > 0 && len(res.Added) > 0 {
		for _, id := range res.Added {
			c.toDS(Envelope{
				VNI:     vni,
				Type:    MsgWelcome,
				Joiner:  string(id),
				Payload: res.WelcomeMsg,
				Hash:    contentHash(res.WelcomeMsg),
			})
		}
	}
}

// rekey is invoked on the TimerRekey: committer issues an empty PCS Update.
func (c *Client) rekey(vni uint32) {
	st := c.vnis[vni]
	if st == nil || !st.joined || !st.ctrl.IsCommitter() {
		return
	}
	base := st.ctrl.Epoch()
	t0 := time.Now()
	msg, won, err := st.ctrl.Rekey(ctx())
	c.metrics.cpu("Rekey", time.Since(t0))
	if err != nil || !won || msg == nil {
		return
	}
	c.cacheCurrentSA(vni)
	c.broadcastCommit(vni, base, false, msg)
}

// onDeliver dispatches an inbound envelope.
func (c *Client) onDeliver(env Envelope) {
	st := c.vnis[env.VNI]
	switch env.Type {
	case MsgCommit:
		c.onCommit(env)
	case MsgWelcome:
		if env.Joiner == c.identity && st != nil && !st.joined {
			c.onWelcome(env)
		}
	case MsgGroupInfo:
		if st != nil {
			st.giByRef[env.Hash] = env.Payload
		}
	case MsgHeartbeat:
		c.onHeartbeat(env)
	case MsgLogReply:
		c.onLogReply(env)
	case MsgData:
		c.onData(env)
	}
}

func (c *Client) onCommit(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || !st.joined {
		return
	}
	key := vniKey(env.VNI, env.Base)
	for _, r := range st.seen[key] {
		if string(r) == env.Hash {
			goto resolve // already seen; still attempt fork-resolve
		}
	}
	st.seen[key] = append(st.seen[key], []byte(env.Hash))
	if st.ctrl.Epoch() == env.Base {
		t0 := time.Now()
		err := st.ctrl.HandleCommit(env.Payload)
		c.metrics.cpu("HandleCommit", time.Since(t0))
		switch {
		case err == nil:
			st.applied[env.Base] = []byte(env.Hash)
			c.cacheCurrentSA(env.VNI)
			c.reportAuth(env.VNI)
		case isSelfRemoved(err):
			c.leaveVNI(env.VNI)
			return
		}
	}
resolve:
	c.forkResolve(env.VNI, env.Base) // Task 7
}

func (c *Client) onWelcome(env Envelope) {
	st := c.vnis[env.VNI]
	kp, ip, lp := c.dir.joinerMaterial(env.VNI, c.identity)
	t0 := time.Now()
	err := st.ctrl.JoinViaWelcome(env.Payload, kp, ip, lp)
	c.metrics.cpu("JoinViaWelcome", time.Since(t0))
	if err != nil {
		return // Welcome not addressed to our epoch / superseded; will catch up
	}
	st.joined = true
	c.cacheCurrentSA(env.VNI)
	c.reportAuth(env.VNI)
}

// onHeartbeat updates peer epoch tracking and triggers catch-up if behind.
func (c *Client) onHeartbeat(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || !st.joined {
		return
	}
	st.peerEpoch[env.Src] = env.Base
	if env.Base > st.ctrl.Epoch() {
		c.requestCatchup(env.VNI, st.ctrl.Epoch())
	}
}

func (c *Client) requestCatchup(vni uint32, from uint64) {
	c.toDS(Envelope{VNI: vni, Type: MsgLogRequest, Base: from})
	c.metrics.CatchupRequests++
}

func (c *Client) onLogReply(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || !st.joined {
		return
	}
	recs := append([]CommitRecord(nil), env.Records...)
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Base < recs[j].Base })
	for _, r := range recs {
		if st.ctrl.Epoch() != r.Base {
			continue
		}
		key := vniKey(env.VNI, r.Base)
		st.seen[key] = append(st.seen[key], []byte(r.Hash))
		if err := st.ctrl.HandleCommit(r.Bytes); err == nil {
			st.applied[r.Base] = []byte(r.Hash)
			c.cacheCurrentSA(env.VNI)
			c.reportAuth(env.VNI)
		}
	}
	// fallback: still behind and no usable log ⇒ external-commit recovery
	if hb := c.maxPeerEpoch(env.VNI); hb > st.ctrl.Epoch() {
		c.recoverViaLatestGI(env.VNI)
	}
}

func (c *Client) reportAuth(vni uint32) {
	st := c.vnis[vni]
	c.checker.reportAuth(vni, st.ctrl.Epoch(), st.ctrl.Group().EpochAuthenticator())
}

func (c *Client) maxPeerEpoch(vni uint32) uint64 {
	st := c.vnis[vni]
	var mx uint64
	for _, a := range sortedActorEpochs(st.peerEpoch) {
		if st.peerEpoch[a] > mx {
			mx = st.peerEpoch[a]
		}
	}
	return mx
}

func (c *Client) leaveVNI(vni uint32) {
	c.bus.Unsubscribe(vni, c.id)
	delete(c.vnis, vni)
}

// broadcastCommit publishes a commit to BOTH reflectors (dual-peering).
func (c *Client) broadcastCommit(vni uint32, base uint64, external bool, msg []byte) {
	env := Envelope{
		VNI:      vni,
		Type:     MsgCommit,
		Base:     base,
		External: external,
		Payload:  msg,
		Hash:     contentHash(msg),
	}
	c.toDS(env) // toDS publishes directly to each DS; do not double-wrap in bus.Publish
	c.metrics.commitFanout(vni, len(msg), len(c.dsIDs))
	// publish our GroupInfo too (for recovery / external join)
	if st := c.vnis[vni]; st != nil && st.joined {
		if gi, err := st.ctrl.PublishGroupInfo(); err == nil {
			if gb, err := gi.MarshalMLS(); err == nil {
				giEnv := Envelope{
					VNI:     vni,
					Type:    MsgGroupInfo,
					Base:    st.ctrl.Epoch(),
					Payload: gb,
					Hash:    contentHash(msg), // keyed by the commit hash → fetchGI
				}
				c.toDS(giEnv)
				st.giByRef[contentHash(msg)] = gb
			}
		}
	}
}

// toDS sends env to EVERY configured DS reflector (dual-peering). It does NOT
// return a meaningful envelope; callers must NOT wrap it in bus.Publish.
func (c *Client) toDS(env Envelope) Envelope {
	env.Src = c.id
	for _, ds := range c.dsIDs {
		e := env
		e.Dst = ds
		c.bus.Publish(e)
	}
	return env
}

// ─── Task 7: fork detection + resolution + recovery ──────────────────────────

// forkResolve runs the §3.3 / N3 resolution glue for a contested (vni, base).
func (c *Client) forkResolve(vni uint32, base uint64) {
	st := c.vnis[vni]
	if st == nil || !st.joined {
		return
	}
	key := vniKey(vni, base)
	refs := dedupRefs(st.seen[key])
	if len(refs) < 2 {
		return
	}
	c.checker.markDivergence(vni, base)
	applied, ok := st.applied[base]
	if !ok || st.recovered[base] {
		return
	}
	canon := sequencer.CanonicalCommit(c.suite, toGroupRefs(refs))
	if string(canon) == string(applied) {
		return // already on the canonical branch
	}
	// Off-canonical: recover to the canonical branch via external commit.
	fetchGI := func(ref group.CommitRef) (*group.GroupInfo, error) {
		gb := st.giByRef[string(ref)]
		if gb == nil {
			return nil, errNoGI
		}
		var gi group.GroupInfo
		if err := gi.UnmarshalMLS(gb); err != nil {
			return nil, err
		}
		return &gi, nil
	}
	t0 := time.Now()
	recMsg, err := st.ctrl.AutoRecover(ctx(), toGroupRefs(refs), fetchGI)
	c.metrics.cpu("AutoRecover", time.Since(t0))
	if err != nil {
		return // target GI not yet available; retried as more GroupInfos arrive
	}
	st.recovered[base] = true
	c.cacheCurrentSA(vni)
	c.reportAuth(vni)
	c.metrics.Recoveries++
	c.metrics.LostRekeys++ // the loser's branch rekey is discarded (design spec §3.6)
	// broadcast the recovery (external) commit; its base is the canonical epoch.
	newBase := st.ctrl.Epoch() - 1
	st.applied[newBase] = []byte(contentHash(recMsg))
	c.broadcastCommit(vni, newBase, true, recMsg)
}

// recoverViaLatestGI is the catch-up fallback (partition / no usable log).
func (c *Client) recoverViaLatestGI(vni uint32) {
	st := c.vnis[vni]
	// pick any cached GroupInfo whose epoch > ours as the recovery target
	var best []byte
	for _, ref := range sortedRefKeys(st.giByRef) {
		best = st.giByRef[ref]
	}
	if best == nil {
		return
	}
	var gi group.GroupInfo
	if gi.UnmarshalMLS(best) != nil {
		return
	}
	vg := ironcore.NewVNIGroup(vni, st.ctrl.Group())
	refs := []group.CommitRef{group.CommitRef(c.suite.Hash(best))}
	st.giByRef[string(refs[0])] = best
	fetchGI := func(group.CommitRef) (*group.GroupInfo, error) { return &gi, nil }
	recMsg, err := ironcore.RecoverViaExternalCommit(ctx(), vg, c.suite, refs, fetchGI,
		optimisticOrdering{}, c.dir.cred(c.identity), c.signer, maxLifetime())
	if err != nil {
		return
	}
	c.cacheCurrentSA(vni)
	c.reportAuth(vni)
	c.metrics.Recoveries++
	c.broadcastCommit(vni, st.ctrl.Epoch()-1, true, recMsg)
}

// ─── stubs: replaced in Task 8 ────────────────────────────────────────────────

// cacheCurrentSA is fully implemented in Task 8.
func (c *Client) cacheCurrentSA(_ uint32) {}

// trimSAs is fully implemented in Task 8.
func (c *Client) trimSAs(_ uint32) {}

// effectiveW is fully implemented in Task 8.
func (c *Client) effectiveW() int {
	if c.mbbDisabled {
		return 0
	}
	return c.W
}

// sendEpoch is fully implemented in Task 8.
func (c *Client) sendEpoch(vni uint32) uint64 {
	st := c.vnis[vni]
	if st == nil {
		return 0
	}
	return st.ctrl.Epoch()
}

// sendData is fully implemented in Task 8.
func (c *Client) sendData(_ uint32) {}

// onData is fully implemented in Task 8.
func (c *Client) onData(_ Envelope) {}

// emitHeartbeat is fully implemented in Task 8.
func (c *Client) emitHeartbeat(vni uint32) {
	st := c.vnis[vni]
	if st == nil || !st.joined {
		return
	}
	c.bus.Publish(Envelope{
		VNI:  vni,
		Type: MsgHeartbeat,
		Src:  c.id,
		Dst:  Broadcast,
		Base: st.ctrl.Epoch(),
	})
}
