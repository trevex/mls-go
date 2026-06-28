package sim

import (
	"context"
	"crypto"
	"fmt"
	"sort"
	"time"

	"github.com/trevex/mls-go/ironcore"
	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
)

// numDS is the number of MetalBond reflectors = the number of independent
// replicas per VNI (dual-group pure redundancy, rev 5 §0).
const numDS = 2

// saVNI maps a tenant VNI + replica index to the per-replica channel id used as
// BOTH the MLS GroupID and the ironcore SA derivation VNI, so the two replicas of
// a tenant get distinct group state, distinct SA keys AND distinct SPIs — no
// collision (rev 5 §0).
func saVNI(vni uint32, r int) uint32 { return vni*numDS + uint32(r) }

func replicaOf(ch uint32) int   { return int(ch % numDS) }
func tenantOf(ch uint32) uint32 { return ch / numDS }

// optimisticOrdering is the client-side Ordering adapter: the client commits and
// broadcasts optimistically; the authoritative accept-once decision is made by the
// reflector R_r's OWN register (in ds.go). With a single designated committer per
// replica there are never competing commits, so this is always consistent.
type optimisticOrdering struct{}

func (optimisticOrdering) AcceptCommit(_ context.Context, _ group.GroupID, _ uint64, _ group.CommitRef) (bool, error) {
	return true, nil
}

// vniState is one client's state for one replica channel (one MLS group).
type vniState struct {
	ctrl      *ironcore.Controller
	joined    bool
	joinEpoch uint64
	saCache   map[uint64]ironcore.SA // epoch -> SA (derive-time cache; never re-derive)
	peerEpoch map[ActorID]uint64     // last-known epoch per co-replica member
	heard     map[ActorID]bool       // members we've received a heartbeat from (confirmed live on this replica)

	// committer-side reliable delivery (drop recovery without any fork machinery):
	// the single designated committer caches the head commit + any outstanding
	// Welcomes and resends them until the reflector confirms (echoes) the commit
	// and the joiner reports in. It does not issue a new commit until the head is
	// confirmed and all Welcomes have landed, which keeps each replica a clean
	// single-writer total order.
	outbox         map[uint64][]byte // base -> commit bytes issued by this committer
	confirmed      map[uint64]bool   // base -> reflector echoed it back (landed at R_r)
	hasHead        bool
	headBase       uint64
	pendingWelcome map[string][]byte // joiner identity -> Welcome bytes not yet joined

	catchupReqs map[uint64]int
}

func newVNIState() *vniState {
	return &vniState{
		saCache:        map[uint64]ironcore.SA{},
		peerEpoch:      map[ActorID]uint64{},
		heard:          map[ActorID]bool{},
		outbox:         map[uint64][]byte{},
		confirmed:      map[uint64]bool{},
		pendingWelcome: map[string][]byte{},
		catchupReqs:    map[uint64]int{},
	}
}

// Client is one metalnet host actor. It runs two ironcore.Controllers per tenant
// VNI (one per replica channel saVNI(vni,r)); every host is a member of BOTH
// replicas and installs BOTH replicas' SAs (rev 5 §0).
type Client struct {
	id          ActorID
	suite       cipher.Suite
	signer      crypto.Signer
	identity    string
	vnis        map[uint32]*vniState // keyed by channel = saVNI(vni, r)
	bus         *Bus
	sched       *Scheduler
	dir         *kpDirectory
	dsIDs       []ActorID // dsIDs[r] = reflector R_r
	metrics     *Metrics
	checker     *InvariantChecker
	W                 int  // SA-overlap depth (make-before-break window)
	mbbDisabled       bool // negative control: W=0 + no sender-lag
	encryptHandshakes bool // EncryptedChurn scenario: member handshakes are PrivateMessage
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

// reflectorFor returns the reflector that orders channel ch's replica.
func (c *Client) reflectorFor(ch uint32) ActorID { return c.dsIDs[replicaOf(ch)] }

// foundVNI makes this client the founder of channel ch (epoch-0 group).
func (c *Client) foundVNI(ch uint32) {
	st := newVNIState()
	g := c.dir.newFounderGroup(c.suite, ch, c.identity, c.signer)
	ctrl, err := ironcore.NewController(c.controllerCfg(ch), g)
	if err != nil {
		panic(err)
	}
	st.ctrl, st.joined, st.joinEpoch = ctrl, true, 0
	c.vnis[ch] = st
	c.bus.Subscribe(ch, c.id)
	c.cacheCurrentSA(ch)
}

// prospectiveVNI registers this client as a prospective joiner of channel ch.
func (c *Client) prospectiveVNI(ch uint32) {
	st := newVNIState()
	ctrl, _ := ironcore.NewController(c.controllerCfg(ch), nil)
	st.ctrl = ctrl
	c.vnis[ch] = st
	c.dir.publishKeyPackage(c.suite, ch, c.identity, c.signer)
	c.bus.Subscribe(ch, c.id)
}

func (c *Client) controllerCfg(ch uint32) ironcore.ControllerConfig {
	// ironcore's zero-value HandshakePrivacy is HandshakeEncrypted, so we opt out
	// EXPLICITLY here for non-encrypted scenarios. This keeps the existing
	// scenarios on PublicMessage commits and isolates the plaintext-exposure
	// invariant to EncryptedChurn. Do NOT drop the HandshakePrivacy field below —
	// removing it would silently encrypt all scenario traffic with no test failure.
	hp := ironcore.HandshakePlaintext
	if c.encryptHandshakes {
		hp = ironcore.HandshakeEncrypted
	}
	return ironcore.ControllerConfig{
		VNI:              ch, // channel id drives BOTH GroupID and DeriveSAKeys
		Suite:            c.suite,
		Ordering:         optimisticOrdering{},
		Clock:            fixedClock{},
		Validator:        group.BasicCredentialValidator{},
		Cred:             c.dir.cred(c.identity),
		Signer:           c.signer,
		Lifetime:         maxLifetime(),
		Resolve:          c.dir.resolver(ch),
		HandshakePrivacy: hp,
	}
}

// canCommit gates new commits: the head must be confirmed landed at the reflector
// and no Welcomes may be outstanding. This serializes each replica into a clean
// single-writer stream and keeps an in-flight Welcome valid (the epoch does not
// advance underneath it) until the joiner lands — the only reliability mechanism
// needed in the no-fork model.
func (c *Client) canCommit(ch uint32) bool {
	st := c.vnis[ch]
	if st == nil || !st.joined || !st.ctrl.IsCommitter() {
		return false
	}
	if len(st.pendingWelcome) > 0 {
		return false
	}
	if st.hasHead && !st.confirmed[st.headBase] {
		return false
	}
	return true
}

// reconcile drives membership toward the desired set (committer only).
func (c *Client) reconcile(ch uint32, desired [][]byte) {
	if !c.canCommit(ch) {
		return
	}
	st := c.vnis[ch]
	t0 := time.Now()
	res, err := st.ctrl.Reconcile(ctx(), desired)
	c.metrics.cpu("Reconcile", time.Since(t0))
	if err != nil || !res.Committed {
		return
	}
	c.cacheCurrentSA(ch)
	base := st.ctrl.Epoch() - 1
	c.recordHead(ch, base, res.CommitMsg)
	c.sendCommit(ch, base, res.CommitMsg)
	if len(res.WelcomeMsg) > 0 && len(res.Added) > 0 {
		curEpoch := st.ctrl.Epoch()
		for _, id := range res.Added {
			if aid, ok := actorIDFromIdentity(string(id)); ok && aid != c.id {
				if _, exists := st.peerEpoch[aid]; !exists {
					st.peerEpoch[aid] = curEpoch
				}
			}
			st.pendingWelcome[string(id)] = res.WelcomeMsg
		}
		c.sendWelcome(ch, res.WelcomeMsg, res.Added)
	}
}

// rekey issues an empty PCS Update (committer only).
func (c *Client) rekey(ch uint32) {
	if !c.canCommit(ch) {
		return
	}
	st := c.vnis[ch]
	base := st.ctrl.Epoch()
	t0 := time.Now()
	msg, won, err := st.ctrl.Rekey(ctx())
	c.metrics.cpu("Rekey", time.Since(t0))
	if err != nil || !won || msg == nil {
		return
	}
	c.cacheCurrentSA(ch)
	c.recordHead(ch, base, msg)
	c.sendCommit(ch, base, msg)
}

// recordHead stores the latest committer-issued commit for confirm/resend.
func (c *Client) recordHead(ch uint32, base uint64, msg []byte) {
	st := c.vnis[ch]
	st.outbox[base] = msg
	st.hasHead, st.headBase = true, base
}

// onDeliver dispatches an inbound envelope.
func (c *Client) onDeliver(env Envelope) {
	switch env.Type {
	case MsgCommit:
		c.onCommit(env)
	case MsgWelcome:
		if env.Joiner == c.identity {
			c.onWelcome(env)
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
	// A reflector echo of our own head confirms it landed at R_r.
	if env.Src == c.reflectorFor(env.VNI) {
		if _, ok := st.outbox[env.Base]; ok && contentHash(st.outbox[env.Base]) == env.Hash {
			st.confirmed[env.Base] = true
		}
	}
	if st.ctrl.Epoch() != env.Base {
		return // stale / future commit — first-wins; catch-up handles gaps
	}
	before := c.leafIdentitySet(env.VNI)
	t0 := time.Now()
	err := st.ctrl.HandleCommit(env.Payload)
	c.metrics.cpu("HandleCommit", time.Since(t0))
	switch {
	case err == nil:
		c.cacheCurrentSA(env.VNI)
		c.initPeerEpochForNewMembers(env.VNI, before)
	case isSelfRemoved(err):
		c.leaveVNI(env.VNI)
	}
}

func (c *Client) onWelcome(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || st.joined {
		return
	}
	kp, ip, lp := c.dir.joinerMaterial(env.VNI, c.identity)
	t0 := time.Now()
	err := st.ctrl.JoinViaWelcome(env.Payload, kp, ip, lp)
	c.metrics.cpu("JoinViaWelcome", time.Since(t0))
	if err != nil {
		return // Welcome superseded / not for our epoch; committer will resend
	}
	st.joined = true
	st.joinEpoch = st.ctrl.Epoch()
	c.cacheCurrentSA(env.VNI)
	// Announce our join epoch immediately so senders learn we exist on this replica.
	c.emitHeartbeat(env.VNI)
	// Conservatively seed peerEpoch for existing members at joinEpoch-1 (they may
	// not have processed our Add yet) so a sender does not run ahead of them.
	if st.ctrl.Group() != nil {
		init := st.ctrl.Epoch()
		if init > 0 {
			init--
		}
		for _, leaf := range st.ctrl.Group().ActiveLeaves() {
			cred, _, err2 := st.ctrl.Group().LeafCredential(leaf)
			if err2 != nil {
				continue
			}
			if aid, ok := actorIDFromIdentity(string(cred.Identity)); ok && aid != c.id {
				if _, exists := st.peerEpoch[aid]; !exists {
					st.peerEpoch[aid] = init
				}
			}
		}
	}
}

// onHeartbeat updates peer-epoch tracking and triggers catch-up if behind. When
// a joiner reports in, the committer clears it from the pending-Welcome set.
func (c *Client) onHeartbeat(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || !st.joined {
		return
	}
	st.heard[env.Src] = true
	if env.Base > st.peerEpoch[env.Src] || st.peerEpoch[env.Src] == 0 {
		st.peerEpoch[env.Src] = env.Base
	}
	if id, ok := identityFromActorID(env.Src); ok {
		delete(st.pendingWelcome, id)
	}
	if env.Base > st.ctrl.Epoch() {
		c.requestCatchup(env.VNI, st.ctrl.Epoch())
	}
}

func (c *Client) requestCatchup(ch uint32, from uint64) {
	if st := c.vnis[ch]; st != nil {
		st.catchupReqs[from]++
	}
	c.toReflector(ch, Envelope{VNI: ch, Type: MsgLogRequest, Base: from})
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
		before := c.leafIdentitySet(env.VNI)
		if err := st.ctrl.HandleCommit(r.Bytes); err == nil {
			c.cacheCurrentSA(env.VNI)
			c.initPeerEpochForNewMembers(env.VNI, before)
		} else if isSelfRemoved(err) {
			c.leaveVNI(env.VNI)
			return
		}
	}
}

func (c *Client) leaveVNI(ch uint32) {
	c.bus.Unsubscribe(ch, c.id)
	delete(c.vnis, ch)
}

// sendCommit publishes a commit to this replica's reflector ONLY (no dual-peering;
// replica r is ordered exclusively by R_r).
func (c *Client) sendCommit(ch uint32, base uint64, msg []byte) {
	c.toReflector(ch, Envelope{
		VNI:     ch,
		Type:    MsgCommit,
		Base:    base,
		Payload: msg,
		Hash:    contentHash(msg),
	})
	c.metrics.commitFanout(len(msg), 1)
}

func (c *Client) sendWelcome(ch uint32, welcome []byte, added [][]byte) {
	for _, id := range added {
		c.toReflector(ch, Envelope{
			VNI:     ch,
			Type:    MsgWelcome,
			Joiner:  string(id),
			Payload: welcome,
			Hash:    contentHash(welcome),
		})
	}
}

// toReflector sends env to the single reflector ordering channel ch's replica.
func (c *Client) toReflector(ch uint32, env Envelope) {
	env.Src = c.id
	env.Dst = c.reflectorFor(ch)
	c.bus.Publish(env)
}

// resendUnacked re-delivers the unconfirmed head commit + any outstanding
// Welcomes to the reflector (idempotent: the register de-dups, JoinViaWelcome is
// retried). Driven off the heartbeat timer so it is fully deterministic. This is
// the entire drop/failover recovery story — no external commits, no forks.
func (c *Client) resendUnacked(ch uint32) {
	st := c.vnis[ch]
	if st == nil || !st.joined || !st.ctrl.IsCommitter() {
		return
	}
	if st.hasHead && !st.confirmed[st.headBase] {
		if msg, ok := st.outbox[st.headBase]; ok {
			c.toReflector(ch, Envelope{VNI: ch, Type: MsgCommit, Base: st.headBase,
				Payload: msg, Hash: contentHash(msg)})
			c.metrics.CommitResends++
		}
	}
	for _, id := range sortedStrKeys(st.pendingWelcome) {
		w := st.pendingWelcome[id]
		c.toReflector(ch, Envelope{VNI: ch, Type: MsgWelcome, Joiner: id,
			Payload: w, Hash: contentHash(w)})
	}
}

// ─── data plane: per-replica make-before-break + sender-lag + cross-replica ──────

// actorIDFromIdentity parses "client-N" -> ActorID(N).
func actorIDFromIdentity(identity string) (ActorID, bool) {
	var n int
	if _, err := fmt.Sscanf(identity, "client-%d", &n); err == nil {
		return ActorID(n), true
	}
	return -1, false
}

func identityFromActorID(a ActorID) (string, bool) {
	if a < 0 {
		return "", false
	}
	return fmt.Sprintf("client-%d", int(a)), true
}

func (c *Client) leafIdentitySet(ch uint32) map[string]bool {
	st := c.vnis[ch]
	if st == nil || !st.joined || st.ctrl.Group() == nil {
		return nil
	}
	out := map[string]bool{}
	for _, leaf := range st.ctrl.Group().ActiveLeaves() {
		if cred, _, err := st.ctrl.Group().LeafCredential(leaf); err == nil {
			out[string(cred.Identity)] = true
		}
	}
	return out
}

// replicaMembers returns the actor set in this client's view of channel ch.
func (c *Client) replicaMembers(ch uint32) map[ActorID]bool {
	out := map[ActorID]bool{}
	for id := range c.leafIdentitySet(ch) {
		if aid, ok := actorIDFromIdentity(id); ok {
			out[aid] = true
		}
	}
	return out
}

// initPeerEpochForNewMembers seeds peerEpoch=currentEpoch for members added by the
// commit just applied (they joined at this epoch). Pre-existing members are left
// untouched (they may still be behind).
func (c *Client) initPeerEpochForNewMembers(ch uint32, beforeLeaves map[string]bool) {
	st := c.vnis[ch]
	if st == nil || !st.joined || st.ctrl.Group() == nil {
		return
	}
	cur := st.ctrl.Epoch()
	for _, leaf := range st.ctrl.Group().ActiveLeaves() {
		cred, _, err := st.ctrl.Group().LeafCredential(leaf)
		if err != nil {
			continue
		}
		id := string(cred.Identity)
		if beforeLeaves[id] {
			continue
		}
		if aid, ok := actorIDFromIdentity(id); ok && aid != c.id {
			if _, exists := st.peerEpoch[aid]; !exists {
				st.peerEpoch[aid] = cur
			}
		}
	}
}

// cacheCurrentSA derives + stores the current-epoch SA (derive-time cache; past
// epochs cannot be re-derived — forward secrecy).
func (c *Client) cacheCurrentSA(ch uint32) {
	st := c.vnis[ch]
	if st == nil || !st.joined {
		return
	}
	sa, err := st.ctrl.CurrentSA()
	if err != nil {
		return
	}
	st.saCache[sa.Epoch] = sa
	c.trimSAs(ch)
	c.metrics.observeOverlap(len(st.saCache))
}

// trimSAs enforces the per-replica overlap window [cur-W .. cur].
func (c *Client) trimSAs(ch uint32) {
	st := c.vnis[ch]
	cur := st.ctrl.Epoch()
	w := uint64(c.effectiveW())
	for _, e := range sortedEpochs(st.saCache) {
		if cur >= w && e < cur-w {
			delete(st.saCache, e)
		}
	}
}

func (c *Client) effectiveW() int {
	if c.mbbDisabled {
		return 0
	}
	return c.W
}

// sendEpoch is the per-replica sender-lag: the latest epoch believed group-wide
// converged = min over self + all known co-replica members. With mbbDisabled it
// sends under the client's own current epoch (negative control).
func (c *Client) sendEpoch(ch uint32) uint64 {
	st := c.vnis[ch]
	cur := st.ctrl.Epoch()
	if c.mbbDisabled {
		return cur
	}
	mn := cur
	for _, a := range sortedActorEpochs(st.peerEpoch) {
		if st.peerEpoch[a] < mn {
			mn = st.peerEpoch[a]
		}
	}
	return mn
}

// dataCand is one usable replica candidate for a sender at this instant.
type dataCand struct {
	ch      uint32
	se      uint64
	spi     uint32
	ok      bool
	members map[ActorID]bool
	heard   map[ActorID]bool
}

// sendData emits tenant data packets. For each receiver it picks SOME replica
// where the sender holds a send-SA and the receiver is a (preferably heard-from)
// member — so even if one replica is stalled/down/partitioned for that receiver,
// the other carries the packet (the redundancy headline, rev 5 §0 inv. 2).
func (c *Client) sendData(tenant uint32) {
	cands := make([]*dataCand, numDS)
	recv := map[ActorID]bool{}
	for r := 0; r < numDS; r++ {
		ch := saVNI(tenant, r)
		st := c.vnis[ch]
		if st == nil || !st.joined {
			continue
		}
		se := c.sendEpoch(ch)
		sa, ok := st.saCache[se]
		cd := &dataCand{ch: ch, se: se, spi: sa.SPI, ok: ok,
			members: c.replicaMembers(ch), heard: st.heard}
		cands[r] = cd
		for a := range cd.members {
			recv[a] = true
		}
	}
	for _, rcv := range sortedActorSet(recv) {
		if rcv == c.id {
			continue
		}
		c.sendToReceiver(tenant, rcv, cands)
	}
}

func (c *Client) sendToReceiver(tenant uint32, rcv ActorID, cands []*dataCand) {
	// Pass 1: prefer a replica where we've heard a heartbeat from the receiver
	// (confirmed live + converged there). Pass 2: any replica it's a member of.
	for _, requireHeard := range []bool{true, false} {
		for r := 0; r < numDS; r++ {
			cd := cands[r]
			if cd == nil || !cd.ok || !cd.members[rcv] {
				continue
			}
			if requireHeard && !cd.heard[rcv] {
				continue
			}
			st := c.vnis[cd.ch]
			c.metrics.observeSendLag(st.ctrl.Epoch() - cd.se)
			c.bus.Publish(Envelope{VNI: cd.ch, Type: MsgData, Src: c.id, Dst: rcv,
				Base: cd.se, SPI: cd.spi})
			c.metrics.DataSent++
			return
		}
	}
}

// onData is the inv. 2 (zero key-loss) check point: a delivered (non-dropped)
// packet MUST be decryptable by the receiver under some replica SA it holds.
func (c *Client) onData(env Envelope) {
	st := c.vnis[env.VNI]
	if st == nil || !st.joined {
		return // not a live member of this replica ⇒ the packet is not "for" us
	}
	if env.Base < st.joinEpoch {
		return // pre-join epoch: we never held that key (forward secrecy, not a loss)
	}
	for _, e := range sortedEpochs(st.saCache) {
		if st.saCache[e].SPI == env.SPI {
			c.metrics.DataDecryptable++
			return
		}
	}
	c.checker.packetLoss(uint64(env.VNI), env.Base, st.ctrl.Epoch(), c.sched.Now())
}

// emitHeartbeat advertises our current epoch on channel ch and (committer only)
// resends any unconfirmed head commit / outstanding Welcomes.
func (c *Client) emitHeartbeat(ch uint32) {
	st := c.vnis[ch]
	if st == nil || !st.joined {
		return
	}
	c.bus.Publish(Envelope{
		VNI:  ch,
		Type: MsgHeartbeat,
		Src:  c.id,
		Dst:  Broadcast,
		Base: st.ctrl.Epoch(),
	})
	c.resendUnacked(ch)
}

func sortedActorSet(m map[ActorID]bool) []ActorID {
	out := make([]ActorID, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedStrKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
