package ironcore

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/framing"
	"github.com/trevex/mls-go/mls/group"
	"github.com/trevex/mls-go/mls/tree"
)

// ─── sentinels ────────────────────────────────────────────────────────────────

var (
	// ErrSelfRemoved is returned by HandleCommit when the inbound commit removes
	// this node's own leaf — the node has left the group (design spec §10.3 Leave).
	ErrSelfRemoved = errors.New("ironcore: controller self-removed from group")

	// ErrLostRace is returned by Reconcile/Rekey when the optimistic commit was
	// rejected by the sequencer (another committer won the epoch slot). The caller
	// should AutoRecover onto the canonical branch.
	ErrLostRace = errors.New("ironcore: commit lost the linearization race; AutoRecover")

	// ErrJoinSuperseded is returned by JoinViaExternalCommit when the external
	// commit slot was already decided. Caller re-fetches the decided GroupInfo and
	// retries.
	ErrJoinSuperseded = errors.New("ironcore: external-commit join superseded; refetch GroupInfo")

	// ErrNoGroup is returned when a method requires an active group state but the
	// controller was constructed with g=nil and no join has been performed yet.
	ErrNoGroup = errors.New("ironcore: controller has no group state")
)

// ─── public types ─────────────────────────────────────────────────────────────

// KeyPackageResolver resolves a desired member identity to its published
// KeyPackage MLSMessage bytes (control-plane published out-of-band, §10.3).
// ok=false ⇒ no KeyPackage available yet; the identity is reported Pending.
type KeyPackageResolver func(identity []byte) (kpMsg []byte, ok bool)

// HandshakePrivacy selects how a VNI frames its members' outbound handshakes.
// The zero value is HandshakeEncrypted — the default — so a reflector relaying a
// member commit/proposal sees only ciphertext. External-commit recovery is
// always PublicMessage regardless (RFC 9420 §12.4.3).
type HandshakePrivacy int

const (
	HandshakeEncrypted HandshakePrivacy = iota // default: member handshakes are PrivateMessage
	HandshakePlaintext                         // member handshakes are PublicMessage
)

// ControllerConfig configures one VNI's membership controller.
type ControllerConfig struct {
	VNI      uint32
	Suite    cipher.Suite
	Ordering group.Ordering            // the single linearization point
	Clock    group.Clock               // injectable; the controller never reads wall-clock
	Validator group.CredentialValidator // AS: maps a leaf credential → verified identity
	Cred     tree.Credential           // this node's own credential
	Signer   crypto.Signer             // this node's own signing key
	Lifetime tree.Lifetime             // KeyPackage lifetime for our external-commit/join leaves
	Resolve  KeyPackageResolver        // resolves desired identities → published KeyPackages

	// HandshakePrivacy selects PrivateMessage (default) vs PublicMessage framing
	// for this VNI's member handshakes. Zero value = HandshakeEncrypted.
	HandshakePrivacy HandshakePrivacy
}

// ReconcileResult reports what one Reconcile did.
type ReconcileResult struct {
	Committed  bool     // this node issued a commit
	Won        bool     // the sequencer accepted it (false ⇒ ErrLostRace; AutoRecover)
	Added      [][]byte // identities Added
	Removed    []uint32 // leaves Removed
	Pending    [][]byte // desired identities with no published KeyPackage yet
	CommitMsg  []byte   // broadcast to members when Committed
	WelcomeMsg []byte   // send to Added members when len(Added) > 0
}

// Controller orchestrates one VNI's MLS group over the operational lifecycle
// (design spec §10.3). It is NOT safe for concurrent use; serialize calls per
// Controller (mirrors *group.Group). It spawns no goroutines and reads no
// wall-clock — Rekey/Reconcile are triggers the caller schedules.
type Controller struct {
	cfg      ControllerConfig
	g        *group.Group
	groupID  group.GroupID
	suite    cipher.Suite
	ordering group.Ordering
	curSA    SA
	prevSA   SA
	hasPrev  bool
}

// NewController creates a Controller. If g is non-nil (founder/already-joined),
// it derives the initial current SA. If g is nil (prospective joiner), the SA is
// derived later inside JoinViaWelcome or JoinViaExternalCommit.
func NewController(cfg ControllerConfig, g *group.Group) (*Controller, error) {
	c := &Controller{
		cfg:      cfg,
		g:        g,
		groupID:  GroupID(cfg.VNI),
		suite:    cfg.Suite,
		ordering: cfg.Ordering,
	}
	if g != nil {
		c.applyHandshakePrivacy()
		if err := c.deriveCur(); err != nil {
			return nil, fmt.Errorf("ironcore: NewController: deriveCur: %w", err)
		}
	}
	return c, nil
}

// Group returns the underlying *group.Group (nil if not yet joined).
func (c *Controller) Group() *group.Group { return c.g }

// Epoch returns the current MLS epoch (0 if not yet joined).
func (c *Controller) Epoch() uint64 {
	if c.g == nil {
		return 0
	}
	return c.g.Epoch()
}

// IsCommitter reports whether this node is the designated committer for the
// current epoch: true iff this node's own leaf index equals the lowest active
// leaf in the ratchet tree (design spec §10.3). Returns false if not yet joined.
func (c *Controller) IsCommitter() bool {
	if c.g == nil {
		return false
	}
	leaves := c.g.ActiveLeaves()
	if len(leaves) == 0 {
		return false
	}
	return c.g.OwnLeaf() == leaves[0]
}

// CurrentSA returns the current-epoch SA (the one the data plane installs).
// Returns ErrNoGroup if the controller has no group state yet.
func (c *Controller) CurrentSA() (SA, error) {
	if c.g == nil {
		return SA{}, ErrNoGroup
	}
	return c.curSA, nil
}

// PreviousSA returns the immediately-prior epoch's SA for the make-before-break
// overlap window (design spec §10.4). ok=false only at the very first epoch or
// before any join.
func (c *Controller) PreviousSA() (SA, bool) {
	return c.prevSA, c.hasPrev
}

// JoinViaWelcome processes a Welcome and adopts the new group state.
// Called by a node that was Added by the committer's Reconcile commit.
func (c *Controller) JoinViaWelcome(welcomeMsg, kpMsg, initPriv, leafPriv []byte) error {
	g, err := group.JoinFromWelcome(c.suite, welcomeMsg, group.JoinOptions{
		KeyPackage:     kpMsg,
		InitPriv:       initPriv,
		EncryptionPriv: leafPriv,
		Signer:         c.cfg.Signer,
		ExternalPSKs:   map[string][]byte{},
	})
	if err != nil {
		return fmt.Errorf("ironcore: JoinViaWelcome: %w", err)
	}
	c.g = g
	c.applyHandshakePrivacy()
	if err := c.deriveCur(); err != nil {
		return fmt.Errorf("ironcore: JoinViaWelcome: deriveCur: %w", err)
	}
	return nil
}

// JoinViaExternalCommit lets a node join without a Welcome using an external
// commit against the sequencer's latest signed GroupInfo. Returns ErrJoinSuperseded
// if the slot was already decided by a different commit.
func (c *Controller) JoinViaExternalCommit(ctx context.Context, gi *group.GroupInfo) ([]byte, error) {
	if gi == nil {
		return nil, fmt.Errorf("ironcore: JoinViaExternalCommit: GroupInfo is nil")
	}
	newGroup, commitMsg, err := group.ExternalCommit(c.suite, *gi, c.cfg.Cred, c.cfg.Signer, c.cfg.Lifetime)
	if err != nil {
		return nil, fmt.Errorf("ironcore: JoinViaExternalCommit: ExternalCommit: %w", err)
	}
	ref := group.CommitRef(c.suite.Hash(commitMsg))
	ok, err := c.ordering.AcceptCommit(ctx, c.groupID, gi.GroupContext.Epoch, ref)
	if err != nil {
		return nil, fmt.Errorf("ironcore: JoinViaExternalCommit: AcceptCommit: %w", err)
	}
	if !ok {
		return nil, ErrJoinSuperseded
	}
	c.g = newGroup
	c.applyHandshakePrivacy()
	if err := c.deriveCur(); err != nil {
		return nil, fmt.Errorf("ironcore: JoinViaExternalCommit: deriveCur: %w", err)
	}
	return commitMsg, nil
}

// PublishGroupInfo builds a signed GroupInfo for the current epoch (carrying
// ratchet_tree + external_pub extensions) for external joins and fork recovery.
func (c *Controller) PublishGroupInfo() (*group.GroupInfo, error) {
	if c.g == nil {
		return nil, ErrNoGroup
	}
	return c.g.PublishGroupInfo()
}

// HandleCommit processes an inbound commit (member or external) and advances
// the epoch. Returns ErrSelfRemoved if the commit removes this node's own leaf.
func (c *Controller) HandleCommit(commitMsg []byte) error {
	if c.g == nil {
		return ErrNoGroup
	}
	if c.commitRemovesSelf(commitMsg) {
		return ErrSelfRemoved
	}
	if err := c.g.ProcessCommit(nil, commitMsg); err != nil {
		return fmt.Errorf("ironcore: HandleCommit: ProcessCommit: %w", err)
	}
	return c.rotateSA()
}

// Rekey issues an empty path-only commit (periodic PCS, design spec §10.3).
// Only the designated committer issues a real commit; a non-committer returns
// (nil, false, nil) as a no-op.
func (c *Controller) Rekey(ctx context.Context) (commitMsg []byte, won bool, err error) {
	if c.g == nil {
		return nil, false, ErrNoGroup
	}
	if !c.IsCommitter() {
		return nil, false, nil
	}
	msg, _, w, err := c.commitAndOrder(ctx, nil)
	return msg, w, err
}

// Reconcile diffs the desired identity set against the current group membership
// and issues an Add/Remove commit to converge. Only the designated committer
// issues a real commit; non-committers return a no-op ReconcileResult.
func (c *Controller) Reconcile(ctx context.Context, desired [][]byte) (ReconcileResult, error) {
	if c.g == nil {
		return ReconcileResult{}, ErrNoGroup
	}
	if c.cfg.Validator == nil {
		return ReconcileResult{}, fmt.Errorf("ironcore: Reconcile: no CredentialValidator in config")
	}

	// Step 1: build identity→leaf map for current members.
	idToLeaf, err := c.identityToLeaf()
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("ironcore: Reconcile: identityToLeaf: %w", err)
	}

	// Step 2: compute remove set and add set.
	desiredSet := make(map[string]struct{}, len(desired))
	for _, id := range desired {
		desiredSet[string(id)] = struct{}{}
	}

	removeSet := map[uint32]struct{}{} // leaves to remove
	for id, leaf := range idToLeaf {
		if _, ok := desiredSet[id]; !ok {
			removeSet[leaf] = struct{}{}
		}
	}

	var addIdents [][]byte // identities to add
	for _, id := range desired {
		if _, ok := idToLeaf[string(id)]; !ok {
			addIdents = append(addIdents, id)
		}
	}

	// Step 3: entitlement — determine the committer-elect.
	leaves := c.g.ActiveLeaves()
	committer := uint32(0)
	if len(leaves) > 0 {
		committer = leaves[0]
	}
	// Handover: if the current lowest leaf is being removed, the committer-elect
	// is the lowest surviving leaf (first ActiveLeaves() element not in removeSet).
	if _, removed := removeSet[committer]; removed {
		committer = ^uint32(0) // sentinel: no committer found yet
		for _, l := range leaves {
			if _, removing := removeSet[l]; !removing {
				committer = l
				break
			}
		}
	}

	// Step 4: delete our own leaf from removeSet (§12.1.3: cannot self-remove).
	delete(removeSet, c.g.OwnLeaf())

	// Not the committer — return no-op.
	if c.g.OwnLeaf() != committer {
		return ReconcileResult{Committed: false}, nil
	}

	// Step 5: build by-value proposals (removes first, then adds).
	// Sort removes for determinism.
	var proposals []group.Proposal
	var removedLeaves []uint32
	for leaf := range removeSet {
		removedLeaves = append(removedLeaves, leaf)
	}
	sortUint32(removedLeaves)
	for _, leaf := range removedLeaves {
		proposals = append(proposals, group.ProposeRemove(leaf))
	}

	var addedIdents [][]byte
	var pending [][]byte
	for _, id := range addIdents {
		if c.cfg.Resolve == nil {
			pending = append(pending, id)
			continue
		}
		kpMsg, ok := c.cfg.Resolve(id)
		if !ok {
			pending = append(pending, id)
			continue
		}
		kp, err := group.DecodeKeyPackageMessage(kpMsg)
		if err != nil {
			return ReconcileResult{}, fmt.Errorf("ironcore: Reconcile: decode KP for %q: %w", id, err)
		}
		proposals = append(proposals, group.ProposeAdd(kp))
		addedIdents = append(addedIdents, id)
	}

	// If no proposals, return a no-op (nothing to change).
	if len(proposals) == 0 && len(pending) == 0 {
		return ReconcileResult{Committed: false}, nil
	}
	if len(proposals) == 0 {
		// Only pending identities — nothing to commit.
		return ReconcileResult{Committed: false, Pending: pending}, nil
	}

	// Step 6: commit + order.
	commitMsg, welcomeMsg, won, err := c.commitAndOrder(ctx, proposals)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("ironcore: Reconcile: commitAndOrder: %w", err)
	}

	result := ReconcileResult{
		Committed:  true,
		Won:        won,
		Added:      addedIdents,
		Removed:    removedLeaves,
		Pending:    pending,
		CommitMsg:  commitMsg,
		WelcomeMsg: welcomeMsg,
	}
	if !won {
		// Return ErrLostRace so callers can errors.Is-check, but also return the
		// result (Won=false, with commitMsg) per the API contract.
		return result, ErrLostRace
	}
	return result, nil
}

// AutoRecover re-converges a stale/losing VNIGroup onto the canonical branch
// after a fork (design spec §5.6). It delegates to RecoverViaExternalCommit.
func (c *Controller) AutoRecover(ctx context.Context, candidates []group.CommitRef, fetchGI func(group.CommitRef) (*group.GroupInfo, error)) ([]byte, error) {
	if c.g == nil {
		return nil, ErrNoGroup
	}
	vg := NewVNIGroup(c.cfg.VNI, c.g)
	commitMsg, err := RecoverViaExternalCommit(
		ctx, vg, c.suite, candidates, fetchGI,
		c.ordering, c.cfg.Cred, c.cfg.Signer, c.cfg.Lifetime,
	)
	if err != nil {
		return nil, err
	}
	c.g = vg.g // adopt the recovered group
	c.applyHandshakePrivacy()
	if rerr := c.rotateSA(); rerr != nil {
		return commitMsg, fmt.Errorf("ironcore: AutoRecover: rotateSA: %w", rerr)
	}
	return commitMsg, nil
}

// ─── unexported helpers ───────────────────────────────────────────────────────

// applyHandshakePrivacy sets the adopted group's outbound-handshake framing from
// config. External-commit/recovery messages are always PublicMessage regardless
// (RFC 9420 §12.4.3); this only governs the member's own future commits/proposals.
func (c *Controller) applyHandshakePrivacy() {
	if c.g != nil {
		c.g.SetEncryptHandshakes(c.cfg.HandshakePrivacy != HandshakePlaintext)
	}
}

// deriveCur derives the current SA from g and stores it in c.curSA.
func (c *Controller) deriveCur() error {
	sa, err := DeriveSAKeys(c.g, c.cfg.VNI)
	if err != nil {
		return err
	}
	c.curSA = sa
	return nil
}

// rotateSA shifts curSA → prevSA and re-derives curSA at the new epoch.
func (c *Controller) rotateSA() error {
	c.prevSA = c.curSA
	c.hasPrev = true
	return c.deriveCur()
}

// commitAndOrder performs an optimistic commit then reserves the epoch slot via
// the Ordering register (design spec §5.1). On win: rotateSA and return
// won=true. On loss (ok=false from AcceptCommit): return won=false; the in-place
// epoch advance is a dead fork branch — the caller must AutoRecover.
func (c *Controller) commitAndOrder(ctx context.Context, byValue []group.Proposal) (commitMsg, welcomeMsg []byte, won bool, err error) {
	epoch := c.g.Epoch() // pre-commit epoch n
	commitMsg, welcomeMsg, err = c.g.Commit(group.CommitOptions{ByValue: byValue})
	if err != nil {
		return nil, nil, false, err
	}
	ref := group.CommitRef(c.suite.Hash(commitMsg))
	ok, err := c.ordering.AcceptCommit(ctx, c.groupID, epoch, ref)
	if err != nil {
		return commitMsg, welcomeMsg, false, err
	}
	if !ok {
		return commitMsg, welcomeMsg, false, nil // lost — caller AutoRecovers
	}
	if err := c.rotateSA(); err != nil {
		return commitMsg, welcomeMsg, true, err
	}
	return commitMsg, welcomeMsg, true, nil
}

// identityToLeaf builds a map from verified identity (string) to leaf index for
// all current active members. Used by Reconcile to diff desired vs current.
func (c *Controller) identityToLeaf() (map[string]uint32, error) {
	leaves := c.g.ActiveLeaves()
	m := make(map[string]uint32, len(leaves))
	for _, leaf := range leaves {
		cred, sigPub, err := c.g.LeafCredential(leaf)
		if err != nil {
			return nil, fmt.Errorf("LeafCredential(%d): %w", leaf, err)
		}
		identity, err := c.cfg.Validator.Validate(cred, sigPub)
		if err != nil {
			// Validation failure means we can't map this leaf to an identity.
			// The leaf is INVISIBLE to both the add and remove paths: it never
			// enters idToLeaf so it cannot appear in removeSet and therefore
			// cannot be evicted via Reconcile even if the control plane omits
			// it from desired. A member with an unverifiable credential must be
			// removed by a direct proposal rather than through Reconcile.
			continue
		}
		m[string(identity)] = leaf
	}
	return m, nil
}

// memberCommitBody extracts the Commit body bytes from a framed member
// PublicMessage commit (SenderTypeMember). Returns (body, true) for a valid
// member commit, (nil, false) for any other message type or parse error.
// Only the Commit body bytes are returned — no authentication is performed here
// (authentication happens in ProcessCommit); this is purely structural.
func memberCommitBody(commitMsg []byte) ([]byte, bool) {
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(commitMsg); err != nil {
		return nil, false
	}
	if m.WireFormat != framing.WireFormatPublicMessage || m.Public == nil {
		return nil, false
	}
	if m.Public.Content.Sender.Type != framing.SenderTypeMember {
		return nil, false
	}
	if m.Public.Content.ContentType != framing.ContentTypeCommit {
		return nil, false
	}
	return m.Public.Content.Content, true
}

// commitRemovesSelf reports whether the framed member commit contains a by-value
// Remove of this node's own leaf. Returns false for any
// parse error or non-member commit.
func (c *Controller) commitRemovesSelf(commitMsg []byte) bool {
	body, ok := memberCommitBody(commitMsg)
	if !ok {
		return false
	}
	var cm group.Commit
	if err := cm.UnmarshalMLS(body); err != nil {
		return false
	}
	own := c.g.OwnLeaf()
	for _, por := range cm.Proposals {
		if por.Type == group.ProposalOrRefTypeProposal && por.Proposal != nil &&
			por.Proposal.Type == group.ProposalTypeRemove && por.Proposal.Remove != nil &&
			por.Proposal.Remove.Removed == own {
			return true
		}
	}
	return false
}

// sortUint32 sorts a []uint32 in ascending order (insertion sort; slices are small).
func sortUint32(s []uint32) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}
