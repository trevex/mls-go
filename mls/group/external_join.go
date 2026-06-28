package group

import (
	"bytes"
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/framing"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// PublishGroupInfo builds a signed GroupInfo for the current epoch, carrying the
// ratchet_tree (0x0002) and external_pub (0x0004) extensions, so a non-member can
// join via an external Commit (RFC 9420 §12.4.3.1/§12.4.3.2). The signer is this
// member (g.ownLeaf); confirmation_tag is recomputed from the current epoch.
func (g *Group) PublishGroupInfo() (*GroupInfo, error) {
	if g.signer == nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: no signer (pure receiver)")
	}
	rtree, err := g.tree.MarshalMLS()
	if err != nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: marshal tree: %w", err)
	}
	_, extPub, err := keyschedule.ExternalPub(g.suite, g.epoch.ExternalSecret)
	if err != nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: ExternalPub: %w", err)
	}
	confTag := keyschedule.ConfirmationTag(g.suite, g.epoch.ConfirmationKey, g.groupContext.ConfirmedTranscriptHash)
	gi := &GroupInfo{
		GroupContext: g.groupContext,
		Extensions: []tree.Extension{
			{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: rtree},
			{ExtensionType: ExtensionTypeExternalPub, ExtensionData: extPub},
		},
		ConfirmationTag: confTag,
		Signer:          g.ownLeaf,
	}
	if err := gi.Sign(g.suite, g.signer); err != nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: Sign: %w", err)
	}
	return gi, nil
}

// ProcessExternalCommit applies an external Commit (RFC 9420 §12.4.3.2) sent by
// a non-member (new_member_commit sender) to g, advancing it to epoch n+1.
// It is equivalent to ProcessCommit but dispatches on the new_member_commit
// sender type: the committer is not in the tree, so authentication uses the
// signature key embedded in the commit's UpdatePath.LeafNode rather than a
// tree-resident key.
//
// ProcessCommit already dispatches here when it sees SenderTypeNewMemberCommit.
// Callers may also invoke ProcessExternalCommit directly.
func (g *Group) ProcessExternalCommit(commit []byte) error {
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(commit); err != nil {
		return fmt.Errorf("group: ProcessExternalCommit: parse: %w", err)
	}
	return g.processExternalCommit(m)
}

// processExternalCommit is the internal implementation; it accepts an already-
// parsed MLSMessage so both ProcessExternalCommit and ProcessCommit's dispatch
// share the same code path.
func (g *Group) processExternalCommit(m framing.MLSMessage) error {
	// step 1: Basic wire-format and sender-type checks.
	if m.WireFormat != framing.WireFormatPublicMessage || m.Public == nil {
		return fmt.Errorf("group: processExternalCommit: not a PublicMessage")
	}
	if m.Public.Content.Sender.Type != framing.SenderTypeNewMemberCommit {
		return fmt.Errorf("group: processExternalCommit: sender type %v, want new_member_commit",
			m.Public.Content.Sender.Type)
	}
	if m.Public.Content.ContentType != framing.ContentTypeCommit {
		return fmt.Errorf("group: processExternalCommit: content type %v, want commit",
			m.Public.Content.ContentType)
	}

	// Parse the Commit body (unverified yet — we need cm.Path.LeafNode.SignatureKey
	// to verify the signature, so parse before authenticating).
	var cm Commit
	if err := cm.UnmarshalMLS(m.Public.Content.Content); err != nil {
		return fmt.Errorf("group: processExternalCommit: parse Commit body: %w", err)
	}

	// §12.4.3.2 validity checks. Returns the single ExternalInit proposal so we
	// never assume its position in cm.Proposals (an ExternalInit that is not first
	// must not nil-deref a [0] index — CVE-class DoS).
	extInit, err := validateExternalCommit(cm)
	if err != nil {
		return err
	}

	// The joiner's signature key is in the UpdatePath's LeafNode (committer not in
	// tree yet — §6.1 / §12.4.3.2).
	joinerSigKey := cm.Path.LeafNode.SignatureKey

	// Authenticate: verify signature with the joiner's key; no membership_tag for
	// new_member_commit (framing.UnprotectPublic skips the tag for non-member senders).
	gc := g.groupContext
	ac, err := framing.UnprotectPublic(g.suite, joinerSigKey, &gc, nil, *m.Public)
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: authenticate: %w", err)
	}
	if ac.Content.Epoch != g.groupContext.Epoch {
		return fmt.Errorf("group: processExternalCommit: commit epoch %d != group epoch %d",
			ac.Content.Epoch, g.groupContext.Epoch)
	}

	// Post-authentication authorization checks (§12.4.3.2 / §7.6). Run only after
	// the joiner's signature is verified.
	//
	// §7.6: a leaf added by a Commit's UpdatePath MUST carry leaf_node_source =
	// commit. Reject anything else before trusting the leaf.
	if cm.Path.LeafNode.LeafNodeSource != tree.LeafNodeSourceCommit {
		return fmt.Errorf("group: processExternalCommit: joiner leaf_node_source %d, want commit (§7.6)",
			cm.Path.LeafNode.LeafNodeSource)
	}

	// §12.4.3.2 anti-double-join: a Remove in an external commit may ONLY target
	// the joiner's own prior (stale) leaf — i.e. a leaf whose signature key equals
	// the joiner's. Removing any other member is an unauthorized eviction. Look up
	// each removed leaf in the CURRENT tree (pre-mutation) and compare keys.
	for _, por := range cm.Proposals {
		if por.Type != ProposalOrRefTypeProposal || por.Proposal == nil {
			continue
		}
		if por.Proposal.Type == ProposalTypeRemove && por.Proposal.Remove != nil {
			removed := por.Proposal.Remove.Removed
			ln, err := g.tree.LeafNodeAt(removed)
			if err != nil {
				return fmt.Errorf("group: processExternalCommit: Remove targets leaf %d: %w", removed, err)
			}
			if !bytes.Equal(ln.SignatureKey, joinerSigKey) {
				return fmt.Errorf("group: processExternalCommit: Remove of leaf %d is not the joiner's own leaf (§12.4.3.2)", removed)
			}
		}
	}

	// Split the authenticated content into confirmedInput and the confirmation_tag.
	acBytes, err := ac.MarshalMLS()
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: marshal AC: %w", err)
	}
	confirmedInput, confTag, err := keyschedule.SplitAuthenticatedContent(g.suite, acBytes)
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: SplitAuthenticatedContent: %w", err)
	}

	// step 2: Derive the external-init secret from the ExternalInit proposal's
	// kem_output using this epoch's external_priv.
	extPriv, _, err := keyschedule.ExternalPub(g.suite, g.epoch.ExternalSecret)
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: ExternalPub: %w", err)
	}
	kemOutput := extInit.KemOutput
	initSecret, err := g.suite.ExternalInitDecap(extPriv, kemOutput)
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: ExternalInitDecap: %w", err)
	}

	// step 3: Build working tree — apply Remove (if any), then AddLeaf.
	// Both sides independently agree on liC via deterministic leftmost-blank-or-append
	// (after the same Remove), so the joiner and receivers place the new leaf at the
	// same index without communicating it.
	wt, err := g.tree.Clone()
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: clone tree: %w", err)
	}
	// Apply Remove proposals (anti-double-join).
	for _, por := range cm.Proposals {
		if por.Type != ProposalOrRefTypeProposal || por.Proposal == nil {
			continue
		}
		if por.Proposal.Type == ProposalTypeRemove && por.Proposal.Remove != nil {
			if err := wt.RemoveLeaf(por.Proposal.Remove.Removed); err != nil {
				return fmt.Errorf("group: processExternalCommit: RemoveLeaf(%d): %w",
					por.Proposal.Remove.Removed, err)
			}
		}
	}
	// AddLeaf with the commit-signed leaf node from the UpdatePath.
	liC, err := wt.AddLeaf(cm.Path.LeafNode)
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: AddLeaf: %w", err)
	}

	// §7.3: verify the joiner's own LeafNode signature under "LeafNodeTBS" at its
	// resolved index liC. The UpdatePath leaf is self-signed by the joiner; an
	// attacker-controlled commit could carry a forged or mismatched leaf.
	if ok, err := cm.Path.LeafNode.VerifySignature(g.suite, g.groupContext.GroupID, liC); err != nil {
		return fmt.Errorf("group: processExternalCommit: verify joiner leaf signature: %w", err)
	} else if !ok {
		return fmt.Errorf("group: processExternalCommit: joiner leaf signature invalid (§7.3)")
	}

	// step 4: Compute post-path tree hash (clone + Merge) for the two-GroupContext
	// rule. encGC uses the OLD confirmed_transcript_hash for HPKE context.
	ct, err := wt.Clone()
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: clone for tree hash: %w", err)
	}
	if err := ct.Merge(liC, cm.Path); err != nil {
		return fmt.Errorf("group: processExternalCommit: Merge (hash clone): %w", err)
	}
	newTreeHash, err := ct.RootTreeHash()
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: post-path RootTreeHash: %w", err)
	}

	encGC := keyschedule.GroupContext{
		Version:                 g.groupContext.Version,
		CipherSuite:             g.groupContext.CipherSuite,
		GroupID:                 g.groupContext.GroupID,
		Epoch:                   g.groupContext.Epoch + 1,
		TreeHash:                newTreeHash,
		ConfirmedTranscriptHash: g.groupContext.ConfirmedTranscriptHash, // OLD — two-GroupContext rule
		Extensions:              g.groupContext.Extensions,
	}
	encGCBytes, err := encGC.MarshalMLS()
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: marshal encGC: %w", err)
	}

	// Decrypt the path secret using the pre-merge working tree + encGC.
	// ProcessUpdatePath returns (pathSecret, commitSecret): capture both in one call.
	// The working tree (wt) has the new leaf at liC from AddLeaf but no path public
	// keys yet (Merge not applied) — correct state for ProcessUpdatePath (§7.5).
	decryptedPS, commitSecret, err := wt.ProcessUpdatePath(liC, cm.Path, g.priv, encGCBytes, nil)
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: ProcessUpdatePath: %w", err)
	}
	if commitSecret == nil {
		commitSecret = make([]byte, g.suite.HashLen())
	}

	// Apply the path to the working tree.
	if err := wt.Merge(liC, cm.Path); err != nil {
		return fmt.Errorf("group: processExternalCommit: Merge (working tree): %w", err)
	}

	// §7.9.2: the post-merge tree MUST be parent-hash valid. A malformed UpdatePath
	// could otherwise leave the tree inconsistent (mirrors JoinFromWelcome).
	if ok, err := wt.VerifyParentHashes(); err != nil {
		return fmt.Errorf("group: processExternalCommit: VerifyParentHashes: %w", err)
	} else if !ok {
		return fmt.Errorf("group: processExternalCommit: parent hash verification failed (§7.9.2)")
	}

	// step 5: Confirmed transcript hash (uses g.interim, the receiver's current
	// interim hash = InterimTranscriptHash(confirmed_n, confTag_n)).
	confirmed := keyschedule.ConfirmedTranscriptHash(g.suite, g.interim, confirmedInput)

	// step 6: Advance key schedule with the external-init secret as init_secret.
	newGC := keyschedule.GroupContext{
		Version:                 g.groupContext.Version,
		CipherSuite:             g.groupContext.CipherSuite,
		GroupID:                 g.groupContext.GroupID,
		Epoch:                   g.groupContext.Epoch + 1,
		TreeHash:                newTreeHash,
		ConfirmedTranscriptHash: confirmed, // NEW
		Extensions:              g.groupContext.Extensions,
	}
	newGCBytes, err := newGC.MarshalMLS()
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: marshal newGC: %w", err)
	}
	es, err := keyschedule.DeriveEpochSecrets(g.suite, initSecret, commitSecret, nil, newGCBytes)
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: DeriveEpochSecrets: %w", err)
	}

	// Verify confirmation_tag — integrity backstop; reject on mismatch.
	expectedConfTag := keyschedule.ConfirmationTag(g.suite, es.ConfirmationKey, confirmed)
	if !bytes.Equal(expectedConfTag, confTag) {
		return fmt.Errorf("group: processExternalCommit: confirmation_tag mismatch")
	}

	// Chain transcript hash.
	interim, err := keyschedule.InterimTranscriptHash(g.suite, confirmed, confTag)
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: InterimTranscriptHash: %w", err)
	}

	ownKey, ok := g.priv.PrivateKeyAt(2 * g.ownLeaf)
	if !ok {
		return fmt.Errorf("group: processExternalCommit: own leaf private key missing")
	}
	newPriv := tree.NewTreeKEMPrivate(g.ownLeaf, ownKey)
	if decryptedPS != nil {
		if err := installJoinerPriv(g.suite, newPriv, decryptedPS, g.ownLeaf, liC, wt.LeafCount()); err != nil {
			return fmt.Errorf("group: processExternalCommit: installJoinerPriv: %w", err)
		}
	}

	st, err := keyschedule.NewSecretTree(g.suite, wt.LeafCount(), es.EncryptionSecret)
	if err != nil {
		return fmt.Errorf("group: processExternalCommit: NewSecretTree: %w", err)
	}

	// Commit all state atomically (only reached after confirmation_tag verified).
	g.resumptionPSKHistory[g.groupContext.Epoch] = g.epoch.ResumptionPSK
	g.tree = wt
	g.groupContext = newGC
	g.epoch = es
	g.initSecret = es.InitSecret
	g.interim = interim
	g.priv = newPriv
	g.secretTree = st
	g.resumptionPSKHistory[newGC.Epoch] = es.ResumptionPSK
	g.appGeneration = 0
	g.pendingUpdates = map[string][]byte{}

	return nil
}

// validateExternalCommit enforces the §12.4.3.2 proposal validity rules for an
// external commit and returns the single ExternalInit proposal body:
//   - exactly one ExternalInit proposal
//   - UpdatePath must be present
//   - no by-reference proposals
//   - only ExternalInit, Remove, PreSharedKey, GroupContextExtensions proposals allowed
//     (no Add, Update, ReInit)
//
// It returns the (only) ExternalInit so the caller never has to guess its
// position in the proposal list. The RFC does NOT require ExternalInit to be
// first, so callers MUST use the returned value rather than indexing
// cm.Proposals[0] (which would nil-deref if some other proposal precedes it).
func validateExternalCommit(cm Commit) (*ExternalInit, error) {
	if cm.Path == nil {
		return nil, fmt.Errorf("group: external commit: path is required (§12.4.3.2)")
	}
	var extInit *ExternalInit
	nExternalInit := 0
	for _, por := range cm.Proposals {
		if por.Type == ProposalOrRefTypeReference {
			return nil, fmt.Errorf("group: external commit: by-reference proposals not allowed (§12.4.3.2)")
		}
		if por.Proposal == nil {
			return nil, fmt.Errorf("group: external commit: nil inline proposal")
		}
		switch por.Proposal.Type {
		case ProposalTypeExternalInit:
			if por.Proposal.ExternalInit == nil {
				return nil, fmt.Errorf("group: external commit: ExternalInit proposal has nil body")
			}
			extInit = por.Proposal.ExternalInit
			nExternalInit++
		case ProposalTypeRemove, ProposalTypePreSharedKey, ProposalTypeGroupContextExtensions:
			// allowed
		case ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeReInit:
			return nil, fmt.Errorf("group: external commit: proposal type %v not allowed (§12.4.3.2)",
				por.Proposal.Type)
		default:
			return nil, fmt.Errorf("group: external commit: unknown proposal type %v", por.Proposal.Type)
		}
	}
	if nExternalInit != 1 {
		return nil, fmt.Errorf("group: external commit: must have exactly 1 ExternalInit proposal, got %d (§12.4.3.2)",
			nExternalInit)
	}
	return extInit, nil
}
