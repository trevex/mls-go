package group

import (
	"bytes"
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/framing"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// cachedProposal is one by-reference proposal in the per-epoch proposal cache.
type cachedProposal struct {
	proposal Proposal
	sender   uint32
}

// applyProposals resolves cm.Proposals (by-value/by-reference via cache),
// applies them to wt in RFC 9420 §12.3 order (Update, Remove, Add,
// GroupContextExtensions), collects PSK ids, and returns whether any
// proposal requires a path (pathRequired = any Update|Remove|Add).
//
// committerLeaf is used as the sender for by-value proposals.
// externalPSKs maps external PSK IDs (string) to their secret bytes.
// resumptionPSKs maps epoch numbers to the group's resumption PSK for that
// epoch (resolved from the group's history for RFC 9420 §8.4 resumption PSKs).
// groupID is the current group identifier, used to validate resumption PSK refs.
//
// newlyAdded is the list of leaf indices of members added by Add proposals in
// this commit. Senders MAY omit path-secret ciphertexts for these leaves
// (RFC 9420 §7.5); callers must pass this list to ProcessUpdatePath so it can
// correctly compute the ciphertext index.
func applyProposals(
	suite cipher.Suite,
	wt *tree.RatchetTree,
	cm Commit,
	cache map[string]cachedProposal,
	currentExt []tree.Extension,
	externalPSKs map[string][]byte,
	resumptionPSKs map[uint64][]byte,
	groupID []byte,
	committerLeaf uint32,
) (provisionalExt []tree.Extension, psks []keyschedule.PSK, pathRequired bool, newlyAdded []uint32, err error) {
	// Step 1: Resolve all ProposalOrRef into (proposal, sender) pairs, in
	// commit order.
	type resolved struct {
		proposal Proposal
		sender   uint32
	}
	allResolved := make([]resolved, 0, len(cm.Proposals))
	for _, por := range cm.Proposals {
		switch por.Type {
		case ProposalOrRefTypeProposal:
			if por.Proposal == nil {
				return nil, nil, false, nil, fmt.Errorf("group: applyProposals: by-value ProposalOrRef has nil Proposal")
			}
			allResolved = append(allResolved, resolved{proposal: *por.Proposal, sender: committerLeaf})
		case ProposalOrRefTypeReference:
			cp, ok := cache[string(por.Reference)]
			if !ok {
				return nil, nil, false, nil, fmt.Errorf("group: applyProposals: ProposalRef %x not in cache", por.Reference)
			}
			allResolved = append(allResolved, resolved{proposal: cp.proposal, sender: cp.sender})
		default:
			return nil, nil, false, nil, fmt.Errorf("group: applyProposals: unknown ProposalOrRefType %d", por.Type)
		}
	}

	// Step 2: Bucket by proposal type (in commit order within each bucket).
	var updates, removes, adds, gces []resolved
	for _, r := range allResolved {
		switch r.proposal.Type {
		case ProposalTypeUpdate:
			updates = append(updates, r)
			pathRequired = true
		case ProposalTypeRemove:
			removes = append(removes, r)
			pathRequired = true
		case ProposalTypeAdd:
			adds = append(adds, r)
			pathRequired = true
		case ProposalTypeGroupContextExtensions:
			gces = append(gces, r)
		case ProposalTypePreSharedKey:
			// PSKs collected below.
		case ProposalTypeReInit, ProposalTypeExternalInit:
			// Not tree-mutating; handled at higher level if needed.
		}
	}

	// Step 3: Apply in §12.3 order: Update → Remove → Add → GCE.

	// Update.
	for _, r := range updates {
		if r.proposal.Update == nil {
			return nil, nil, false, nil, fmt.Errorf("group: applyProposals: Update proposal body is nil")
		}
		if err := wt.UpdateLeaf(r.sender, r.proposal.Update.LeafNode); err != nil {
			return nil, nil, false, nil, fmt.Errorf("group: applyProposals: UpdateLeaf(%d): %w", r.sender, err)
		}
	}

	// Remove.
	for _, r := range removes {
		if r.proposal.Remove == nil {
			return nil, nil, false, nil, fmt.Errorf("group: applyProposals: Remove proposal body is nil")
		}
		if err := wt.RemoveLeaf(r.proposal.Remove.Removed); err != nil {
			return nil, nil, false, nil, fmt.Errorf("group: applyProposals: RemoveLeaf(%d): %w", r.proposal.Remove.Removed, err)
		}
	}

	// Add: collect the leaf indices of newly-added members. Senders MAY omit
	// path-secret ciphertexts for these leaves in the same commit's UpdatePath
	// (RFC 9420 §7.5); we return them so ProcessCommit can pass them to
	// ProcessUpdatePath for correct ciphertext-index alignment.
	for _, r := range adds {
		if r.proposal.Add == nil {
			return nil, nil, false, nil, fmt.Errorf("group: applyProposals: Add proposal body is nil")
		}
		li, err := wt.AddLeaf(r.proposal.Add.KeyPackage.LeafNode)
		if err != nil {
			return nil, nil, false, nil, fmt.Errorf("group: applyProposals: AddLeaf: %w", err)
		}
		newlyAdded = append(newlyAdded, li)
	}

	// GroupContextExtensions (last one wins).
	provisionalExt = currentExt
	for _, r := range gces {
		if r.proposal.GroupContextExtensions == nil {
			return nil, nil, false, nil, fmt.Errorf("group: applyProposals: GCE proposal body is nil")
		}
		provisionalExt = r.proposal.GroupContextExtensions.Extensions
	}

	// Collect PSK secrets (in commit order per RFC 9420 §8.4).
	for _, r := range allResolved {
		if r.proposal.Type != ProposalTypePreSharedKey {
			continue
		}
		if r.proposal.PreSharedKey == nil {
			return nil, nil, false, nil, fmt.Errorf("group: applyProposals: PreSharedKey proposal body is nil")
		}
		id := r.proposal.PreSharedKey.PSK
		switch id.PSKType {
		case keyschedule.PSKTypeExternal:
			pskBytes, ok := externalPSKs[string(id.PSKID)]
			if !ok {
				return nil, nil, false, nil, fmt.Errorf("group: applyProposals: external PSK %x not found", id.PSKID)
			}
			psks = append(psks, keyschedule.PSK{ID: id, PSK: pskBytes})
		case keyschedule.PSKTypeResumption:
			// Resumption PSKs reference a specific epoch of a specific group (RFC 9420 §8.4).
			// We only support the case where the PSKGroupID matches our group.
			if !bytes.Equal(id.PSKGroupID, groupID) {
				return nil, nil, false, nil, fmt.Errorf("group: applyProposals: resumption PSK references foreign group %x", id.PSKGroupID)
			}
			pskBytes, ok := resumptionPSKs[id.PSKEpoch]
			if !ok {
				return nil, nil, false, nil, fmt.Errorf("group: applyProposals: resumption PSK for epoch %d not in history", id.PSKEpoch)
			}
			psks = append(psks, keyschedule.PSK{ID: id, PSK: pskBytes})
		default:
			return nil, nil, false, nil, fmt.Errorf("group: applyProposals: unknown PSKType %d", id.PSKType)
		}
	}

	return provisionalExt, psks, pathRequired, newlyAdded, nil
}

// resolveOwnUpdatePriv returns the pending leaf private key for an Update in cm
// authored by g's own leaf, or nil if this commit does not apply such an Update.
// It errors only if an own Update is committed but no pending key is tracked.
func (g *Group) resolveOwnUpdatePriv(cm Commit, cache map[string]cachedProposal, committerLeaf uint32) ([]byte, error) {
	for _, por := range cm.Proposals {
		var prop Proposal
		var sender uint32
		switch por.Type {
		case ProposalOrRefTypeProposal:
			if por.Proposal == nil {
				continue
			}
			prop, sender = *por.Proposal, committerLeaf
		case ProposalOrRefTypeReference:
			cp, ok := cache[string(por.Reference)]
			if !ok {
				continue // applyProposals will surface the missing-ref error
			}
			prop, sender = cp.proposal, cp.sender
		default:
			continue
		}
		if prop.Type != ProposalTypeUpdate || sender != g.ownLeaf || prop.Update == nil {
			continue
		}
		pub := prop.Update.LeafNode.EncryptionKey
		priv, ok := g.pendingUpdates[string(pub)]
		if !ok {
			return nil, fmt.Errorf("own Update committed but no pending leaf key tracked")
		}
		return priv, nil
	}
	return nil, nil
}

// ProcessCommit advances the group by one epoch, given the proposals delivered
// before the commit (cached by reference) and the commit MLSMessage. It verifies
// the commit's authentication and confirmation_tag and returns an error (leaving
// g unchanged) on any failure (RFC 9420 §12.4).
//
// The exact sequence follows N2/N3/N5 from the plan:
//   - Two GroupContexts differ ONLY in confirmed_transcript_hash (encryption=old,
//     key-schedule=new), both at epoch=n+1 with the post-path tree hash (N3).
//   - confirmed_transcript_hash input = wire_format || FramedContent || signature
//     (N5, via keyschedule.SplitAuthenticatedContent).
//   - ProposalRef = RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent)
//     (RFC 9420 §12.4 / §5.2 — over the full AuthenticatedContent bytes, NOT the
//     bare Proposal body).
func (g *Group) ProcessCommit(proposals [][]byte, commit []byte) error {
	// N2 step 1: Build proposal cache from the by-reference proposals.
	// Each proposal is a PublicMessage whose AuthenticatedContent bytes serve as
	// the input to RefHash("MLS 1.0 Proposal Reference", …) (RFC 9420 §12.4/§5.2).
	cache := make(map[string]cachedProposal, len(proposals))
	for idx, propBytes := range proposals {
		var m framing.MLSMessage
		if err := m.UnmarshalMLS(propBytes); err != nil {
			return fmt.Errorf("group: ProcessCommit: proposal[%d] parse: %w", idx, err)
		}
		if m.WireFormat != framing.WireFormatPublicMessage || m.Public == nil {
			return fmt.Errorf("group: ProcessCommit: proposal[%d] is not a PublicMessage", idx)
		}
		senderLeaf := m.Public.Content.Sender.LeafIndex
		senderLeafNode, err := g.tree.LeafNodeAt(senderLeaf)
		if err != nil {
			return fmt.Errorf("group: ProcessCommit: proposal[%d] sender leaf %d: %w", idx, senderLeaf, err)
		}
		gc := g.groupContext
		ac, err := framing.UnprotectPublic(g.suite, senderLeafNode.SignatureKey, &gc, g.epoch.MembershipKey, *m.Public)
		if err != nil {
			return fmt.Errorf("group: ProcessCommit: proposal[%d] authenticate: %w", idx, err)
		}
		var prop Proposal
		if err := prop.UnmarshalMLS(ac.Content.Content); err != nil {
			return fmt.Errorf("group: ProcessCommit: proposal[%d] parse body: %w", idx, err)
		}
		// ProposalRef = RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent)
		// (RFC 9420 §12.4 / §5.2: the hash is over the full authenticated framing,
		// not just the bare Proposal body).
		acBytes, err := ac.MarshalMLS()
		if err != nil {
			return fmt.Errorf("group: ProcessCommit: proposal[%d] marshal AC: %w", idx, err)
		}
		ref, err := g.suite.RefHash("MLS 1.0 Proposal Reference", acBytes)
		if err != nil {
			return fmt.Errorf("group: ProcessCommit: proposal[%d] RefHash: %w", idx, err)
		}
		cache[string(ref)] = cachedProposal{proposal: prop, sender: senderLeaf}
	}

	// N2 step 2: Authenticate the commit (PublicMessage, member sender).
	var m framing.MLSMessage
	if err := m.UnmarshalMLS(commit); err != nil {
		return fmt.Errorf("group: ProcessCommit: parse commit: %w", err)
	}
	if m.WireFormat != framing.WireFormatPublicMessage || m.Public == nil {
		return fmt.Errorf("group: ProcessCommit: commit is not a PublicMessage")
	}

	// Dispatch: new_member_commit (external joiner) is handled separately because
	// the committer is not in the tree and uses the joiner's UpdatePath key for auth.
	if m.Public.Content.Sender.Type == framing.SenderTypeNewMemberCommit {
		return g.processExternalCommit(m)
	}

	committerLeaf := m.Public.Content.Sender.LeafIndex
	committerLeafNode, err := g.tree.LeafNodeAt(committerLeaf)
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: committer leaf %d: %w", committerLeaf, err)
	}
	gc := g.groupContext
	ac, err := framing.UnprotectPublic(g.suite, committerLeafNode.SignatureKey, &gc, g.epoch.MembershipKey, *m.Public)
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: authenticate commit: %w", err)
	}
	if ac.Content.Epoch != g.groupContext.Epoch {
		return fmt.Errorf("group: ProcessCommit: commit epoch %d != group epoch %d",
			ac.Content.Epoch, g.groupContext.Epoch)
	}

	// N2 step 3: Parse the Commit body.
	var cm Commit
	if err := cm.UnmarshalMLS(ac.Content.Content); err != nil {
		return fmt.Errorf("group: ProcessCommit: parse Commit body: %w", err)
	}

	// N2 step 4: Resolve proposals + apply in §12.3 order on a working clone.
	wt, err := g.tree.Clone()
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: clone tree: %w", err)
	}
	// Build the resumption PSK resolver: current epoch's PSK + historical PSKs.
	// This makes the group's own resumption PSKs available for PSK proposals
	// that reference previous epochs of this group (RFC 9420 §8.4).
	resumptionPSKs := make(map[uint64][]byte, len(g.resumptionPSKHistory)+1)
	for epoch, psk := range g.resumptionPSKHistory {
		resumptionPSKs[epoch] = psk
	}
	// Also include the current epoch (it may not be in history if it was just set).
	resumptionPSKs[g.groupContext.Epoch] = g.epoch.ResumptionPSK

	provisionalExt, epochPSKs, _, newlyAdded, err := applyProposals(
		g.suite, wt, cm, cache,
		g.groupContext.Extensions, g.externalPSKs, resumptionPSKs,
		g.groupContext.GroupID, committerLeaf,
	)
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: applyProposals: %w", err)
	}

	// Atomic pending-update swap: if this commit applies an Update authored by our
	// own leaf, decrypt the UpdatePath with the pending leaf key (path secrets are
	// encrypted to our NEW leaf pubkey after the Update is applied to the tree).
	// g.priv is NOT mutated here — workingPriv is local until confirmation_tag
	// verifies, so a superseded update leaves the old key usable.
	ownUpdatePriv, err := g.resolveOwnUpdatePriv(cm, cache, committerLeaf)
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: %w", err)
	}
	workingPriv := g.priv
	if ownUpdatePriv != nil {
		workingPriv = tree.NewTreeKEMPrivate(g.ownLeaf, ownUpdatePriv)
	}

	// N2 step 5 (transcript part, N5): Compute the provisional confirmed
	// transcript hash from the commit's AuthenticatedContent.
	// confirmed = Hash(interim[n-1] || wire_format || FramedContent || signature)
	acBytes, err := ac.MarshalMLS()
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: marshal AuthenticatedContent: %w", err)
	}
	confirmedInput, confTag, err := keyschedule.SplitAuthenticatedContent(g.suite, acBytes)
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: SplitAuthenticatedContent: %w", err)
	}
	confirmed := keyschedule.ConfirmedTranscriptHash(g.suite, g.interim, confirmedInput)

	// N2 step 5 (path part): Process the UpdatePath if present.
	// THE #1 TRAP (N3): encGC uses the OLD confirmed_transcript_hash (epoch n);
	// newGC uses the NEW confirmed_transcript_hash. Both use epoch=n+1 and the
	// post-path tree hash.
	var commitSecret []byte
	var newTreeHash []byte
	var decryptedPS []byte

	if cm.Path != nil {
		// Compute the new tree hash from a post-path clone (so we don't mutate
		// the working tree before calling ProcessUpdatePath).
		ct, cloneErr := wt.Clone()
		if cloneErr != nil {
			return fmt.Errorf("group: ProcessCommit: clone for tree hash: %w", cloneErr)
		}
		if mergeErr := ct.Merge(committerLeaf, cm.Path); mergeErr != nil {
			return fmt.Errorf("group: ProcessCommit: Merge (hash clone): %w", mergeErr)
		}
		newTreeHash, err = ct.RootTreeHash()
		if err != nil {
			return fmt.Errorf("group: ProcessCommit: post-path RootTreeHash: %w", err)
		}

		// Build the encryption GroupContext with the OLD confirmed_transcript_hash.
		encGC := keyschedule.GroupContext{
			Version:                 g.groupContext.Version,
			CipherSuite:             g.groupContext.CipherSuite,
			GroupID:                 g.groupContext.GroupID,
			Epoch:                   g.groupContext.Epoch + 1,
			TreeHash:                newTreeHash,
			ConfirmedTranscriptHash: g.groupContext.ConfirmedTranscriptHash, // OLD — N3
			Extensions:              provisionalExt,
		}
		encGCBytes, gcErr := encGC.MarshalMLS()
		if gcErr != nil {
			return fmt.Errorf("group: ProcessCommit: marshal encGC: %w", gcErr)
		}

		// Decrypt the path secret using the pre-merge working tree + encGC.
		// Pass newlyAdded so ProcessUpdatePath can correctly skip ciphertext slots
		// for members whose Add proposal is in this same commit (RFC 9420 §7.5).
		decryptedPS, commitSecret, err = wt.ProcessUpdatePath(committerLeaf, cm.Path, workingPriv, encGCBytes, newlyAdded)
		if err != nil {
			return fmt.Errorf("group: ProcessCommit: ProcessUpdatePath: %w", err)
		}
		// Safety net: if we still couldn't find a decryptable path secret,
		// use commit_secret = zeros (RFC 9420 §7.4 fallback for excluded receivers).
		if commitSecret == nil {
			commitSecret = make([]byte, g.suite.HashLen())
		}

		// Apply the path to the working tree.
		if mergeErr := wt.Merge(committerLeaf, cm.Path); mergeErr != nil {
			return fmt.Errorf("group: ProcessCommit: Merge (working tree): %w", mergeErr)
		}
	} else {
		// No path: commitSecret is nil (all-zero in key schedule), newTreeHash
		// from the post-proposal working tree.
		newTreeHash, err = wt.RootTreeHash()
		if err != nil {
			return fmt.Errorf("group: ProcessCommit: RootTreeHash (no path): %w", err)
		}
	}

	// N2 step 6: Advance the key schedule using the NEW confirmed_transcript_hash.
	// newGC and encGC differ ONLY in confirmed_transcript_hash (N3).
	newGC := keyschedule.GroupContext{
		Version:                 g.groupContext.Version,
		CipherSuite:             g.groupContext.CipherSuite,
		GroupID:                 g.groupContext.GroupID,
		Epoch:                   g.groupContext.Epoch + 1,
		TreeHash:                newTreeHash,
		ConfirmedTranscriptHash: confirmed, // NEW — N3
		Extensions:              provisionalExt,
	}
	newGCBytes, gcErr := newGC.MarshalMLS()
	if gcErr != nil {
		return fmt.Errorf("group: ProcessCommit: marshal newGC: %w", gcErr)
	}
	pskSecret, pskErr := keyschedule.PSKSecret(g.suite, epochPSKs)
	if pskErr != nil {
		return fmt.Errorf("group: ProcessCommit: PSKSecret: %w", pskErr)
	}
	es, esErr := keyschedule.DeriveEpochSecrets(g.suite, g.initSecret, commitSecret, pskSecret, newGCBytes)
	if esErr != nil {
		return fmt.Errorf("group: ProcessCommit: DeriveEpochSecrets: %w", esErr)
	}

	// N2 step 7: Verify confirmation_tag — reject the commit on mismatch (§12.4).
	expectedConfTag := keyschedule.ConfirmationTag(g.suite, es.ConfirmationKey, confirmed)
	if !bytes.Equal(expectedConfTag, confTag) {
		return fmt.Errorf("group: ProcessCommit: confirmation_tag mismatch")
	}

	// N2 step 8: Chain transcript hashes.
	interim, interimErr := keyschedule.InterimTranscriptHash(g.suite, confirmed, confTag)
	if interimErr != nil {
		return fmt.Errorf("group: ProcessCommit: InterimTranscriptHash: %w", interimErr)
	}

	// Rebuild private TreeKEM state from the decrypted path secret (N4).
	// The path secret lives at commonAncestor(2*ownLeaf, 2*committerLeaf).
	var newPriv *tree.TreeKEMPrivate
	if cm.Path != nil && decryptedPS != nil {
		ownKey, ok := workingPriv.PrivateKeyAt(2 * g.ownLeaf)
		if !ok {
			return fmt.Errorf("group: ProcessCommit: own leaf private key missing")
		}
		newPriv = tree.NewTreeKEMPrivate(g.ownLeaf, ownKey)
		if installErr := installJoinerPriv(g.suite, newPriv, decryptedPS, g.ownLeaf, committerLeaf, wt.LeafCount()); installErr != nil {
			return fmt.Errorf("group: ProcessCommit: installJoinerPriv: %w", installErr)
		}
	} else {
		newPriv = workingPriv
	}

	// Build a new SecretTree from the fresh encryption_secret.
	st, stErr := keyschedule.NewSecretTree(g.suite, wt.LeafCount(), es.EncryptionSecret)
	if stErr != nil {
		return fmt.Errorf("group: ProcessCommit: NewSecretTree: %w", stErr)
	}

	// Commit all state atomically (only reached after confirmation_tag verified).
	// Add the current epoch's resumption PSK to history before advancing.
	g.resumptionPSKHistory[g.groupContext.Epoch] = g.epoch.ResumptionPSK
	g.tree = wt
	g.groupContext = newGC
	g.epoch = es
	g.initSecret = es.InitSecret
	g.interim = interim
	g.priv = newPriv
	g.secretTree = st
	// Seed the next epoch's resumption PSK into history immediately.
	g.resumptionPSKHistory[newGC.Epoch] = es.ResumptionPSK
	// Reset per-epoch sender ratchet counter (RFC 9420 §9.1).
	g.appGeneration = 0
	// Clear pending updates on epoch change — any pending key from the old epoch
	// is now either committed (and swapped into g.priv) or superseded.
	g.pendingUpdates = map[string][]byte{}

	return nil
}
