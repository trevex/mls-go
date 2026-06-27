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
// committerLeaf is the sender for by-value proposals.
func applyProposals(
	suite cipher.Suite,
	wt *tree.RatchetTree,
	cm Commit,
	cache map[string]cachedProposal,
	currentExt []tree.Extension,
	externalPSKs map[string][]byte,
	committerLeaf uint32,
) (provisionalExt []tree.Extension, psks []keyschedule.PSK, pathRequired bool, err error) {
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
				return nil, nil, false, fmt.Errorf("group: applyProposals: by-value ProposalOrRef has nil Proposal")
			}
			allResolved = append(allResolved, resolved{proposal: *por.Proposal, sender: committerLeaf})
		case ProposalOrRefTypeReference:
			cp, ok := cache[string(por.Reference)]
			if !ok {
				return nil, nil, false, fmt.Errorf("group: applyProposals: ProposalRef %x not in cache", por.Reference)
			}
			allResolved = append(allResolved, resolved{proposal: cp.proposal, sender: cp.sender})
		default:
			return nil, nil, false, fmt.Errorf("group: applyProposals: unknown ProposalOrRefType %d", por.Type)
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
			return nil, nil, false, fmt.Errorf("group: applyProposals: Update proposal body is nil")
		}
		if err := wt.UpdateLeaf(r.sender, r.proposal.Update.LeafNode); err != nil {
			return nil, nil, false, fmt.Errorf("group: applyProposals: UpdateLeaf(%d): %w", r.sender, err)
		}
	}

	// Remove.
	for _, r := range removes {
		if r.proposal.Remove == nil {
			return nil, nil, false, fmt.Errorf("group: applyProposals: Remove proposal body is nil")
		}
		if err := wt.RemoveLeaf(r.proposal.Remove.Removed); err != nil {
			return nil, nil, false, fmt.Errorf("group: applyProposals: RemoveLeaf(%d): %w", r.proposal.Remove.Removed, err)
		}
	}

	// Add.
	for _, r := range adds {
		if r.proposal.Add == nil {
			return nil, nil, false, fmt.Errorf("group: applyProposals: Add proposal body is nil")
		}
		if _, err := wt.AddLeaf(r.proposal.Add.KeyPackage.LeafNode); err != nil {
			return nil, nil, false, fmt.Errorf("group: applyProposals: AddLeaf: %w", err)
		}
	}

	// GroupContextExtensions (last one wins).
	provisionalExt = currentExt
	for _, r := range gces {
		if r.proposal.GroupContextExtensions == nil {
			return nil, nil, false, fmt.Errorf("group: applyProposals: GCE proposal body is nil")
		}
		provisionalExt = r.proposal.GroupContextExtensions.Extensions
	}

	// Collect PSK secrets (in commit order per RFC 9420 §8.4).
	for _, r := range allResolved {
		if r.proposal.Type != ProposalTypePreSharedKey {
			continue
		}
		if r.proposal.PreSharedKey == nil {
			return nil, nil, false, fmt.Errorf("group: applyProposals: PreSharedKey proposal body is nil")
		}
		id := r.proposal.PreSharedKey.PSK
		switch id.PSKType {
		case keyschedule.PSKTypeExternal:
			pskBytes, ok := externalPSKs[string(id.PSKID)]
			if !ok {
				return nil, nil, false, fmt.Errorf("group: applyProposals: PSK %x not in external PSKs", id.PSKID)
			}
			psks = append(psks, keyschedule.PSK{ID: id, PSK: pskBytes})
		case keyschedule.PSKTypeResumption:
			return nil, nil, false, fmt.Errorf("group: applyProposals: resumption PSKs not supported")
		default:
			return nil, nil, false, fmt.Errorf("group: applyProposals: unknown PSKType %d", id.PSKType)
		}
	}

	return provisionalExt, psks, pathRequired, nil
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
func (g *Group) ProcessCommit(proposals [][]byte, commit []byte) error {
	// N2 step 1: Build proposal cache from the by-reference proposals.
	// Each proposal is a PublicMessage whose Proposal body we authenticate and
	// cache under ProposalRef = RefHash("MLS 1.0 Proposal Reference", body).
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
		ref, err := prop.Ref(g.suite)
		if err != nil {
			return fmt.Errorf("group: ProcessCommit: proposal[%d] Ref: %w", idx, err)
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
	provisionalExt, epochPSKs, _, err := applyProposals(
		g.suite, wt, cm, cache,
		g.groupContext.Extensions, g.externalPSKs, committerLeaf,
	)
	if err != nil {
		return fmt.Errorf("group: ProcessCommit: applyProposals: %w", err)
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
		decryptedPS, commitSecret, err = wt.ProcessUpdatePath(committerLeaf, cm.Path, g.priv, encGCBytes)
		if err != nil {
			return fmt.Errorf("group: ProcessCommit: ProcessUpdatePath: %w", err)
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
		ownKey, ok := g.priv.PrivateKeyAt(2 * g.ownLeaf)
		if !ok {
			return fmt.Errorf("group: ProcessCommit: own leaf private key missing")
		}
		newPriv = tree.NewTreeKEMPrivate(g.ownLeaf, ownKey)
		if installErr := installJoinerPriv(g.suite, newPriv, decryptedPS, g.ownLeaf, committerLeaf, wt.LeafCount()); installErr != nil {
			return fmt.Errorf("group: ProcessCommit: installJoinerPriv: %w", installErr)
		}
	} else {
		newPriv = g.priv
	}

	// Build a new SecretTree from the fresh encryption_secret.
	st, stErr := keyschedule.NewSecretTree(g.suite, wt.LeafCount(), es.EncryptionSecret)
	if stErr != nil {
		return fmt.Errorf("group: ProcessCommit: NewSecretTree: %w", stErr)
	}

	// Commit all state (only reached after the confirmation_tag has been verified).
	g.tree = wt
	g.groupContext = newGC
	g.epoch = es
	g.initSecret = es.InitSecret
	g.interim = interim
	g.priv = newPriv
	g.secretTree = st

	return nil
}
