package group

import (
	"crypto/rand"
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/framing"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// CommitOptions selects the proposals to include in a Commit.
type CommitOptions struct {
	// ByValue holds proposals inlined into the Commit (e.g. Adds the committer
	// originates).
	ByValue []Proposal
	// ByReference holds previously-delivered PublicMessage proposal MLSMessage
	// bytes to include by reference (ProposalRef).
	ByReference [][]byte
}

// Commit applies the options' proposals to a cloned tree (RFC 9420 §12.3
// order), generates an UpdatePath, advances the key schedule to epoch n+1,
// frames the commit as a PublicMessage, builds a Welcome for newly-added
// members, and advances g to epoch n+1. It returns the commit MLSMessage bytes
// and (if any members were added) the Welcome MLSMessage bytes
// (RFC 9420 §12.4/§12.4.3.1).
//
// The two-GroupContext rule (N0): encGC uses the OLD confirmed_transcript_hash
// for the UpdatePath HPKE context; newGC uses the NEW confirmed_transcript_hash
// for the key schedule and confirmation_tag. Both are at epoch=n+1 with the
// post-path tree hash.
func (g *Group) Commit(opt CommitOptions) (commit []byte, welcome []byte, err error) {
	// Step 1: Clone tree; build proposal cache for by-reference entries; build
	// the Commit body.
	wt, err := g.tree.Clone()
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: clone tree: %w", err)
	}

	// Build proposal cache from the by-reference proposals (same logic as
	// ProcessCommit — UnmarshalMLS → UnprotectPublic → RefHash).
	// Also build Commit.Proposals by-reference entries in the same pass so we
	// never re-parse or swallow errors in a second loop.
	var cm Commit
	cache := make(map[string]cachedProposal, len(opt.ByReference))
	for idx, propBytes := range opt.ByReference {
		var m framing.MLSMessage
		if err := m.UnmarshalMLS(propBytes); err != nil {
			return nil, nil, fmt.Errorf("group: Commit: by-reference[%d] parse: %w", idx, err)
		}
		if m.WireFormat != framing.WireFormatPublicMessage || m.Public == nil {
			return nil, nil, fmt.Errorf("group: Commit: by-reference[%d] not a PublicMessage", idx)
		}
		senderLeaf := m.Public.Content.Sender.LeafIndex
		senderLeafNode, err := g.tree.LeafNodeAt(senderLeaf)
		if err != nil {
			return nil, nil, fmt.Errorf("group: Commit: by-reference[%d] sender leaf %d: %w", idx, senderLeaf, err)
		}
		gc := g.groupContext
		ac, err := framing.UnprotectPublic(g.suite, senderLeafNode.SignatureKey, &gc, g.epoch.MembershipKey, *m.Public)
		if err != nil {
			return nil, nil, fmt.Errorf("group: Commit: by-reference[%d] authenticate: %w", idx, err)
		}
		acBytes, err := ac.MarshalMLS()
		if err != nil {
			return nil, nil, fmt.Errorf("group: Commit: by-reference[%d] marshal AC: %w", idx, err)
		}
		ref, err := g.suite.RefHash("MLS 1.0 Proposal Reference", acBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("group: Commit: by-reference[%d] RefHash: %w", idx, err)
		}
		var prop Proposal
		if err := prop.UnmarshalMLS(ac.Content.Content); err != nil {
			return nil, nil, fmt.Errorf("group: Commit: by-reference[%d] parse body: %w", idx, err)
		}
		cache[string(ref)] = cachedProposal{proposal: prop, sender: senderLeaf}
		// Reuse the already-computed ref — no second parse needed.
		cm.Proposals = append(cm.Proposals, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: ref})
	}
	// Append by-value proposals after by-reference ones; track added KeyPackages
	// in order for Welcome construction.
	var addedKPs []KeyPackage
	for i := range opt.ByValue {
		p := opt.ByValue[i]
		cm.Proposals = append(cm.Proposals, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: &p})
		if p.Type == ProposalTypeAdd && p.Add != nil {
			addedKPs = append(addedKPs, p.Add.KeyPackage)
		}
	}

	// Step 2: Apply proposals in §12.3 order on the working clone.
	resumptionPSKs := make(map[uint64][]byte, len(g.resumptionPSKHistory)+1)
	for epoch, psk := range g.resumptionPSKHistory {
		resumptionPSKs[epoch] = psk
	}
	resumptionPSKs[g.groupContext.Epoch] = g.epoch.ResumptionPSK

	provisionalExt, epochPSKs, _, newlyAdded, err := applyProposals(
		g.suite, wt, cm, cache,
		g.groupContext.Extensions, g.externalPSKs, resumptionPSKs,
		g.groupContext.GroupID, g.ownLeaf,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: applyProposals: %w", err)
	}

	// Step 3: Generate the UpdatePath. Use the OLD confirmed_transcript_hash
	// for the HPKE encryption context (encGC, the #1 trap per N0).
	leafSecret := make([]byte, g.suite.HashLen())
	if _, err := rand.Read(leafSecret); err != nil {
		return nil, nil, fmt.Errorf("group: Commit: rand.Read(leafSecret): %w", err)
	}

	oldConfirmed := g.groupContext.ConfirmedTranscriptHash
	mkGC := func(treeHash []byte) ([]byte, error) {
		encGC := keyschedule.GroupContext{
			Version:                 g.groupContext.Version,
			CipherSuite:             g.groupContext.CipherSuite,
			GroupID:                 g.groupContext.GroupID,
			Epoch:                   g.groupContext.Epoch + 1,
			TreeHash:                treeHash,
			ConfirmedTranscriptHash: oldConfirmed, // OLD — N0
			Extensions:              provisionalExt,
		}
		return encGC.MarshalMLS()
	}

	up, commitSecret, pathSecretByNode, err := wt.GenerateUpdatePath(
		g.ownLeaf, leafSecret, g.signer, g.groupContext.GroupID, newlyAdded, mkGC,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: GenerateUpdatePath: %w", err)
	}
	cm.Path = up

	// Step 4: The §6.1/§8.2 circular dance.
	// Sign the FramedContent → get the ConfirmedTranscriptHashInput (= wire_format ‖ FramedContent ‖ sig).
	commitBody, err := cm.MarshalMLS()
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: marshal Commit body: %w", err)
	}
	fc := framing.FramedContent{
		GroupID:     g.groupContext.GroupID,
		Epoch:       g.groupContext.Epoch,
		Sender:      framing.Sender{Type: framing.SenderTypeMember, LeafIndex: g.ownLeaf},
		ContentType: framing.ContentTypeCommit,
		Content:     commitBody,
	}
	gc := g.groupContext
	confirmedInput, sig, err := framing.SignCommit(g.suite, g.signer, &gc, fc)
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: SignCommit: %w", err)
	}

	// Compute confirmed_transcript_hash[n+1] using the NEW signature.
	confirmed := keyschedule.ConfirmedTranscriptHash(g.suite, g.interim, confirmedInput)

	// Build newGC (NEW confirmed_transcript_hash — differs from encGC only here).
	newTreeHash, err := wt.RootTreeHash()
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: RootTreeHash: %w", err)
	}
	newGC := keyschedule.GroupContext{
		Version:                 g.groupContext.Version,
		CipherSuite:             g.groupContext.CipherSuite,
		GroupID:                 g.groupContext.GroupID,
		Epoch:                   g.groupContext.Epoch + 1,
		TreeHash:                newTreeHash,
		ConfirmedTranscriptHash: confirmed, // NEW — N0
		Extensions:              provisionalExt,
	}
	newGCBytes, err := newGC.MarshalMLS()
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: marshal newGC: %w", err)
	}

	// Advance the key schedule.
	pskSecret, err := keyschedule.PSKSecret(g.suite, epochPSKs)
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: PSKSecret: %w", err)
	}
	es, err := keyschedule.DeriveEpochSecrets(g.suite, g.initSecret, commitSecret, pskSecret, newGCBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: DeriveEpochSecrets: %w", err)
	}

	// Compute confirmation_tag.
	confTag := keyschedule.ConfirmationTag(g.suite, es.ConfirmationKey, confirmed)

	// Assemble the PublicMessage (adds membership_tag using gc_n / membership_key_n).
	pubMsg, err := framing.AssembleCommitPublic(g.suite, &gc, g.epoch.MembershipKey, fc, sig, confTag)
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: AssembleCommitPublic: %w", err)
	}
	commitMLS := framing.MLSMessage{
		Version:    tree.ProtocolVersionMLS10,
		WireFormat: framing.WireFormatPublicMessage,
		Public:     &pubMsg,
	}
	commitBytes, err := commitMLS.MarshalMLS()
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: marshal commit MLSMessage: %w", err)
	}

	// Step 5: Build Welcome for newly-added members.
	var welcomeBytes []byte
	if len(newlyAdded) > 0 {
		// Collect PSK IDs to embed in GroupSecrets (empty for the core gate).
		var pskIDs []keyschedule.PreSharedKeyID
		for _, psk := range epochPSKs {
			pskIDs = append(pskIDs, psk.ID)
		}
		welcomeBytes, err = buildWelcome(g.suite, es, newGC, wt, g.ownLeaf, g.signer,
			newlyAdded, addedKPs, pathSecretByNode, confTag, pskIDs)
		if err != nil {
			return nil, nil, fmt.Errorf("group: Commit: buildWelcome: %w", err)
		}
	}

	// Step 6: Advance committer to epoch n+1 (mirror ProcessCommit state-commit).
	interim, err := keyschedule.InterimTranscriptHash(g.suite, confirmed, confTag)
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: InterimTranscriptHash: %w", err)
	}

	// Rebuild own private TreeKEM state from the freshly-derived path secrets.
	// Derive own leaf key from leafSecret, plus all path secrets for ancestors.
	leafNodeSecret, err := g.suite.DeriveSecret(leafSecret, "node")
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: DeriveSecret(leafNodeSecret): %w", err)
	}
	newLeafPriv, _, err := g.suite.DeriveKeyPair(leafNodeSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: DeriveKeyPair(newLeaf): %w", err)
	}
	newPriv := tree.NewTreeKEMPrivate(g.ownLeaf, newLeafPriv)
	for nodeIdx, ps := range pathSecretByNode {
		if err := newPriv.AddPathSecret(g.suite, nodeIdx, ps); err != nil {
			return nil, nil, fmt.Errorf("group: Commit: AddPathSecret(node %d): %w", nodeIdx, err)
		}
	}

	st, err := keyschedule.NewSecretTree(g.suite, wt.LeafCount(), es.EncryptionSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("group: Commit: NewSecretTree: %w", err)
	}

	// Commit all state atomically.
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

	return commitBytes, welcomeBytes, nil
}
