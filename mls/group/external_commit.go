package group

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/framing"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// ExternalCommit lets a non-member join an existing group without a Welcome
// (RFC 9420 §12.4.3.2). The joiner builds a special Commit containing exactly
// one ExternalInit proposal (which carries kem_output so existing members can
// derive the same init_secret) plus a mandatory UpdatePath, advances its own
// key schedule with the external-init secret, and returns the new *Group at
// epoch n+1 together with the commit MLSMessage bytes to broadcast.
//
// The joiner's GroupInfo gi must be signed and carry both the ratchet_tree
// (0x0002) and external_pub (0x0004) extensions (see PublishGroupInfo).
//
// Anti-double-join (§12.4.3.2): if the joiner's signature key already appears
// in the published tree (stale/losing-branch re-join), ExternalCommit
// automatically includes a Remove of the prior leaf.
func ExternalCommit(suite cipher.Suite, gi GroupInfo, cred tree.Credential, signer crypto.Signer, lifetime tree.Lifetime) (*Group, []byte, error) {
	// 1. external_pub → external-init secret (RFC 9420 §8.3).
	extPub := gi.ExternalPubExtension()
	if extPub == nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: GroupInfo has no external_pub extension")
	}
	kemOutput, initSecret, err := suite.ExternalInitEncap(extPub)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: ExternalInitEncap: %w", err)
	}

	// 2. Rebuild + validate the tree from the GroupInfo (mirror JoinFromWelcome).
	rtreeData := gi.RatchetTreeExtension()
	if rtreeData == nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: GroupInfo has no ratchet_tree extension")
	}
	wt, err := tree.ParseRatchetTree(suite, rtreeData)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: ParseRatchetTree: %w", err)
	}
	if ok, err := wt.VerifyParentHashes(); err != nil || !ok {
		return nil, nil, fmt.Errorf("group: ExternalCommit: parent hash verification failed (%v)", err)
	}
	if err := wt.VerifyLeafSignatures(gi.GroupContext.GroupID); err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: VerifyLeafSignatures: %w", err)
	}
	if th, err := wt.RootTreeHash(); err != nil || !bytes.Equal(th, gi.GroupContext.TreeHash) {
		return nil, nil, fmt.Errorf("group: ExternalCommit: tree hash mismatch")
	}

	gc := gi.GroupContext // GroupContext[n]

	// 3. Anti-double-join: Remove a prior appearance of this signer.
	sigPub, err := suite.SignaturePublicKey(signer)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: SignaturePublicKey: %w", err)
	}
	var byValue []Proposal
	if oldLeaf, ok := findLeafBySignatureKey(wt, sigPub); ok {
		if err := wt.RemoveLeaf(oldLeaf); err != nil {
			return nil, nil, fmt.Errorf("group: ExternalCommit: RemoveLeaf(%d): %w", oldLeaf, err)
		}
		byValue = append(byValue, ProposeRemove(oldLeaf))
	}

	// 4. Mint the joiner leaf and add it (leftmost-blank-or-append → liC).
	// NewKeyPackage mints fresh HPKE keys and a key_package-source leaf signed
	// under the joiner's signing key. The minted init/leaf priv keys are unused
	// here: the leaf encryption key is rederived from the commit path below.
	kp, _, _, err := NewKeyPackage(suite, cred, signer, lifetime)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: NewKeyPackage: %w", err)
	}
	liC, err := wt.AddLeaf(kp.LeafNode)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: AddLeaf: %w", err)
	}

	// 5. Proposals: exactly one ExternalInit first, then optional Remove.
	// No by-reference proposals; no Add/Update (§12.4.3.2).
	var cm Commit
	cm.Proposals = append(cm.Proposals, ProposalOrRef{
		Type: ProposalOrRefTypeProposal,
		Proposal: &Proposal{
			Type:         ProposalTypeExternalInit,
			ExternalInit: &ExternalInit{KemOutput: kemOutput},
		},
	})
	for i := range byValue {
		p := byValue[i]
		cm.Proposals = append(cm.Proposals, ProposalOrRef{
			Type:     ProposalOrRefTypeProposal,
			Proposal: &p,
		})
	}

	// 6. UpdatePath from liC. The mkGC closure builds the HPKE encryption context
	// GroupContext with the OLD confirmed_transcript_hash (two-GroupContext rule).
	leafSecret := make([]byte, suite.HashLen())
	if _, err := rand.Read(leafSecret); err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: rand.Read(leafSecret): %w", err)
	}
	oldConfirmed := gc.ConfirmedTranscriptHash
	mkGC := func(treeHash []byte) ([]byte, error) {
		return (keyschedule.GroupContext{
			Version:                 gc.Version,
			CipherSuite:             gc.CipherSuite,
			GroupID:                 gc.GroupID,
			Epoch:                   gc.Epoch + 1,
			TreeHash:                treeHash,
			ConfirmedTranscriptHash: oldConfirmed, // OLD — two-GroupContext rule
			Extensions:              gc.Extensions,
		}).MarshalMLS()
	}
	up, commitSecret, pathByNode, err := wt.GenerateUpdatePath(liC, leafSecret, signer, gc.GroupID, nil, mkGC)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: GenerateUpdatePath: %w", err)
	}
	cm.Path = up

	// 7–8. Frame as new_member_commit (no leaf index) + sign.
	commitBody, err := cm.MarshalMLS()
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: marshal Commit body: %w", err)
	}
	fc := framing.FramedContent{
		GroupID:     gc.GroupID,
		Epoch:       gc.Epoch,
		Sender:      framing.Sender{Type: framing.SenderTypeNewMemberCommit},
		ContentType: framing.ContentTypeCommit,
		Content:     commitBody,
	}
	confirmedInput, sig, err := framing.SignCommit(suite, signer, &gc, fc)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: SignCommit: %w", err)
	}

	// 9. Advance transcript: use the epoch-n interim hash from the published
	// GroupInfo to anchor this commit in the transcript chain.
	// interimN = Hash(confirmed_n || confTag_n); confirmed = Hash(interimN || confirmedInput)
	interimN, err := keyschedule.InterimTranscriptHash(suite, gc.ConfirmedTranscriptHash, gi.ConfirmationTag)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: InterimTranscriptHash: %w", err)
	}
	confirmed := keyschedule.ConfirmedTranscriptHash(suite, interimN, confirmedInput)

	// 10. New GroupContext + key schedule. The init_secret is the external-init
	// secret from step 1 (RFC 9420 §8.3 — substitutes the prior epoch's init_secret).
	newTreeHash, err := wt.RootTreeHash()
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: RootTreeHash: %w", err)
	}
	newGC := keyschedule.GroupContext{
		Version:                 gc.Version,
		CipherSuite:             gc.CipherSuite,
		GroupID:                 gc.GroupID,
		Epoch:                   gc.Epoch + 1,
		TreeHash:                newTreeHash,
		ConfirmedTranscriptHash: confirmed, // NEW
		Extensions:              gc.Extensions,
	}
	newGCBytes, err := newGC.MarshalMLS()
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: marshal newGC: %w", err)
	}
	es, err := keyschedule.DeriveEpochSecrets(suite, initSecret, commitSecret, nil, newGCBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: DeriveEpochSecrets: %w", err)
	}

	// 11. Assemble the PublicMessage WITHOUT a membership_tag (new_member_commit
	// sender is not a member; §12.4.3.2 / §6.2).
	confTag := keyschedule.ConfirmationTag(suite, es.ConfirmationKey, confirmed)
	pubMsg := framing.PublicMessage{
		Content: fc,
		Auth:    framing.FramedContentAuthData{Signature: sig, ConfirmationTag: confTag},
	}
	commitMLS := framing.MLSMessage{
		Version:    tree.ProtocolVersionMLS10,
		WireFormat: framing.WireFormatPublicMessage,
		Public:     &pubMsg,
	}
	commitBytes, err := commitMLS.MarshalMLS()
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: marshal MLSMessage: %w", err)
	}

	// 12. Build the joiner's own Group state at epoch n+1.
	// Derive own leaf key from leafSecret, plus all path secrets for ancestors
	// (mirror commit_gen.go step 6).
	interim, err := keyschedule.InterimTranscriptHash(suite, confirmed, confTag)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: InterimTranscriptHash(new): %w", err)
	}
	leafNodeSecret, err := suite.DeriveSecret(leafSecret, "node")
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: DeriveSecret(node): %w", err)
	}
	newLeafPriv, _, err := suite.DeriveKeyPair(leafNodeSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: DeriveKeyPair(leaf): %w", err)
	}
	priv := tree.NewTreeKEMPrivate(liC, newLeafPriv)
	for nodeIdx, ps := range pathByNode {
		if err := priv.AddPathSecret(suite, nodeIdx, ps); err != nil {
			return nil, nil, fmt.Errorf("group: ExternalCommit: AddPathSecret(%d): %w", nodeIdx, err)
		}
	}
	st, err := keyschedule.NewSecretTree(suite, wt.LeafCount(), es.EncryptionSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("group: ExternalCommit: NewSecretTree: %w", err)
	}

	g := &Group{
		suite:        suite,
		groupContext: newGC,
		tree:         wt,
		priv:         priv,
		epoch:        es,
		secretTree:   st,
		interim:      interim,
		initSecret:   es.InitSecret,
		ownLeaf:      liC,
		signer:       signer,
		externalPSKs: map[string][]byte{},
		resumptionPSKHistory: map[uint64][]byte{
			newGC.Epoch: es.ResumptionPSK,
		},
		pendingUpdates: map[string][]byte{},
	}
	return g, commitBytes, nil
}

// findLeafBySignatureKey returns the leaf index of the first leaf node in rt
// whose SignatureKey equals sigKey, or (0, false) if not found.
// Used for anti-double-join (§12.4.3.2).
func findLeafBySignatureKey(rt *tree.RatchetTree, sigKey []byte) (uint32, bool) {
	for i := uint32(0); i < rt.LeafCount(); i++ {
		ln, err := rt.LeafNodeAt(i)
		if err != nil {
			continue // blank leaf
		}
		if bytes.Equal(ln.SignatureKey, sigKey) {
			return i, true
		}
	}
	return 0, false
}
