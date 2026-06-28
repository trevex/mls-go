package group

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/tree"
)

// JoinOptions carries the joiner's private material and optional inputs
// for JoinFromWelcome.
type JoinOptions struct {
	KeyPackage     []byte            // our KeyPackage MLSMessage (envelope)
	InitPriv       []byte            // HPKE init private key
	EncryptionPriv []byte            // HPKE leaf encryption private key
	Signer         crypto.Signer     // our leaf signing key (may be nil for a pure receiver)
	RatchetTree    []byte            // external ratchet_tree wire form (nil ⇒ use GroupInfo ext)
	ExternalPSKs   map[string][]byte // psk_id (string key) -> psk secret
}

// JoinFromWelcome processes a Welcome MLSMessage and returns the joined Group
// at its initial epoch (RFC 9420 §12.4.3.1). Each step is verified to reproduce
// initial_epoch_authenticator for all 16 registered-suite
// passive-client-welcome.json cases.
func JoinFromWelcome(suite cipher.Suite, welcome []byte, opt JoinOptions) (*Group, error) {
	// step 1: Parse the Welcome MLSMessage envelope.
	w, err := DecodeWelcomeMessage(welcome)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: parse Welcome: %w", err)
	}

	// step 2: Parse our KeyPackage; compute our KeyPackageRef and select the
	// matching EncryptedGroupSecrets entry.
	kp, err := DecodeKeyPackageMessage(opt.KeyPackage)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: parse KeyPackage: %w", err)
	}
	ref, err := kp.Ref(suite)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: kp.Ref: %w", err)
	}
	var egs *EncryptedGroupSecrets
	for idx := range w.Secrets {
		if bytes.Equal(w.Secrets[idx].NewMember, ref) {
			egs = &w.Secrets[idx]
			break
		}
	}
	if egs == nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: no EncryptedGroupSecrets for our KeyPackageRef")
	}

	// step 3: Decrypt GroupSecrets.
	// context = encrypted_group_info (verified).
	gsBytes, err := suite.DecryptWithLabel(
		opt.InitPriv,
		"Welcome",
		w.EncryptedGroupInfo,
		egs.EncryptedGroupSecrets.KemOutput,
		egs.EncryptedGroupSecrets.Ciphertext,
	)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: decrypt GroupSecrets: %w", err)
	}
	var gs GroupSecrets
	if err := gs.UnmarshalMLS(gsBytes); err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: unmarshal GroupSecrets: %w", err)
	}

	// step 4: Resolve PSKs → psk_secret.
	psks := make([]keyschedule.PSK, 0, len(gs.PSKs))
	for _, id := range gs.PSKs {
		if id.PSKType != keyschedule.PSKTypeExternal {
			return nil, fmt.Errorf("group: JoinFromWelcome: resumption PSKs not supported")
		}
		pskBytes, ok := opt.ExternalPSKs[string(id.PSKID)]
		if !ok {
			return nil, fmt.Errorf("group: JoinFromWelcome: PSK %x not in ExternalPSKs", id.PSKID)
		}
		psks = append(psks, keyschedule.PSK{ID: id, PSK: pskBytes})
	}
	pskSecret, err := keyschedule.PSKSecret(suite, psks)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: PSKSecret: %w", err)
	}

	// step 5: Derive welcome key/nonce; decrypt GroupInfo.
	// member = Extract(salt=joiner_secret, IKM=psk_secret); welcome_secret = DeriveSecret(member, "welcome").
	// AAD is empty (verified).
	member, err := suite.Extract(gs.JoinerSecret, pskSecret)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: Extract(joiner,psk): %w", err)
	}
	welcomeSecret, err := suite.DeriveSecret(member, "welcome")
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: DeriveSecret(member,welcome): %w", err)
	}
	wk, wn, err := keyschedule.WelcomeKeyNonce(suite, welcomeSecret)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: WelcomeKeyNonce: %w", err)
	}
	giBytes, err := suite.Open(wk, wn, nil, w.EncryptedGroupInfo)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: Open(GroupInfo): %w", err)
	}
	var gi GroupInfo
	if err := gi.UnmarshalMLS(giBytes); err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: unmarshal GroupInfo: %w", err)
	}

	// step 6: Install the ratchet tree.
	var rtreeData []byte
	if len(opt.RatchetTree) > 0 {
		rtreeData = opt.RatchetTree
	} else {
		rtreeData = gi.RatchetTreeExtension()
		if rtreeData == nil {
			return nil, fmt.Errorf("group: JoinFromWelcome: no ratchet_tree in GroupInfo and none provided")
		}
	}
	rt, err := tree.ParseRatchetTree(suite, rtreeData)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: ParseRatchetTree: %w", err)
	}

	// step 7: Validate tree + tree-hash binding.
	if ok, err := rt.VerifyParentHashes(); err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: VerifyParentHashes: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("group: JoinFromWelcome: parent hash verification failed")
	}
	if err := rt.VerifyLeafSignatures(gi.GroupContext.GroupID); err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: VerifyLeafSignatures: %w", err)
	}
	treeHash, err := rt.RootTreeHash()
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: RootTreeHash: %w", err)
	}
	if !bytes.Equal(treeHash, gi.GroupContext.TreeHash) {
		return nil, fmt.Errorf("group: JoinFromWelcome: tree hash mismatch (got %x, want %x)",
			treeHash, gi.GroupContext.TreeHash)
	}

	// step 8: Verify GroupInfo signature using the signer leaf's key.
	signerLeaf, err := rt.LeafNodeAt(gi.Signer)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: signer leaf %d: %w", gi.Signer, err)
	}
	if ok, err := gi.VerifySignature(suite, signerLeaf.SignatureKey); err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: VerifySignature: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("group: JoinFromWelcome: GroupInfo signature invalid")
	}

	// step 9: Find own leaf; build TreeKEMPrivate; optionally install path secret.
	ownLeaf, ok := rt.FindLeafByEncryptionKey(kp.LeafNode.EncryptionKey)
	if !ok {
		return nil, fmt.Errorf("group: JoinFromWelcome: own encryption key not found in tree")
	}
	priv := tree.NewTreeKEMPrivate(ownLeaf, opt.EncryptionPriv)
	if gs.PathSecret != nil {
		if err := installJoinerPriv(suite, priv, gs.PathSecret.PathSecret, ownLeaf, gi.Signer, rt.LeafCount()); err != nil {
			return nil, fmt.Errorf("group: JoinFromWelcome: installJoinerPriv: %w", err)
		}
	}

	// step 10: Derive epoch secrets from joiner_secret.
	gcBytes, err := gi.GroupContext.MarshalMLS()
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: marshal GroupContext: %w", err)
	}
	es, err := keyschedule.EpochSecretsFromJoiner(suite, gs.JoinerSecret, pskSecret, gcBytes)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: EpochSecretsFromJoiner: %w", err)
	}

	// step 11: Verify confirmation_tag.
	ct := keyschedule.ConfirmationTag(suite, es.ConfirmationKey, gi.GroupContext.ConfirmedTranscriptHash)
	if !bytes.Equal(ct, gi.ConfirmationTag) {
		return nil, fmt.Errorf("group: JoinFromWelcome: confirmation_tag mismatch")
	}

	// step 12: Initialize interim transcript hash.
	interim, err := keyschedule.InterimTranscriptHash(suite, gi.GroupContext.ConfirmedTranscriptHash, gi.ConfirmationTag)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: InterimTranscriptHash: %w", err)
	}

	// Build SecretTree from encryption_secret (for future AEAD decryption).
	st, err := keyschedule.NewSecretTree(suite, rt.LeafCount(), es.EncryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("group: JoinFromWelcome: NewSecretTree: %w", err)
	}

	// step 13: epoch_authenticator = es.EpochAuthenticator — verified to equal
	// initial_epoch_authenticator for all 16 registered-suite KAT cases.
	//
	// Seed the resumption PSK history with the joined epoch so that ProcessCommit
	// can resolve resumption PSK proposals that reference this epoch (RFC 9420 §8.4).
	rpsks := map[uint64][]byte{gi.GroupContext.Epoch: es.ResumptionPSK}
	return &Group{
		suite:                suite,
		groupContext:         gi.GroupContext,
		tree:                 rt,
		priv:                 priv,
		epoch:                es,
		secretTree:           st,
		interim:              interim,
		initSecret:           es.InitSecret,
		ownLeaf:              ownLeaf,
		signer:               opt.Signer,
		externalPSKs:         opt.ExternalPSKs,
		resumptionPSKHistory: rpsks,
		pendingUpdates:       map[string][]byte{},
	}, nil
}
