package group

import (
	"crypto"
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/tree"
)

// buildWelcome constructs a Welcome MLSMessage for the newly-added members
// (RFC 9420 §12.4.3.1).
//
// Parameters:
//   - es: the new epoch's EpochSecrets (after DeriveEpochSecrets for epoch n+1).
//   - newGC: the new GroupContext at epoch n+1 with NEW confirmed_transcript_hash.
//   - wt: the post-commit RatchetTree (post-path, post-proposals).
//   - committerLeaf: the committer's leaf index.
//   - signer: the committer's signing key (for GroupInfo.Sign).
//   - newlyAdded: leaf indices of newly-added members, in proposal commit order.
//   - addedKPs: KeyPackages of newly-added members, in same order as newlyAdded.
//   - pathSecretByNode: filtered-direct-path node index → path secret (from GenerateUpdatePath).
//   - confTag: the confirmation_tag for this commit.
//   - pskIDs: PSK IDs to include in each member's GroupSecrets (empty for core gate).
func buildWelcome(
	suite cipher.Suite,
	es keyschedule.EpochSecrets,
	newGC keyschedule.GroupContext,
	wt *tree.RatchetTree,
	committerLeaf uint32,
	signer crypto.Signer,
	newlyAdded []uint32,
	addedKPs []KeyPackage,
	pathSecretByNode map[uint32][]byte,
	confTag []byte,
	pskIDs []keyschedule.PreSharedKeyID,
) ([]byte, error) {
	if len(newlyAdded) != len(addedKPs) {
		return nil, fmt.Errorf("group: buildWelcome: newlyAdded len %d != addedKPs len %d", len(newlyAdded), len(addedKPs))
	}

	// Step 1: Build and sign GroupInfo.
	// The ratchet_tree extension (0x0002) carries the post-commit serialized tree.
	rtreeData, err := wt.MarshalMLS()
	if err != nil {
		return nil, fmt.Errorf("group: buildWelcome: MarshalMLS tree: %w", err)
	}
	gi := GroupInfo{
		GroupContext: newGC,
		Extensions: []tree.Extension{
			{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: rtreeData},
		},
		ConfirmationTag: confTag,
		Signer:          committerLeaf,
	}
	if err := gi.Sign(suite, signer); err != nil {
		return nil, fmt.Errorf("group: buildWelcome: GroupInfo.Sign: %w", err)
	}

	// Step 2: Encrypt GroupInfo.
	// welcome_key/nonce from welcome_secret (already in EpochSecrets); AAD = nil.
	giBytes, err := gi.MarshalMLS()
	if err != nil {
		return nil, fmt.Errorf("group: buildWelcome: GroupInfo.MarshalMLS: %w", err)
	}
	wk, wn, err := keyschedule.WelcomeKeyNonce(suite, es.WelcomeSecret)
	if err != nil {
		return nil, fmt.Errorf("group: buildWelcome: WelcomeKeyNonce: %w", err)
	}
	encGI, err := suite.Seal(wk, wn, nil, giBytes)
	if err != nil {
		return nil, fmt.Errorf("group: buildWelcome: Seal(GroupInfo): %w", err)
	}

	// Step 3: Build per-member EncryptedGroupSecrets.
	nLeaves := wt.LeafCount()
	secrets := make([]EncryptedGroupSecrets, len(newlyAdded))
	for i, addedLeaf := range newlyAdded {
		// The joiner's path secret is at the common ancestor of the joiner's
		// node (2*addedLeaf) and the committer's node (2*committerLeaf).
		node := commonAncestor(2*addedLeaf, 2*committerLeaf, nLeaves)
		ps, ok := pathSecretByNode[node]
		if !ok {
			return nil, fmt.Errorf("group: buildWelcome: no path secret for node %d (added leaf %d, committer leaf %d)", node, addedLeaf, committerLeaf)
		}

		gs := GroupSecrets{
			JoinerSecret: es.JoinerSecret,
			PathSecret:   &PathSecret{PathSecret: ps},
			PSKs:         pskIDs,
		}
		gsBytes, err := gs.MarshalMLS()
		if err != nil {
			return nil, fmt.Errorf("group: buildWelcome: marshal GroupSecrets[%d]: %w", i, err)
		}

		// HPKE-encrypt GroupSecrets to the added member's init_key.
		// Label "Welcome", context = encrypted_group_info.
		kem, ct, err := suite.EncryptWithLabel(addedKPs[i].InitKey, "Welcome", encGI, gsBytes)
		if err != nil {
			return nil, fmt.Errorf("group: buildWelcome: EncryptWithLabel[%d]: %w", i, err)
		}

		ref, err := addedKPs[i].Ref(suite)
		if err != nil {
			return nil, fmt.Errorf("group: buildWelcome: KP Ref[%d]: %w", i, err)
		}

		secrets[i] = EncryptedGroupSecrets{
			NewMember: ref,
			EncryptedGroupSecrets: tree.HPKECiphertext{
				KemOutput:  kem,
				Ciphertext: ct,
			},
		}
	}

	w := Welcome{
		CipherSuite:        suite.ID,
		Secrets:            secrets,
		EncryptedGroupInfo: encGI,
	}
	return EncodeWelcomeMessage(w)
}
