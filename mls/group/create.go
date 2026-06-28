package group

import (
	"crypto"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/tree"
)

// NewGroup creates a one-member group at epoch 0 with the creator at leaf 0
// (RFC 9420 §11/§8). The groupID is opaque to the mls/ layer; callers supply
// their credential and signing key. The returned Group is ready to originate
// proposals and commits.
//
// Epoch-0 key schedule: init_secret_[-1] = Hash.Nh zero bytes; commit_secret =
// nil (all-zero Hash.Nh); psk_secret = nil (all-zero Hash.Nh). Both transcript
// hashes start as the zero-length octet string (RFC 9420 §8.2).
func NewGroup(suite cipher.Suite, groupID []byte, cred tree.Credential, signer crypto.Signer, lifetime tree.Lifetime) (*Group, error) {
	// Generate the creator's KeyPackage (init key + signed leaf + signed KP).
	// initPriv is not needed: the creator never decrypts its own Welcome path.
	kp, _, leafPriv, err := NewKeyPackage(suite, cred, signer, lifetime)
	if err != nil {
		return nil, err
	}

	// Build a single-leaf tree at index 0.
	rt := tree.NewRatchetTree(suite, kp.LeafNode)
	treeHash, err := rt.RootTreeHash()
	if err != nil {
		return nil, err
	}

	// Epoch-0 GroupContext. confirmed_transcript_hash is nil (zero-length octet
	// string per RFC 9420 §8.2); extensions are initially empty.
	gc0 := keyschedule.GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             suite.ID,
		GroupID:                 groupID,
		Epoch:                   0,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: nil, // zero-length — §8.2
	}
	gc0Bytes, err := gc0.MarshalMLS()
	if err != nil {
		return nil, err
	}

	// Epoch-0 key schedule seeded with all-zero init_secret and nil commit/psk.
	es0, err := keyschedule.DeriveEpochSecrets(suite, make([]byte, suite.HashLen()), nil, nil, gc0Bytes)
	if err != nil {
		return nil, err
	}

	// Secret tree for application message encryption at this epoch.
	st, err := keyschedule.NewSecretTree(suite, 1, es0.EncryptionSecret)
	if err != nil {
		return nil, err
	}

	return &Group{
		suite:                suite,
		groupContext:         gc0,
		tree:                 rt,
		priv:                 tree.NewTreeKEMPrivate(0, leafPriv),
		epoch:                es0,
		secretTree:           st,
		interim:              nil, // zero-length per §8.2
		initSecret:           es0.InitSecret,
		ownLeaf:              0,
		signer:               signer,
		externalPSKs:         map[string][]byte{},
		resumptionPSKHistory: map[uint64][]byte{0: es0.ResumptionPSK},
		pendingUpdates:       map[string][]byte{},
	}, nil
}
