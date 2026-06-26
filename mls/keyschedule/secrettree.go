package keyschedule

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// SenderDataKeyNonce derives the sender-data AEAD key and nonce (RFC 9420 §9.1):
//
//	ciphertext_sample = ciphertext[0 .. KDF.Nh-1]   (whole ciphertext if shorter)
//	sender_data_key   = ExpandWithLabel(sender_data_secret, "key",   sample, AEAD.Nk)
//	sender_data_nonce = ExpandWithLabel(sender_data_secret, "nonce", sample, AEAD.Nn)
func SenderDataKeyNonce(suite cipher.Suite, senderDataSecret, ciphertext []byte) (key, nonce []byte, err error) {
	sample := ciphertext
	if nh := suite.HashLen(); len(sample) > nh {
		sample = sample[:nh]
	}
	key, err = suite.ExpandWithLabel(senderDataSecret, "key", sample, suite.AEADKeySize())
	if err != nil {
		return nil, nil, err
	}
	nonce, err = suite.ExpandWithLabel(senderDataSecret, "nonce", sample, suite.AEADNonceSize())
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}

// RatchetType selects a leaf's handshake or application ratchet (RFC 9420 §9.1).
type RatchetType int

const (
	HandshakeRatchet RatchetType = iota
	ApplicationRatchet
)

// SecretTree holds the per-leaf ratchet base secrets derived from
// encryption_secret (RFC 9420 §9).
type SecretTree struct {
	suite           cipher.Suite
	nLeaves         uint32
	handshakeBase   map[uint32][]byte // leaf index -> handshake_ratchet_secret_[N]_[0]
	applicationBase map[uint32][]byte // leaf index -> application_ratchet_secret_[N]_[0]
}

// NewSecretTree builds the secret tree for nLeaves leaves with encryption_secret
// at the root, deriving each leaf's handshake/application ratchet roots (§9).
func NewSecretTree(suite cipher.Suite, nLeaves uint32, encryptionSecret []byte) (*SecretTree, error) {
	if nLeaves == 0 {
		return nil, fmt.Errorf("keyschedule: secret tree requires at least one leaf")
	}
	st := &SecretTree{
		suite:           suite,
		nLeaves:         nLeaves,
		handshakeBase:   make(map[uint32][]byte, nLeaves),
		applicationBase: make(map[uint32][]byte, nLeaves),
	}
	if err := st.deriveNode(tree.Root(nLeaves), encryptionSecret); err != nil {
		return nil, err
	}
	return st, nil
}

func (st *SecretTree) deriveNode(node uint32, secret []byte) error {
	nh := st.suite.HashLen()
	left, ok := tree.Left(node)
	if !ok {
		// Leaf node: node index == 2 * leaf index (RFC 9420 §9 / tree math).
		leaf := node / 2
		hs, err := st.suite.ExpandWithLabel(secret, "handshake", nil, nh)
		if err != nil {
			return err
		}
		app, err := st.suite.ExpandWithLabel(secret, "application", nil, nh)
		if err != nil {
			return err
		}
		st.handshakeBase[leaf] = hs
		st.applicationBase[leaf] = app
		return nil
	}
	right, _ := tree.Right(node, st.nLeaves)
	ls, err := st.suite.ExpandWithLabel(secret, "tree", []byte("left"), nh)
	if err != nil {
		return err
	}
	rs, err := st.suite.ExpandWithLabel(secret, "tree", []byte("right"), nh)
	if err != nil {
		return err
	}
	if err := st.deriveNode(left, ls); err != nil {
		return err
	}
	return st.deriveNode(right, rs)
}

// KeyNonce returns the AEAD key and nonce for a leaf's ratchet at the given
// generation (RFC 9420 §9.1). The running secret is advanced from generation 0.
//
// KeyNonce is stateless: it re-derives the ratchet from generation 0 on every
// call, which is correct for verification and KATs but O(generation) per call.
// Production senders/receivers must keep a stateful ratchet (advancing and
// discarding consumed generations) to preserve forward secrecy and performance.
func (st *SecretTree) KeyNonce(leaf uint32, rt RatchetType, generation uint32) (key, nonce []byte, err error) {
	var base []byte
	switch rt {
	case HandshakeRatchet:
		base = st.handshakeBase[leaf]
	case ApplicationRatchet:
		base = st.applicationBase[leaf]
	default:
		return nil, nil, fmt.Errorf("keyschedule: invalid ratchet type %d", rt)
	}
	if base == nil {
		return nil, nil, fmt.Errorf("keyschedule: no ratchet for leaf %d (nLeaves=%d)", leaf, st.nLeaves)
	}
	nh := st.suite.HashLen()
	secret := append([]byte(nil), base...)
	for j := uint32(0); j < generation; j++ {
		secret, err = st.suite.DeriveTreeSecret(secret, "secret", j, nh)
		if err != nil {
			return nil, nil, err
		}
	}
	key, err = st.suite.DeriveTreeSecret(secret, "key", generation, st.suite.AEADKeySize())
	if err != nil {
		return nil, nil, err
	}
	nonce, err = st.suite.DeriveTreeSecret(secret, "nonce", generation, st.suite.AEADNonceSize())
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}
