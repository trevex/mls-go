package group_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"

	"github.com/trevex/mls-go/mls/cipher"
)

// buildSigner constructs a crypto.Signer from the vector's raw signature_priv.
// ok is false for cipher suites whose signature scheme is not handled here.
func buildSigner(cs cipher.CipherSuite, raw []byte) (crypto.Signer, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	switch cs {
	case cipher.X25519_AES128GCM_SHA256_Ed25519:
		return ed25519.NewKeyFromSeed(raw), true
	case cipher.P256_AES128GCM_SHA256_P256:
		sk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
		if err != nil {
			return nil, false
		}
		return sk, true
	default:
		return nil, false
	}
}
