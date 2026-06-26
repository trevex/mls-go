// Package cipher implements the MLS ciphersuite registry and the cryptography
// of RFC 9420 §5: hash, HMAC, HKDF, signatures, labeled key derivation
// (RefHash/ExpandWithLabel/DeriveSecret/DeriveTreeSecret/SignWithLabel), and
// HPKE-based labeled public-key encryption (EncryptWithLabel/DecryptWithLabel,
// §5.1.3). It registers the classical suites 0x0001 and 0x0002 plus the
// private-use X-Wing post-quantum hybrid suite.
package cipher

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"hash"
)

// CipherSuite is the 2-byte MLS ciphersuite identifier (RFC 9420 §17.1).
type CipherSuite uint16

const (
	X25519_AES128GCM_SHA256_Ed25519 CipherSuite = 0x0001
	P256_AES128GCM_SHA256_P256      CipherSuite = 0x0002
)

// SignatureScheme enumerates the signature algorithms used by leaf credentials.
type SignatureScheme uint8

const (
	SigEd25519 SignatureScheme = iota
	SigECDSAP256
)

// Suite bundles the primitive constructors for one ciphersuite.
type Suite struct {
	ID      CipherSuite
	NewHash func() hash.Hash
	Sig     SignatureScheme
	kem     hpke.KEM
	kdf     hpke.KDF
	aead    hpke.AEAD
}

var registry = map[CipherSuite]Suite{
	X25519_AES128GCM_SHA256_Ed25519: {
		ID:      X25519_AES128GCM_SHA256_Ed25519,
		NewHash: sha256.New,
		Sig:     SigEd25519,
		kem:     hpke.DHKEM(ecdh.X25519()),
		kdf:     hpke.HKDFSHA256(),
		aead:    hpke.AES128GCM(),
	},
	P256_AES128GCM_SHA256_P256: {
		ID:      P256_AES128GCM_SHA256_P256,
		NewHash: sha256.New,
		Sig:     SigECDSAP256,
		kem:     hpke.DHKEM(ecdh.P256()),
		kdf:     hpke.HKDFSHA256(),
		aead:    hpke.AES128GCM(),
	},
}

// Lookup returns the Suite for id and whether it is registered.
func Lookup(id CipherSuite) (Suite, bool) {
	s, ok := registry[id]
	return s, ok
}

// HashLen returns the digest size in bytes.
func (s Suite) HashLen() int { return s.NewHash().Size() }

// Hash returns Hash(data).
func (s Suite) Hash(data []byte) []byte {
	h := s.NewHash()
	h.Write(data)
	return h.Sum(nil)
}

// MAC returns HMAC-Hash(key, data) — the MLS MAC primitive (RFC 9420 §5.2).
func (s Suite) MAC(key, data []byte) []byte {
	m := hmac.New(s.NewHash, key)
	m.Write(data)
	return m.Sum(nil)
}

// kdfExpand wraps HKDF-Expand with the suite hash (RFC 9420 §8 KDF.Expand).
func (s Suite) kdfExpand(secret, info []byte, length int) ([]byte, error) {
	return hkdf.Expand(s.NewHash, secret, string(info), length)
}

// verifyClassical verifies a raw signature for the suite's scheme. Used by
// VerifyWithLabel in labeled.go.
func (s Suite) verifyClassical(pub, message, sig []byte) bool {
	switch s.Sig {
	case SigEd25519:
		return len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), message, sig)
	case SigECDSAP256:
		pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
		if err != nil {
			return false
		}
		digest := s.Hash(message)
		return ecdsa.VerifyASN1(pk, digest, sig)
	default:
		return false
	}
}

// GenerateHPKEKeyPair generates a fresh HPKE key pair for the suite's KEM,
// returning the serialized private and public keys (the MLS HPKEPrivateKey /
// HPKEPublicKey encodings).
func (s Suite) GenerateHPKEKeyPair() (priv, pub []byte, err error) {
	sk, err := s.kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := sk.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return privBytes, sk.PublicKey().Bytes(), nil
}

// signClassical signs message with priv for the suite's scheme. Used by
// SignWithLabel in labeled.go and by tests.
func (s Suite) signClassical(priv crypto.Signer, message []byte) ([]byte, error) {
	switch s.Sig {
	case SigEd25519:
		return priv.Sign(nil, message, crypto.Hash(0))
	case SigECDSAP256:
		digest := s.Hash(message)
		return priv.Sign(nil, digest, crypto.SHA256)
	default:
		return nil, errUnsupportedScheme
	}
}
