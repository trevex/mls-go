// Package cipher implements the MLS ciphersuite registry and the labeled
// cryptography of RFC 9420 §5. This plan covers the hash, HMAC, HKDF, and
// signature primitives plus labeled key derivation; HPKE (EncryptWithLabel)
// and the hybrid PQC suite are added in Plan 2.
package cipher

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
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

// Suite bundles the primitive constructors for one ciphersuite. KEM/AEAD/HPKE
// fields are added in Plan 2; this struct intentionally exposes only what the
// foundation needs.
type Suite struct {
	ID      CipherSuite
	NewHash func() hash.Hash
	Sig     SignatureScheme
}

var registry = map[CipherSuite]Suite{
	X25519_AES128GCM_SHA256_Ed25519: {
		ID:      X25519_AES128GCM_SHA256_Ed25519,
		NewHash: sha256.New,
		Sig:     SigEd25519,
	},
	P256_AES128GCM_SHA256_P256: {
		ID:      P256_AES128GCM_SHA256_P256,
		NewHash: sha256.New,
		Sig:     SigECDSAP256,
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
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pub)
		if x == nil {
			xx, yy := elliptic.Unmarshal(elliptic.P256(), pub)
			if xx == nil {
				return false
			}
			x, y = xx, yy
		}
		pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		digest := s.Hash(message)
		return ecdsa.VerifyASN1(pk, digest, sig)
	default:
		return false
	}
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
