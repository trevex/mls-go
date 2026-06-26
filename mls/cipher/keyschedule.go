package cipher

import (
	"crypto/hkdf"
	"fmt"
)

// Extract implements the MLS key schedule's KDF.Extract (RFC 9420 §8): it
// returns a pseudorandom key of length KDF.Nh.
//
// NOTE on argument order: the RFC writes KDF.Extract(salt, IKM), but Go's
// crypto/hkdf.Extract takes the IKM ("secret") first and the salt second.
// This wrapper presents the RFC order (salt, ikm) and swaps internally.
func (s Suite) Extract(salt, ikm []byte) ([]byte, error) {
	return hkdf.Extract(s.NewHash, ikm, salt)
}

// AEADKeySize returns AEAD.Nk (the AEAD key length in bytes, RFC 9180 §7.3) for
// the suite's AEAD.
func (s Suite) AEADKeySize() int {
	switch s.aead.ID() {
	case 0x0001: // AES-128-GCM
		return 16
	case 0x0002, 0x0003: // AES-256-GCM, ChaCha20Poly1305
		return 32
	default:
		panic(fmt.Sprintf("cipher: unknown AEAD id %#x", s.aead.ID()))
	}
}

// AEADNonceSize returns AEAD.Nn (the AEAD nonce length in bytes, RFC 9180 §7.3).
// Every AEAD used by an MLS cipher suite uses a 12-byte nonce.
func (s Suite) AEADNonceSize() int {
	switch s.aead.ID() {
	case 0x0001, 0x0002, 0x0003:
		return 12
	default:
		panic(fmt.Sprintf("cipher: unknown AEAD id %#x", s.aead.ID()))
	}
}

// DeriveKeyPair deterministically derives an HPKE key pair from ikm
// (RFC 9180 DeriveKeyPair), returning the serialized private and public keys
// (the MLS HPKEPrivateKey / HPKEPublicKey encodings). Used to derive external_pub
// from external_secret (RFC 9420 §8).
func (s Suite) DeriveKeyPair(ikm []byte) (priv, pub []byte, err error) {
	sk, err := s.kem.DeriveKeyPair(ikm)
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := sk.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return privBytes, sk.PublicKey().Bytes(), nil
}
