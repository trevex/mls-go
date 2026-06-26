package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// aeadCipher builds the suite's AEAD with the given key. Only the AES-GCM
// AEADs (RFC 9180 ids 0x0001 AES-128-GCM and 0x0002 AES-256-GCM) are
// supported by the standard library; ChaCha20Poly1305 (0x0003) is not in the
// stdlib and is rejected. crypto/cipher.NewGCM uses the standard 12-byte
// nonce, matching Suite.AEADNonceSize.
func (s Suite) aeadCipher(key []byte) (cipher.AEAD, error) {
	switch s.aead.ID() {
	case 0x0001, 0x0002:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("cipher: raw AEAD seal/open unsupported for AEAD id %#x", s.aead.ID())
	}
}

// Seal encrypts plaintext under the suite's AEAD with the caller-supplied key,
// nonce, and associated data (RFC 9420 §6.3 PrivateMessage). The returned
// ciphertext includes the AEAD tag.
func (s Suite) Seal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	a, err := s.aeadCipher(key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts and authenticates ciphertext under the suite's AEAD with the
// caller-supplied key, nonce, and associated data. It returns an error if
// authentication fails.
func (s Suite) Open(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	a, err := s.aeadCipher(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ciphertext, aad)
}
