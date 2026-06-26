package cipher

import (
	"crypto/hpke"
	"crypto/sha256"
)

// XWING_AES256GCM_SHA256_Ed25519 is a private-use (RFC 9420 §17.1 range
// 0xF000–0xFFFF) post-quantum ciphersuite: HPKE over the X-Wing hybrid KEM
// (X25519 + ML-KEM-768, draft-connolly-cfrg-xwing-kem, HPKE KEM id 0x647a),
// AES-256-GCM, SHA-256, with classical Ed25519 signatures. See design spec §7
// for why signatures stay classical.
const XWING_AES256GCM_SHA256_Ed25519 CipherSuite = 0xF001

func init() {
	registry[XWING_AES256GCM_SHA256_Ed25519] = Suite{
		ID:      XWING_AES256GCM_SHA256_Ed25519,
		NewHash: sha256.New,
		Sig:     SigEd25519,
		kem:     hpke.MLKEM768X25519(), // X-Wing
		kdf:     hpke.HKDFSHA256(),
		aead:    hpke.AES256GCM(),
	}
}
