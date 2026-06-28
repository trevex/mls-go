package cipher

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
)

// xwingKEMID is the HPKE KEM identifier for MLKEM768X25519 (X-Wing),
// draft-connolly-cfrg-xwing-kem. crypto/hpke.MLKEM768X25519().ID() == 0x647a.
const xwingKEMID = 0x647a

// xWingLabel is the X-Wing combiner domain separator: the 6 ASCII bytes "\.//^\".
var xWingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// xwingCombiner = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel).
func xwingCombiner(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	// hash.Hash.Write never returns a non-nil error per its contract.
	_, _ = h.Write(ssM)
	_, _ = h.Write(ssX)
	_, _ = h.Write(ctX)
	_, _ = h.Write(pkX)
	_, _ = h.Write(xWingLabel)
	return h.Sum(nil)
}

// xwingExpandSeed implements X-Wing expandDecapsulationKey: SHAKE256(seed, 96)
// → (ML-KEM 64-byte seed d||z) || (X25519 sk 32). VALIDATED to reproduce
// stdlib's pk_M and pk_X byte-for-byte.
func xwingExpandSeed(seed []byte) (dkM *mlkem.DecapsulationKey768, skX *ecdh.PrivateKey, err error) {
	exp := sha3.SumSHAKE256(seed, 96)
	dkM, err = mlkem.NewDecapsulationKey768(exp[0:64])
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: ML-KEM decap key: %w", err)
	}
	skX, err = ecdh.X25519().NewPrivateKey(exp[64:96])
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: X25519 sk: %w", err)
	}
	return dkM, skX, nil
}

// xwingEncap encapsulates to an X-Wing public key (the stdlib 1216-byte
// pk_M(1184)||pk_X(32)), returning kem_output = ct_M(1088)||ct_X(32) and the
// 32-byte shared secret. (RFC 9420 §8.3 init_secret for the external commit.)
func xwingEncap(externalPub []byte) (kemOutput, initSecret []byte, err error) {
	if len(externalPub) != mlkem.EncapsulationKeySize768+32 {
		return nil, nil, fmt.Errorf("cipher: xwing: external_pub len %d, want %d", len(externalPub), mlkem.EncapsulationKeySize768+32)
	}
	pkM, err := mlkem.NewEncapsulationKey768(externalPub[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: parse pk_M: %w", err)
	}
	pkXb := externalPub[mlkem.EncapsulationKeySize768:]
	pkX, err := ecdh.X25519().NewPublicKey(pkXb)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: parse pk_X: %w", err)
	}
	ssM, ctM := pkM.Encapsulate()
	ek, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: X25519 ephemeral: %w", err)
	}
	ctX := ek.PublicKey().Bytes()
	ssX, err := ek.ECDH(pkX)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: xwing: X25519 ECDH: %w", err)
	}
	ss := xwingCombiner(ssM, ssX, ctX, pkXb)
	return append(append([]byte{}, ctM...), ctX...), ss, nil
}

// xwingDecap recovers the same 32-byte shared secret from kem_output and the
// 32-byte X-Wing seed (the stdlib SerializePrivateKey form from DeriveKeyPair).
func xwingDecap(externalPriv, kemOutput []byte) (initSecret []byte, err error) {
	if len(kemOutput) != mlkem.CiphertextSize768+32 {
		return nil, fmt.Errorf("cipher: xwing: kem_output len %d, want %d", len(kemOutput), mlkem.CiphertextSize768+32)
	}
	dkM, skX, err := xwingExpandSeed(externalPriv)
	if err != nil {
		return nil, err
	}
	pkXb := skX.PublicKey().Bytes()
	ctM := kemOutput[:mlkem.CiphertextSize768]
	ctX := kemOutput[mlkem.CiphertextSize768:]
	ssM, err := dkM.Decapsulate(ctM)
	if err != nil {
		return nil, fmt.Errorf("cipher: xwing: ML-KEM decap: %w", err)
	}
	pkX, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, fmt.Errorf("cipher: xwing: parse ct_X: %w", err)
	}
	ssX, err := skX.ECDH(pkX)
	if err != nil {
		return nil, fmt.Errorf("cipher: xwing: X25519 ECDH: %w", err)
	}
	return xwingCombiner(ssM, ssX, ctX, pkXb), nil
}
