package cipher

import (
	"crypto/hkdf"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// errExternalInitUnsupported is returned for suites whose KEM is neither a
// DHKEM curve nor X-Wing (0x647a) — i.e. no external-init derivation is defined.
var errExternalInitUnsupported = errors.New("cipher: external init not supported for this KEM")

// kemSuiteID is the RFC 9180 §4.1 KEM suite_id = "KEM" || I2OSP(kem_id, 2).
func (s Suite) kemSuiteID() []byte {
	return binary.BigEndian.AppendUint16([]byte("KEM"), s.kem.ID())
}

// labeledExtract implements RFC 9180 §4: LabeledExtract(salt, label, ikm) =
// Extract(salt, "HPKE-v1" || suite_id || label || ikm).
func (s Suite) labeledExtract(salt []byte, label string, ikm []byte) ([]byte, error) {
	labeledIKM := append([]byte("HPKE-v1"), s.kemSuiteID()...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdf.Extract(s.NewHash, labeledIKM, salt)
}

// labeledExpand implements RFC 9180 §4: LabeledExpand(prk, label, info, L) =
// Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L).
func (s Suite) labeledExpand(prk []byte, label string, info []byte, length int) ([]byte, error) {
	var li []byte
	li = binary.BigEndian.AppendUint16(li, uint16(length))
	li = append(li, "HPKE-v1"...)
	li = append(li, s.kemSuiteID()...)
	li = append(li, label...)
	li = append(li, info...)
	return s.kdfExpand(prk, li, length)
}

// extractAndExpand is RFC 9180 §4.1 ExtractAndExpand(dh, kem_context), producing
// the KEM shared_secret of length Nsecret (= KDF.Nh = HashLen for our suites).
func (s Suite) extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	eaePrk, err := s.labeledExtract(nil, "eae_prk", dh)
	if err != nil {
		return nil, err
	}
	return s.labeledExpand(eaePrk, "shared_secret", kemContext, s.HashLen())
}

// ExternalInitEncap performs RFC 9420 §8.3 / RFC 9180 §4.1 DHKEM encapsulation to
// the group's external_pub: it returns kem_output (the serialized ephemeral
// public key, to ship in an ExternalInit proposal) and init_secret (the bare KEM
// shared secret used VERBATIM — no MLS label — as the external commit's new-epoch
// init_secret salt). externalPub is the serialized HPKEPublicKey from the
// GroupInfo external_pub extension.
func (s Suite) ExternalInitEncap(externalPub []byte) (kemOutput, initSecret []byte, err error) {
	if s.curve == nil {
		if s.kem.ID() == xwingKEMID { // 0x647a — X-Wing (see xwing.go)
			return xwingEncap(externalPub)
		}
		return nil, nil, fmt.Errorf("%w (kem_id %#x)", errExternalInitUnsupported, s.kem.ID())
	}
	pkR, err := s.curve.NewPublicKey(externalPub)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: ExternalInitEncap: parse external_pub: %w", err)
	}
	skE, err := s.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: ExternalInitEncap: ephemeral keygen: %w", err)
	}
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher: ExternalInitEncap: ECDH: %w", err)
	}
	enc := skE.PublicKey().Bytes()
	kemContext := append(append([]byte{}, enc...), externalPub...)
	ss, err := s.extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return enc, ss, nil
}

// ExternalInitDecap performs the receiving side of RFC 9420 §8.3: existing
// members recover the same init_secret from kem_output and external_priv (the
// serialized HPKEPrivateKey from keyschedule.ExternalPub).
func (s Suite) ExternalInitDecap(externalPriv, kemOutput []byte) (initSecret []byte, err error) {
	if s.curve == nil {
		if s.kem.ID() == xwingKEMID { // 0x647a — X-Wing (see xwing.go)
			return xwingDecap(externalPriv, kemOutput)
		}
		return nil, fmt.Errorf("%w (kem_id %#x)", errExternalInitUnsupported, s.kem.ID())
	}
	skR, err := s.curve.NewPrivateKey(externalPriv)
	if err != nil {
		return nil, fmt.Errorf("cipher: ExternalInitDecap: parse external_priv: %w", err)
	}
	pkE, err := s.curve.NewPublicKey(kemOutput)
	if err != nil {
		return nil, fmt.Errorf("cipher: ExternalInitDecap: parse kem_output: %w", err)
	}
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, fmt.Errorf("cipher: ExternalInitDecap: ECDH: %w", err)
	}
	kemContext := append(append([]byte{}, kemOutput...), skR.PublicKey().Bytes()...)
	return s.extractAndExpand(dh, kemContext)
}
