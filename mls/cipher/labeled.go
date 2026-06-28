package cipher

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/binary"
	"fmt"

	"github.com/trevex/mls-go/mls/syntax"
)

// mlsLabelPrefix is prepended to every label per RFC 9420 §5.
const mlsLabelPrefix = "MLS 1.0 "

// RefHash computes Hash(RefHashInput{label, value}) (RFC 9420 §5.2). The label
// is used verbatim (callers pass the full label, including any "MLS 1.0 ..."
// text as the vectors specify).
func (s Suite) RefHash(label string, value []byte) ([]byte, error) {
	lbl, err := syntax.WriteOpaqueV([]byte(label))
	if err != nil {
		return nil, err
	}
	val, err := syntax.WriteOpaqueV(value)
	if err != nil {
		return nil, err
	}
	return s.Hash(append(lbl, val...)), nil
}

// ExpandWithLabel implements RFC 9420 §8:
//
//	KDFLabel = struct{ uint16 length; opaque label<V>; opaque context<V> }
//	label = "MLS 1.0 " + Label
func (s Suite) ExpandWithLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	if length < 0 || length > 0xFFFF {
		return nil, fmt.Errorf("cipher: ExpandWithLabel: length %d out of range [0, 65535]", length)
	}
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, uint16(length))
	lbl, err := syntax.WriteOpaqueV([]byte(mlsLabelPrefix + label))
	if err != nil {
		return nil, err
	}
	buf = append(buf, lbl...)
	ctx, err := syntax.WriteOpaqueV(context)
	if err != nil {
		return nil, err
	}
	buf = append(buf, ctx...)
	return s.kdfExpand(secret, buf, length)
}

// DeriveSecret implements RFC 9420 §8:
//
//	DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "", Hash.length)
func (s Suite) DeriveSecret(secret []byte, label string) ([]byte, error) {
	return s.ExpandWithLabel(secret, label, nil, s.HashLen())
}

// DeriveTreeSecret implements RFC 9420 §7.1:
//
//	DeriveTreeSecret(Secret, Label, Generation, Length)
//	    = ExpandWithLabel(Secret, Label, encode_uint32(Generation), Length)
func (s Suite) DeriveTreeSecret(secret []byte, label string, generation uint32, length int) ([]byte, error) {
	ctx := binary.BigEndian.AppendUint32(nil, generation)
	return s.ExpandWithLabel(secret, label, ctx, length)
}

// labeledContext builds the struct{ opaque label<V>; opaque data<V> } used by
// both SignContent (RFC 9420 §5.1.2) and EncryptContext (§5.1.3), with
// label = "MLS 1.0 " + Label.
func (s Suite) labeledContext(label string, data []byte) ([]byte, error) {
	lbl, err := syntax.WriteOpaqueV([]byte(mlsLabelPrefix + label))
	if err != nil {
		return nil, err
	}
	body, err := syntax.WriteOpaqueV(data)
	if err != nil {
		return nil, err
	}
	return append(lbl, body...), nil
}

// SignaturePublicKey serializes signer's public key in the suite's
// SignaturePublicKey encoding (RFC 9420 §5.1.2): Ed25519 raw 32 bytes;
// ECDSA-P256 the uncompressed SEC1 point. The bytes are what VerifyWithLabel expects.
func (s Suite) SignaturePublicKey(signer crypto.Signer) ([]byte, error) {
	switch s.Sig {
	case SigEd25519:
		pub, ok := signer.Public().(ed25519.PublicKey)
		if !ok {
			return nil, errUnsupportedScheme
		}
		return append([]byte(nil), pub...), nil
	case SigECDSAP256:
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, errUnsupportedScheme
		}
		// ECDH().Bytes() yields the uncompressed SEC1 point (0x04‖X‖Y),
		// byte-identical to the deprecated elliptic.Marshal and matching
		// ParseUncompressedPublicKey in verifyClassical.
		ecdhPub, err := pub.ECDH()
		if err != nil {
			return nil, err
		}
		return ecdhPub.Bytes(), nil
	default:
		return nil, errUnsupportedScheme
	}
}

// SignWithLabel signs content under the labeled scheme (RFC 9420 §5.1.2).
func (s Suite) SignWithLabel(priv crypto.Signer, label string, content []byte) ([]byte, error) {
	tbs, err := s.labeledContext(label, content)
	if err != nil {
		return nil, err
	}
	return s.signClassical(priv, tbs)
}

// VerifyWithLabel verifies a labeled signature (RFC 9420 §5.1.2).
func (s Suite) VerifyWithLabel(pub []byte, label string, content, sig []byte) bool {
	tbs, err := s.labeledContext(label, content)
	if err != nil {
		return false
	}
	return s.verifyClassical(pub, tbs, sig)
}

// EncryptWithLabel implements RFC 9420 §5.1.3:
//
//	EncryptWithLabel(PublicKey, Label, Context, Plaintext)
//	    = SealBase(PublicKey, EncryptContext, "", Plaintext)
//
// EncryptContext = struct{ opaque label<V> = "MLS 1.0 "+Label; opaque
// context<V> = Context }. Returns the KEM output (HPKE enc) and AEAD
// ciphertext separately. pub is the serialized HPKEPublicKey.
func (s Suite) EncryptWithLabel(pub []byte, label string, context, plaintext []byte) (kemOutput, ciphertext []byte, err error) {
	pk, err := s.kem.NewPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	info, err := s.labeledContext(label, context)
	if err != nil {
		return nil, nil, err
	}
	enc, sender, err := hpke.NewSender(pk, s.kdf, s.aead, info)
	if err != nil {
		return nil, nil, err
	}
	ct, err := sender.Seal(nil, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return enc, ct, nil
}

// DecryptWithLabel implements RFC 9420 §5.1.3 OpenBase. priv is the serialized
// HPKEPrivateKey; kemOutput is the HPKE enc from EncryptWithLabel.
func (s Suite) DecryptWithLabel(priv []byte, label string, context, kemOutput, ciphertext []byte) ([]byte, error) {
	sk, err := s.kem.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	info, err := s.labeledContext(label, context)
	if err != nil {
		return nil, err
	}
	recipient, err := hpke.NewRecipient(kemOutput, sk, s.kdf, s.aead, info)
	if err != nil {
		return nil, err
	}
	return recipient.Open(nil, ciphertext)
}
