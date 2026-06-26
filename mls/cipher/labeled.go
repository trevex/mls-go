package cipher

import (
	"crypto"
	"encoding/binary"

	"github.com/trevex/mls-mlkem-go/mls/syntax"
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

// signContent builds SignContent = struct{ opaque label<V>; opaque content<V> }
// with label = "MLS 1.0 " + Label (RFC 9420 §5.1.2).
func (s Suite) signContent(label string, content []byte) ([]byte, error) {
	lbl, err := syntax.WriteOpaqueV([]byte(mlsLabelPrefix + label))
	if err != nil {
		return nil, err
	}
	body, err := syntax.WriteOpaqueV(content)
	if err != nil {
		return nil, err
	}
	return append(lbl, body...), nil
}

// SignWithLabel signs content under the labeled scheme (RFC 9420 §5.1.2).
func (s Suite) SignWithLabel(priv crypto.Signer, label string, content []byte) ([]byte, error) {
	tbs, err := s.signContent(label, content)
	if err != nil {
		return nil, err
	}
	return s.signClassical(priv, tbs)
}

// VerifyWithLabel verifies a labeled signature (RFC 9420 §5.1.2).
func (s Suite) VerifyWithLabel(pub []byte, label string, content, sig []byte) bool {
	tbs, err := s.signContent(label, content)
	if err != nil {
		return false
	}
	return s.verifyClassical(pub, tbs, sig)
}
