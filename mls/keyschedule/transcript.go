package keyschedule

import (
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/syntax"
)

// ConfirmationTag computes a Commit's confirmation MAC (RFC 9420 §6.1):
//
//	confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)
func ConfirmationTag(suite cipher.Suite, confirmationKey, confirmedTranscriptHash []byte) []byte {
	return suite.MAC(confirmationKey, confirmedTranscriptHash)
}

// ConfirmedTranscriptHash updates the confirmed transcript hash (RFC 9420 §8.2):
//
//	confirmed_[n] = Hash(interim_[n-1] || ConfirmedTranscriptHashInput_[n])
func ConfirmedTranscriptHash(suite cipher.Suite, interimPrev, confirmedInput []byte) []byte {
	h := suite.NewHash()
	h.Write(interimPrev)
	h.Write(confirmedInput)
	return h.Sum(nil)
}

// InterimTranscriptHash updates the interim transcript hash (RFC 9420 §8.2):
//
//	interim_[n] = Hash(confirmed_[n] || InterimTranscriptHashInput_[n])
//	InterimTranscriptHashInput = struct { MAC confirmation_tag; }   // opaque<V>
func InterimTranscriptHash(suite cipher.Suite, confirmed, confirmationTag []byte) ([]byte, error) {
	in, err := syntax.WriteOpaqueV(confirmationTag)
	if err != nil {
		return nil, err
	}
	h := suite.NewHash()
	h.Write(confirmed)
	h.Write(in)
	return h.Sum(nil), nil
}

// SplitAuthenticatedContent splits a serialized Commit AuthenticatedContent into
// its ConfirmedTranscriptHashInput bytes and its confirmation_tag value
// (RFC 9420 §6/§8.2).
//
// AuthenticatedContent = wire_format || FramedContent content || FramedContentAuthData auth,
// and for a Commit auth = opaque signature<V> || MAC confirmation_tag<V>, so
// ConfirmedTranscriptHashInput (= wire_format || content || signature) is exactly
// the AuthenticatedContent with the trailing confirmation_tag<V> field removed.
// confirmation_tag is a MAC of fixed length KDF.Nh, so its serialized field
// length is deterministic and the field is peeled from the end without parsing
// the FramedContent/Commit body (full framing is implemented in a later plan).
func SplitAuthenticatedContent(suite cipher.Suite, ac []byte) (confirmedInput, confirmationTag []byte, err error) {
	macLen := suite.HashLen()
	field, err := syntax.WriteOpaqueV(make([]byte, macLen))
	if err != nil {
		return nil, nil, err
	}
	if len(ac) < len(field) {
		return nil, nil, fmt.Errorf("keyschedule: authenticated_content too short (%d < %d)", len(ac), len(field))
	}
	confirmedInput = ac[:len(ac)-len(field)]
	confirmationTag = ac[len(ac)-macLen:]
	return confirmedInput, confirmationTag, nil
}
