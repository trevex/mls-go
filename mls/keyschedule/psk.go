package keyschedule

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
)

// PSKType designates how a PSK was provisioned (RFC 9420 §8.4).
type PSKType uint8

const (
	PSKTypeReserved   PSKType = 0
	PSKTypeExternal   PSKType = 1
	PSKTypeResumption PSKType = 2
)

// ResumptionPSKUsage classifies a resumption PSK (RFC 9420 §8.4).
type ResumptionPSKUsage uint8

const (
	ResumptionPSKUsageReserved    ResumptionPSKUsage = 0
	ResumptionPSKUsageApplication ResumptionPSKUsage = 1
	ResumptionPSKUsageReinit      ResumptionPSKUsage = 2
	ResumptionPSKUsageBranch      ResumptionPSKUsage = 3
)

// PreSharedKeyID identifies one injected PSK (RFC 9420 §8.4):
//
//	struct {
//	    PSKType psktype;
//	    select (psktype) {
//	        case external:   opaque psk_id<V>;
//	        case resumption: ResumptionPSKUsage usage; opaque psk_group_id<V>; uint64 psk_epoch;
//	    };
//	    opaque psk_nonce<V>;
//	} PreSharedKeyID;
type PreSharedKeyID struct {
	PSKType PSKType
	// external:
	PSKID []byte
	// resumption:
	Usage      ResumptionPSKUsage
	PSKGroupID []byte
	PSKEpoch   uint64
	// both:
	PSKNonce []byte
}

func (p PreSharedKeyID) marshal(b *syntax.Builder) error {
	b.WriteUint8(uint8(p.PSKType))
	switch p.PSKType {
	case PSKTypeExternal:
		if err := b.WriteOpaqueV(p.PSKID); err != nil {
			return err
		}
	case PSKTypeResumption:
		b.WriteUint8(uint8(p.Usage))
		if err := b.WriteOpaqueV(p.PSKGroupID); err != nil {
			return err
		}
		b.WriteUint64(p.PSKEpoch)
	default:
		return fmt.Errorf("keyschedule: invalid psk_type %d", p.PSKType)
	}
	return b.WriteOpaqueV(p.PSKNonce)
}

func decodePreSharedKeyID(c *syntax.Cursor) (PreSharedKeyID, error) {
	var p PreSharedKeyID
	t, err := c.ReadUint8()
	if err != nil {
		return p, err
	}
	p.PSKType = PSKType(t)
	switch p.PSKType {
	case PSKTypeExternal:
		if p.PSKID, err = c.ReadOpaqueV(); err != nil {
			return p, err
		}
	case PSKTypeResumption:
		u, err := c.ReadUint8()
		if err != nil {
			return p, err
		}
		p.Usage = ResumptionPSKUsage(u)
		if p.PSKGroupID, err = c.ReadOpaqueV(); err != nil {
			return p, err
		}
		if p.PSKEpoch, err = c.ReadUint64(); err != nil {
			return p, err
		}
	default:
		return p, fmt.Errorf("keyschedule: invalid psk_type %d", p.PSKType)
	}
	if p.PSKNonce, err = c.ReadOpaqueV(); err != nil {
		return p, err
	}
	return p, nil
}

// pskLabel builds PSKLabel = struct{ PreSharedKeyID id; uint16 index; uint16
// count; } (RFC 9420 §8.4).
func pskLabel(id PreSharedKeyID, index, count uint16) ([]byte, error) {
	b := syntax.NewBuilder()
	if err := id.marshal(b); err != nil {
		return nil, err
	}
	b.WriteUint16(index)
	b.WriteUint16(count)
	return b.Bytes(), nil
}

// PSK pairs a PreSharedKeyID with its secret value.
type PSK struct {
	ID  PreSharedKeyID
	PSK []byte
}

// PSKSecret aggregates psks into psk_secret (RFC 9420 §8.4, Figure 24). With no
// PSKs it returns the all-zero vector of length KDF.Nh (psk_secret_[0]).
func PSKSecret(suite cipher.Suite, psks []PSK) ([]byte, error) {
	nh := suite.HashLen()
	pskSecret := make([]byte, nh) // psk_secret_[0] = 0
	count := uint16(len(psks))
	for i, p := range psks {
		// psk_extracted_[i] = KDF.Extract(0, psk_[i])
		pskExtracted, err := suite.Extract(nil, p.PSK)
		if err != nil {
			return nil, err
		}
		label, err := pskLabel(p.ID, uint16(i), count)
		if err != nil {
			return nil, err
		}
		// psk_input_[i] = ExpandWithLabel(psk_extracted_[i], "derived psk", PSKLabel, KDF.Nh)
		pskInput, err := suite.ExpandWithLabel(pskExtracted, "derived psk", label, nh)
		if err != nil {
			return nil, err
		}
		// psk_secret_[i+1] = KDF.Extract(psk_input_[i], psk_secret_[i])
		pskSecret, err = suite.Extract(pskInput, pskSecret)
		if err != nil {
			return nil, err
		}
	}
	return pskSecret, nil
}
