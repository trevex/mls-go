// Package syntax implements the RFC 9420 presentation-language wire encoding:
// QUIC-style variable-length integers (§2.1.2) and opaque<V> byte vectors.
package syntax

import "fmt"

// MaxVarint is the largest length RFC 9420 permits (2^30 - 1); the 8-byte
// QUIC varint form is disallowed.
const MaxVarint = (1 << 30) - 1

// WriteVarint encodes v using the minimal 1-, 2-, or 4-byte form.
func WriteVarint(v uint64) ([]byte, error) {
	switch {
	case v < (1 << 6):
		return []byte{byte(v)}, nil
	case v < (1 << 14):
		return []byte{0x40 | byte(v>>8), byte(v)}, nil
	case v <= MaxVarint:
		return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}, nil
	default:
		return nil, fmt.Errorf("syntax: varint %d exceeds max %d", v, MaxVarint)
	}
}

// ReadVarint decodes a varint from the front of b, returning the value and the
// number of bytes consumed. It enforces minimal encoding and rejects the
// 8-byte form, per RFC 9420 §2.1.2.
func ReadVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("syntax: empty varint")
	}
	prefix := b[0] >> 6
	if prefix == 3 {
		return 0, 0, fmt.Errorf("syntax: 8-byte varint not allowed in MLS")
	}
	length := 1 << prefix // 1, 2, or 4
	if len(b) < length {
		return 0, 0, fmt.Errorf("syntax: short varint: need %d, have %d", length, len(b))
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = (v << 8) | uint64(b[i])
	}
	// WriteVarint cannot fail here: v is bounded by its decoded prefix range.
	canon, _ := WriteVarint(v)
	if len(canon) != length {
		return 0, 0, fmt.Errorf("syntax: non-minimal varint encoding")
	}
	return v, length, nil
}

// WriteOpaqueV encodes b as a varint length prefix followed by the bytes.
func WriteOpaqueV(b []byte) ([]byte, error) {
	hdr, err := WriteVarint(uint64(len(b)))
	if err != nil {
		return nil, err
	}
	return append(hdr, b...), nil
}

// ReadOpaqueV decodes a varint-prefixed byte vector, returning the contents and
// total bytes consumed (prefix + body). The returned slice is a sub-slice of b;
// callers who need to retain it after b is modified must copy it.
func ReadOpaqueV(b []byte) ([]byte, int, error) {
	n, hdrLen, err := ReadVarint(b)
	if err != nil {
		return nil, 0, err
	}
	total := hdrLen + int(n)
	if len(b) < total {
		return nil, 0, fmt.Errorf("syntax: short opaque<V>: need %d, have %d", total, len(b))
	}
	return b[hdrLen:total], total, nil
}
