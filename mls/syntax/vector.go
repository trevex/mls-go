package syntax

import "fmt"

// WriteVectorV encodes items as an MLS <V> vector of variable-length elements:
// a varint length prefix over the concatenation of each item's encoding.
func WriteVectorV[T any](b *Builder, items []T, enc func(*Builder, T) error) error {
	inner := NewBuilder()
	for _, it := range items {
		if err := enc(inner, it); err != nil {
			return err
		}
	}
	return b.WriteOpaqueV(inner.Bytes())
}

// ReadVectorV decodes an MLS <V> vector: it reads the length-prefixed body, then
// applies dec repeatedly until the body is exactly exhausted. A dec that reads
// past the body boundary surfaces as a short-read error from the inner cursor.
func ReadVectorV[T any](c *Cursor, dec func(*Cursor) (T, error)) ([]T, error) {
	body, err := c.ReadOpaqueV()
	if err != nil {
		return nil, err
	}
	sub := NewCursor(body)
	out := make([]T, 0)
	for !sub.Empty() {
		v, err := dec(sub)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// WriteOptional encodes optional<T> (RFC 9420 §2.1.1): a presence byte (0 absent,
// 1 present) followed by the value when present.
func WriteOptional[T any](b *Builder, v *T, enc func(*Builder, T) error) error {
	if v == nil {
		b.WriteUint8(0)
		return nil
	}
	b.WriteUint8(1)
	return enc(b, *v)
}

// ReadOptional decodes optional<T>.
func ReadOptional[T any](c *Cursor, dec func(*Cursor) (T, error)) (*T, error) {
	present, err := c.ReadUint8()
	if err != nil {
		return nil, err
	}
	switch present {
	case 0:
		return nil, nil
	case 1:
		v, err := dec(c)
		if err != nil {
			return nil, err
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("syntax: invalid optional presence byte %d", present)
	}
}
