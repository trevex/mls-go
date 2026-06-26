package syntax

import (
	"encoding/binary"
	"fmt"
)

// Builder is an append-only buffer for encoding MLS wire structures.
type Builder struct {
	buf []byte
}

// NewBuilder returns an empty Builder.
func NewBuilder() *Builder { return &Builder{} }

func (b *Builder) WriteUint8(v uint8)   { b.buf = append(b.buf, v) }
func (b *Builder) WriteUint16(v uint16) { b.buf = binary.BigEndian.AppendUint16(b.buf, v) }
func (b *Builder) WriteUint32(v uint32) { b.buf = binary.BigEndian.AppendUint32(b.buf, v) }
func (b *Builder) WriteUint64(v uint64) { b.buf = binary.BigEndian.AppendUint64(b.buf, v) }

// WriteRaw appends bytes with no length prefix.
func (b *Builder) WriteRaw(p []byte) { b.buf = append(b.buf, p...) }

// WriteVarint appends a variable-length integer (RFC 9420 §2.1.2).
func (b *Builder) WriteVarint(v uint64) error {
	enc, err := WriteVarint(v)
	if err != nil {
		return err
	}
	b.buf = append(b.buf, enc...)
	return nil
}

// WriteOpaqueV appends a varint-length-prefixed byte vector (opaque<V>).
func (b *Builder) WriteOpaqueV(p []byte) error {
	if err := b.WriteVarint(uint64(len(p))); err != nil {
		return err
	}
	b.buf = append(b.buf, p...)
	return nil
}

// Bytes returns the accumulated encoding. The result aliases the Builder's
// buffer; do not mutate it while still using the Builder.
func (b *Builder) Bytes() []byte { return b.buf }

// Cursor consumes an MLS wire encoding from front to back.
type Cursor struct {
	buf []byte
}

// NewCursor returns a Cursor over b.
func NewCursor(b []byte) *Cursor { return &Cursor{buf: b} }

// Remaining returns the number of unread bytes.
func (c *Cursor) Remaining() int { return len(c.buf) }

// Empty reports whether all bytes have been consumed.
func (c *Cursor) Empty() bool { return len(c.buf) == 0 }

func (c *Cursor) take(n int) ([]byte, error) {
	if n < 0 || len(c.buf) < n {
		return nil, fmt.Errorf("syntax: short read: need %d, have %d", n, len(c.buf))
	}
	p := c.buf[:n]
	c.buf = c.buf[n:]
	return p, nil
}

func (c *Cursor) ReadUint8() (uint8, error) {
	p, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return p[0], nil
}

func (c *Cursor) ReadUint16() (uint16, error) {
	p, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(p), nil
}

func (c *Cursor) ReadUint32() (uint32, error) {
	p, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(p), nil
}

func (c *Cursor) ReadUint64() (uint64, error) {
	p, err := c.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(p), nil
}

// ReadRaw consumes exactly n bytes. The returned slice aliases the underlying
// buffer; copy it if you need to retain it past further mutation of the source.
func (c *Cursor) ReadRaw(n int) ([]byte, error) { return c.take(n) }

// ReadVarint consumes a variable-length integer.
func (c *Cursor) ReadVarint() (uint64, error) {
	v, n, err := ReadVarint(c.buf)
	if err != nil {
		return 0, err
	}
	c.buf = c.buf[n:]
	return v, nil
}

// ReadOpaqueV consumes a varint-length-prefixed byte vector.
func (c *Cursor) ReadOpaqueV() ([]byte, error) {
	n, err := c.ReadVarint()
	if err != nil {
		return nil, err
	}
	return c.take(int(n))
}
