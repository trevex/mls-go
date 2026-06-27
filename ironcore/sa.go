package ironcore

import (
	"encoding/binary"
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
)

const (
	espExporterLabel = "ironcore-esp" // design spec §10.4 verbatim
	saKeyLen         = 32             // AES-256-GCM key length (the X-Wing suite AEAD)
	saSaltLen        = 4              // RFC 4106 AES-GCM-ESP salt length
)

// SA is one IronCore ESP security association derived from an MLS epoch
// (design spec §10.4). It feeds the dpservice/metalnet XFRM data plane.
type SA struct {
	VNI      uint32 // the VNI this SA protects
	Epoch    uint64 // the MLS epoch it was derived from
	SPI      uint32 // ESP SPI (epoch-encoded; > 255)
	Key      []byte // K_group: 32-byte AES-256-GCM group key
	OwnLeaf  uint32 // this member's leaf index
	OwnSalt  []byte // 4-byte GCM nonce salt for this member's own sender nonce space
	saltMask []byte // per-epoch 4-byte mask: SenderSalt(leaf) = saltMask XOR BE32(leaf)
	suite    cipher.Suite
}

// saContext encodes VNI‖epoch as a 12-byte context for MLS-Exporter and
// ExpandWithLabel calls (design spec §10.4): 4-byte big-endian VNI followed
// by 8-byte big-endian epoch.
func saContext(vni uint32, epoch uint64) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint32(b[0:4], vni)
	binary.BigEndian.PutUint64(b[4:12], epoch)
	return b
}

// deriveSPI derives the 32-bit ESP SPI from K_group (design spec §10.4).
// The epoch's low byte is embedded to disambiguate overlapping (make-before-break)
// epochs; the MSB is forced set to keep the SPI out of the RFC 4303 §2.1
// reserved range (0..255).
func deriveSPI(suite cipher.Suite, kGroup []byte, vni uint32, epoch uint64) (uint32, error) {
	raw, err := suite.ExpandWithLabel(kGroup, "esp-spi", saContext(vni, epoch), 4)
	if err != nil {
		return 0, fmt.Errorf("ironcore: derive SPI: %w", err)
	}
	spi := binary.BigEndian.Uint32(raw)
	spi = (spi &^ 0xFF) | uint32(uint8(epoch)) // epoch low byte → disambiguates overlapping epochs
	spi |= 0x80000000                          // keep SPI > 255 (RFC 4303 §2.1 reserved range)
	return spi, nil
}

// SenderSalt returns the 4-byte RFC 4106 AES-GCM-ESP nonce salt for sender
// leafIndex (design spec §10.4 "GCM nonce safety"). The salt is computed as
// saltMask XOR BE32(leafIndex), where saltMask is a per-epoch constant derived
// once in DeriveSAKeys. XOR with a constant is a bijection: distinct leaf
// indices always produce distinct salts (guaranteed injective, not merely
// probabilistic). Each sender therefore gets a guaranteed-disjoint nonce space:
// nonce = SenderSalt(leaf) ‖ IV(8).
func (sa SA) SenderSalt(leafIndex uint32) ([]byte, error) {
	if len(sa.saltMask) != saSaltLen {
		return nil, fmt.Errorf("ironcore: SA saltMask not initialized (use DeriveSAKeys)")
	}
	leaf := make([]byte, saSaltLen)
	binary.BigEndian.PutUint32(leaf, leafIndex)
	salt := make([]byte, saSaltLen)
	for i := range salt {
		salt[i] = sa.saltMask[i] ^ leaf[i]
	}
	return salt, nil
}

// DeriveSAKeys derives the IronCore ESP SA for the given group at its current
// epoch (design spec §10.4). All members of the VNI group obtain byte-identical
// Key and SPI; OwnSalt gives this member's disjoint GCM nonce space.
func DeriveSAKeys(g *group.Group, vni uint32) (SA, error) {
	suite, ok := cipher.Lookup(g.GroupContext().CipherSuite)
	if !ok {
		return SA{}, fmt.Errorf("ironcore: unregistered cipher suite %#x", g.GroupContext().CipherSuite)
	}
	epoch := g.Epoch()
	kGroup, err := g.Exporter(espExporterLabel, saContext(vni, epoch), saKeyLen)
	if err != nil {
		return SA{}, fmt.Errorf("ironcore: derive K_group: %w", err)
	}
	spi, err := deriveSPI(suite, kGroup, vni, epoch)
	if err != nil {
		return SA{}, err
	}
	sa := SA{VNI: vni, Epoch: epoch, SPI: spi, Key: kGroup, OwnLeaf: g.OwnLeaf(), suite: suite}
	// Derive the per-epoch salt mask once. SenderSalt(leaf) = saltMask XOR BE32(leaf),
	// which is injective in leaf: two distinct leaves can never produce the same salt.
	sa.saltMask, err = suite.ExpandWithLabel(kGroup, "esp-salt-mask", nil, saSaltLen)
	if err != nil {
		return SA{}, fmt.Errorf("ironcore: derive salt mask: %w", err)
	}
	if sa.OwnSalt, err = sa.SenderSalt(g.OwnLeaf()); err != nil {
		return SA{}, err
	}
	return sa, nil
}
