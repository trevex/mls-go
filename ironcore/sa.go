package ironcore

import (
	"encoding/binary"
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
)

const (
	espExporterLabel = "ironcore-esp" // design spec §10.4 verbatim
	saKeyLen         = 32             // AES-256-GCM key length (the X-Wing suite AEAD)
	saSaltLen        = 4              // RFC 4106 AES-GCM-ESP salt length
)

// SA is one IronCore ESP security association derived from an MLS epoch
// (design spec §10.4). It feeds the dpservice/metalnet XFRM data plane.
//
// Each member sends under its own per-sender SPI (OwnSPI / SenderSPI(leaf)) so
// every sender occupies a distinct RFC 4303 anti-replay window; a receiver
// installs one inbound SA per sender (InboundSAs). The group-wide SPI field is
// retained for the single-shared-SPI case, but per-sender data planes must not
// use it for anti-replay (all senders would share one window and collide).
type SA struct {
	VNI      uint32 // the VNI this SA protects
	Epoch    uint64 // the MLS epoch it was derived from
	SPI      uint32 // group ESP SPI (leaf-independent; per-sender data planes use OwnSPI/SenderSPI)
	Key      []byte // K_group: 32-byte AES-256-GCM group key
	OwnLeaf  uint32 // this member's leaf index
	OwnSalt  []byte // 4-byte GCM nonce salt for this member's own sender nonce space
	OwnSPI   uint32 // this member's own outbound ESP SPI = SenderSPI(OwnLeaf)
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

// spiContext encodes VNI‖epoch‖leaf as the 16-byte context for a per-sender SPI.
func spiContext(vni uint32, epoch uint64, leaf uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b[0:4], vni)
	binary.BigEndian.PutUint64(b[4:12], epoch)
	binary.BigEndian.PutUint32(b[12:16], leaf)
	return b
}

// deriveSenderSPI derives sender `leaf`'s 32-bit ESP SPI from K_group. Like the
// group SPI it embeds the epoch low byte (make-before-break overlap demux) and
// forces the MSB (keep SPI > 255, RFC 4303 §2.1). The remaining 23 bits are a
// function of the leaf, so distinct senders get distinct SPIs w.h.p. (birthday
// bound ~ M^2/2^24 per epoch — negligible for realistic M; collisions among
// active members are detected in InboundSAs and resolved by a rekey).
func deriveSenderSPI(suite cipher.Suite, kGroup []byte, vni uint32, epoch uint64, leaf uint32) (uint32, error) {
	raw, err := suite.ExpandWithLabel(kGroup, "esp-spi-sender", spiContext(vni, epoch, leaf), 4)
	if err != nil {
		return 0, fmt.Errorf("ironcore: derive sender SPI: %w", err)
	}
	spi := binary.BigEndian.Uint32(raw)
	spi = (spi &^ 0xFF) | uint32(uint8(epoch))
	spi |= 0x80000000
	return spi, nil
}

// SenderSPI returns the per-sender ESP SPI for sender leafIndex at this SA's
// epoch. All members compute identical values (shared K_group), so a receiver
// can install one inbound SA per sender keyed by this SPI.
func (sa SA) SenderSPI(leafIndex uint32) (uint32, error) {
	if len(sa.Key) == 0 {
		return 0, fmt.Errorf("ironcore: SA key not initialized (use DeriveSAKeys)")
	}
	return deriveSenderSPI(sa.suite, sa.Key, sa.VNI, sa.Epoch, leafIndex)
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

// InboundSA is one per-sender ESP inbound security association: the data plane
// installs one of these per active member leaf so every sender occupies its own
// SPI and hence its own RFC 4303 anti-replay window.
type InboundSA struct {
	Leaf uint32 // sender's MLS leaf index
	SPI  uint32 // sender's per-sender SPI
	Key  []byte // shared K_group (32-byte AES-256-GCM key)
	Salt []byte // sender's 4-byte GCM nonce salt
}

// InboundSAs returns one InboundSA per leaf in leaves (typically the group's
// active member leaves). It returns an error if two leaves map to the same SPI
// (a birthday collision in the 23-bit SPI space); the caller resolves this by
// forcing a rekey, which reshuffles every SPI.
func (sa SA) InboundSAs(leaves []uint32) ([]InboundSA, error) {
	out := make([]InboundSA, 0, len(leaves))
	seen := make(map[uint32]uint32, len(leaves)) // spi -> leaf
	for _, leaf := range leaves {
		spi, err := sa.SenderSPI(leaf)
		if err != nil {
			return nil, err
		}
		if other, dup := seen[spi]; dup {
			return nil, fmt.Errorf("ironcore: SPI collision %#x between leaves %d and %d (rekey to resolve)", spi, other, leaf)
		}
		seen[spi] = leaf
		salt, err := sa.SenderSalt(leaf)
		if err != nil {
			return nil, err
		}
		out = append(out, InboundSA{Leaf: leaf, SPI: spi, Key: sa.Key, Salt: salt})
	}
	return out, nil
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
	if sa.OwnSPI, err = sa.SenderSPI(g.OwnLeaf()); err != nil {
		return SA{}, err
	}
	return sa, nil
}
