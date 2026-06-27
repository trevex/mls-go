// Package ironcore is the IronCore integration layer (design spec §3/§10).
// It turns the domain-agnostic MLS engine in mls/ into a per-VNI
// key-agreement service for IronCore underlay encryption: VNI↔GroupID
// mapping, exporter→ESP-SA derivation, SPIFFE/PKI credential adapters,
// and the VNIGroup wrapper.
package ironcore

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

var groupIDTag = []byte("ICVNI1") // 6-byte versioned tag for VNI-derived GroupIDs

// GroupID returns the stable MLS GroupID for a VNI (design spec §10.1).
func GroupID(vni uint32) []byte {
	b := make([]byte, len(groupIDTag)+4)
	copy(b, groupIDTag)
	binary.BigEndian.PutUint32(b[len(groupIDTag):], vni)
	return b
}

// VNIOfGroupID is the inverse of GroupID. It fails on any non-VNI GroupID.
func VNIOfGroupID(gid []byte) (uint32, error) {
	if len(gid) != len(groupIDTag)+4 || !bytes.Equal(gid[:len(groupIDTag)], groupIDTag) {
		return 0, fmt.Errorf("ironcore: not a VNI GroupID: %x", gid)
	}
	return binary.BigEndian.Uint32(gid[len(groupIDTag):]), nil
}
