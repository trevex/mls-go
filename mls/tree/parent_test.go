package tree

import (
	"bytes"
	"testing"
)

func TestParentNodeRoundTrip(t *testing.T) {
	in := ParentNode{
		EncryptionKey:  []byte("enc"),
		ParentHash:     []byte("ph"),
		UnmergedLeaves: []uint32{1, 4, 9},
	}
	enc, err := in.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	var out ParentNode
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.EncryptionKey, in.EncryptionKey) || !bytes.Equal(out.ParentHash, in.ParentHash) ||
		len(out.UnmergedLeaves) != 3 || out.UnmergedLeaves[2] != 9 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestParentNodeEmptyUnmerged(t *testing.T) {
	in := ParentNode{EncryptionKey: []byte("e"), ParentHash: nil, UnmergedLeaves: nil}
	enc, _ := in.MarshalMLS()
	var out ParentNode
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if len(out.UnmergedLeaves) != 0 || len(out.ParentHash) != 0 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}
