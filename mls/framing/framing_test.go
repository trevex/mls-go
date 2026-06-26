package framing

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/syntax"
)

func TestFramedContentRoundTripProposal(t *testing.T) {
	fc := FramedContent{
		GroupID:           []byte{0xaa, 0xbb},
		Epoch:             0x121212,
		Sender:            Sender{Type: SenderTypeMember, LeafIndex: 1},
		AuthenticatedData: nil,
		ContentType:       ContentTypeProposal,
		Content:           []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x02}, // Remove(2)
	}
	b := syntax.NewBuilder()
	if err := fc.marshal(b); err != nil {
		t.Fatal(err)
	}
	got, err := decodeFramedContent(syntax.NewCursor(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Content, fc.Content) || got.ContentType != fc.ContentType ||
		got.Sender.LeafIndex != 1 || got.Epoch != fc.Epoch {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestFramedContentRoundTripApplication(t *testing.T) {
	fc := FramedContent{
		GroupID:           []byte{0x01, 0x02},
		Epoch:             7,
		Sender:            Sender{Type: SenderTypeMember, LeafIndex: 0},
		AuthenticatedData: []byte("aad"),
		ContentType:       ContentTypeApplication,
		Content:           []byte("hello world"),
	}
	b := syntax.NewBuilder()
	if err := fc.marshal(b); err != nil {
		t.Fatal(err)
	}
	got, err := decodeFramedContent(syntax.NewCursor(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Content, fc.Content) || got.ContentType != fc.ContentType {
		t.Fatalf("application round-trip mismatch: %+v", got)
	}
}

func TestFramedContentRoundTripCommit(t *testing.T) {
	// Commit = proposals<V>(empty) + optional<UpdatePath>(absent=0x00)
	commitContent := []byte{
		0x00, // varint length=0 for proposals<V>
		0x00, // optional<UpdatePath> absent
	}
	fc := FramedContent{
		GroupID:     []byte{0x03},
		Epoch:       42,
		Sender:      Sender{Type: SenderTypeMember, LeafIndex: 2},
		ContentType: ContentTypeCommit,
		Content:     commitContent,
	}
	b := syntax.NewBuilder()
	if err := fc.marshal(b); err != nil {
		t.Fatal(err)
	}
	got, err := decodeFramedContent(syntax.NewCursor(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Content, fc.Content) || got.ContentType != fc.ContentType {
		t.Fatalf("commit round-trip mismatch: got %x want %x", got.Content, fc.Content)
	}
}
