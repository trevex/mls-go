package syntax_test

import (
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
)

type deserCase struct {
	VLBytesHeader katutil.HexBytes `json:"vlbytes_header"`
	Length        uint64           `json:"length"`
}

func TestDeserializationKAT(t *testing.T) {
	var cases []deserCase
	katutil.Load(t, "deserialization.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no deserialization vectors loaded")
	}
	for i, c := range cases {
		got, n, err := syntax.ReadVarint(c.VLBytesHeader)
		if err != nil {
			t.Fatalf("case %d: ReadVarint(%x): %v", i, c.VLBytesHeader, err)
		}
		if got != c.Length {
			t.Fatalf("case %d: length got %d, want %d", i, got, c.Length)
		}
		if n != len(c.VLBytesHeader) {
			t.Fatalf("case %d: consumed %d bytes, header is %d", i, n, len(c.VLBytesHeader))
		}
	}
}
