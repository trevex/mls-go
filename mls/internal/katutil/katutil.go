// Package katutil provides JSON helpers for loading the official MLS
// known-answer-test (KAT) vectors vendored under mls/testdata.
package katutil

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// HexBytes unmarshals a JSON hex string into raw bytes. An empty or absent
// JSON string decodes to a nil slice.
type HexBytes []byte

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*h = nil
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

// Load reads and JSON-decodes a vendored KAT file into v. The name is the
// bare file name, e.g. "tree-math.json". Tests live one directory below the
// module root, so testdata is resolved relative to the caller's package dir.
func Load(t *testing.T, name string, v any) {
	t.Helper()
	path := filepath.Join("..", "testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
}
