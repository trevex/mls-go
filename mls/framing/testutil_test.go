package framing

import (
	"encoding/hex"
	"testing"
)

// mustHex decodes a hex string into bytes, failing the test on error.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("mustHex(%q): %v", s, err)
	}
	return b
}
