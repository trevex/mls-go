package cipher

import (
	"bytes"
	"crypto/mlkem"
	"strings"
	"testing"
)

// TestXWingEncapRejectsBadPubLen verifies xwingEncap returns the "external_pub
// len" error (and does not panic) when the public key is not exactly
// mlkem.EncapsulationKeySize768+32 bytes.
func TestXWingEncapRejectsBadPubLen(t *testing.T) {
	const want = mlkem.EncapsulationKeySize768 + 32
	cases := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"one short", want - 1},
		{"one long", want + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kemOut, ss, err := xwingEncap(make([]byte, tc.n))
			if err == nil {
				t.Fatalf("xwingEncap(len=%d) returned nil error; want length error", tc.n)
			}
			if !strings.Contains(err.Error(), "external_pub len") {
				t.Fatalf("xwingEncap(len=%d) error = %q, want substring %q", tc.n, err.Error(), "external_pub len")
			}
			if kemOut != nil || ss != nil {
				t.Fatalf("xwingEncap(len=%d) returned non-nil outputs on error: kemOut=%v ss=%v", tc.n, kemOut, ss)
			}
		})
	}
}

// TestXWingDecapRejectsBadKemOutputLen verifies xwingDecap returns the
// "kem_output len" error (and does not panic) when kem_output is not exactly
// mlkem.CiphertextSize768+32 bytes. The length check precedes any use of the
// private key, so a dummy private key is sufficient.
func TestXWingDecapRejectsBadKemOutputLen(t *testing.T) {
	const want = mlkem.CiphertextSize768 + 32
	cases := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"one short", want - 1},
		{"one long", want + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ss, err := xwingDecap(make([]byte, 32), make([]byte, tc.n))
			if err == nil {
				t.Fatalf("xwingDecap(kemOutput len=%d) returned nil error; want length error", tc.n)
			}
			if !strings.Contains(err.Error(), "kem_output len") {
				t.Fatalf("xwingDecap(kemOutput len=%d) error = %q, want substring %q", tc.n, err.Error(), "kem_output len")
			}
			if ss != nil {
				t.Fatalf("xwingDecap(kemOutput len=%d) returned non-nil secret on error: %v", tc.n, ss)
			}
		})
	}
}

// TestXWingDecapGarbageKemOutput verifies that a correctly-sized but garbage
// kem_output does not panic. ML-KEM uses implicit rejection, so decap may
// succeed but yield a shared secret different from a genuine encapsulation; if
// it instead errors (e.g. an invalid X25519 ct_X point), that is acceptable.
func TestXWingDecapGarbageKemOutput(t *testing.T) {
	suite, ok := Lookup(XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("X-Wing suite not registered")
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privBytes, pubBytes, err := suite.DeriveKeyPair(seed)
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}

	// A genuine encapsulation, for comparison.
	_, realSecret, err := xwingEncap(pubBytes)
	if err != nil {
		t.Fatalf("xwingEncap: %v", err)
	}

	// Correctly sized, all-0xAA garbage kem_output.
	garbage := make([]byte, mlkem.CiphertextSize768+32)
	for i := range garbage {
		garbage[i] = 0xAA
	}
	ss, derr := xwingDecap(privBytes, garbage)
	if derr != nil {
		// Errored without panicking — acceptable.
		return
	}
	// Decapped (implicit rejection): must not equal the genuine secret.
	if bytes.Equal(ss, realSecret) {
		t.Fatalf("garbage kem_output decapped to the genuine shared secret")
	}
	if len(ss) != 32 {
		t.Fatalf("garbage decap secret len %d, want 32", len(ss))
	}
}
