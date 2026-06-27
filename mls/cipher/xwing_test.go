package cipher

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/sha3"
	"testing"
)

// TestXWingStdlibSplit verifies that the stdlib X-Wing public key (1216 bytes)
// splits as pk_M(1184) || pk_X(32), and that SHAKE256(seed, 96) reconstruction
// reproduces the stdlib pk_M and pk_X byte-for-byte (Option A validation).
func TestXWingStdlibSplit(t *testing.T) {
	suite, ok := Lookup(XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("X-Wing suite not registered")
	}
	// Generate a fresh X-Wing keypair via DeriveKeyPair.
	seed := randomBytes(t, 32)
	privBytes, pubBytes, err := suite.DeriveKeyPair(seed)
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}

	// Public key must be 1216 bytes = pk_M(1184) || pk_X(32).
	if len(pubBytes) != mlkem.EncapsulationKeySize768+32 {
		t.Fatalf("X-Wing pub len %d, want %d", len(pubBytes), mlkem.EncapsulationKeySize768+32)
	}

	// Private key must be 32 bytes (X-Wing seed).
	if len(privBytes) != 32 {
		t.Fatalf("X-Wing priv len %d, want 32", len(privBytes))
	}

	// Expand the seed via SHAKE256(seed, 96) → (d||z) || sk_X.
	exp := sha3.SumSHAKE256(privBytes, 96)

	// Reconstruct dk_M from exp[0:64] and verify its encapsulation key matches pk_M.
	dkM, err := mlkem.NewDecapsulationKey768(exp[0:64])
	if err != nil {
		t.Fatalf("NewDecapsulationKey768: %v", err)
	}
	reconstructedPkM := dkM.EncapsulationKey().Bytes()
	if !bytes.Equal(reconstructedPkM, pubBytes[:mlkem.EncapsulationKeySize768]) {
		t.Errorf("reconstructed pk_M mismatch:\n got  %x...\n want %x...",
			reconstructedPkM[:8], pubBytes[:8])
	}

	// Reconstruct sk_X from exp[64:96] and verify its public key matches pk_X.
	skX, err := ecdh.X25519().NewPrivateKey(exp[64:96])
	if err != nil {
		t.Fatalf("X25519 NewPrivateKey: %v", err)
	}
	reconstructedPkX := skX.PublicKey().Bytes()
	if !bytes.Equal(reconstructedPkX, pubBytes[mlkem.EncapsulationKeySize768:]) {
		t.Errorf("reconstructed pk_X mismatch:\n got  %x\n want %x",
			reconstructedPkX, pubBytes[mlkem.EncapsulationKeySize768:])
	}
}

// TestXWingCombinerLabel verifies the domain separator bytes are exactly "\.//^\".
func TestXWingCombinerLabel(t *testing.T) {
	want := []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}
	if !bytes.Equal(xWingLabel, want) {
		t.Errorf("xWingLabel = %x, want %x", xWingLabel, want)
	}
}

// TestXWingEncapDecapRoundTrip encap/decaps over many random DeriveKeyPair
// keypairs and verifies the 32-byte shared secret is identical each time.
func TestXWingEncapDecapRoundTrip(t *testing.T) {
	suite, ok := Lookup(XWING_AES256GCM_SHA256_Ed25519)
	if !ok {
		t.Skip("X-Wing suite not registered")
	}
	for i := 0; i < 20; i++ {
		seed := randomBytes(t, 32)
		privBytes, pubBytes, err := suite.DeriveKeyPair(seed)
		if err != nil {
			t.Fatalf("iter %d DeriveKeyPair: %v", i, err)
		}
		kemOut, ssEnc, err := xwingEncap(pubBytes)
		if err != nil {
			t.Fatalf("iter %d xwingEncap: %v", i, err)
		}
		ssDec, err := xwingDecap(privBytes, kemOut)
		if err != nil {
			t.Fatalf("iter %d xwingDecap: %v", i, err)
		}
		if !bytes.Equal(ssEnc, ssDec) {
			t.Fatalf("iter %d round-trip mismatch:\n encap %x\n decap %x", i, ssEnc, ssDec)
		}
		if len(ssEnc) != 32 {
			t.Fatalf("iter %d shared secret len %d, want 32", i, len(ssEnc))
		}
	}
}
