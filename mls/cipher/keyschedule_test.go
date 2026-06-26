package cipher

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAEADSizes(t *testing.T) {
	for _, tc := range []struct {
		id     CipherSuite
		nk, nn int
	}{
		{X25519_AES128GCM_SHA256_Ed25519, 16, 12},
		{P256_AES128GCM_SHA256_P256, 16, 12},
		{XWING_AES256GCM_SHA256_Ed25519, 32, 12},
	} {
		s, ok := Lookup(tc.id)
		if !ok {
			t.Fatalf("suite %#x not registered", tc.id)
		}
		if got := s.AEADKeySize(); got != tc.nk {
			t.Errorf("suite %#x AEADKeySize=%d want %d", tc.id, got, tc.nk)
		}
		if got := s.AEADNonceSize(); got != tc.nn {
			t.Errorf("suite %#x AEADNonceSize=%d want %d", tc.id, got, tc.nn)
		}
	}
}

func TestExtractMatchesKAT(t *testing.T) {
	// key-schedule.json case 0, epoch 0: Extract(salt=initial_init_secret,
	// IKM=commit_secret) then ExpandWithLabel("joiner", group_context) == joiner_secret.
	s, _ := Lookup(X25519_AES128GCM_SHA256_Ed25519)
	initSecret := mustHex(t, "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e")
	commit := mustHex(t, "a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509")
	gc := mustHex(t, "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00")
	prk, err := s.Extract(initSecret, commit)
	if err != nil {
		t.Fatal(err)
	}
	joiner, err := s.ExpandWithLabel(prk, "joiner", gc, s.HashLen())
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "4fb996ba26b29a70f3ce6c310151ce8701cb812d027f4d4bbf5cc4e9f884638d")
	if !bytes.Equal(joiner, want) {
		t.Fatalf("joiner=%x want %x", joiner, want)
	}
}

func TestDeriveKeyPairMatchesKAT(t *testing.T) {
	// key-schedule.json case 0, epoch 0: DeriveKeyPair(external_secret).pub == external_pub.
	s, _ := Lookup(X25519_AES128GCM_SHA256_Ed25519)
	external := mustHex(t, "b5cb5666cfb9c501ed76715c6ed1cafbed5061cd6b86898ae5d3fd4cb05abb26")
	_, pub, err := s.DeriveKeyPair(external)
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "640117516be304ac1160933c894a6df9290231f1843f3685c124fc42c785c02c")
	if !bytes.Equal(pub, want) {
		t.Fatalf("external_pub=%x want %x", pub, want)
	}
}
