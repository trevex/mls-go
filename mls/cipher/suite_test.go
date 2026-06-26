package cipher

import (
	"bytes"
	"testing"
)

func TestSuiteLookup(t *testing.T) {
	cs, ok := Lookup(X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite 0x0001 not registered")
	}
	if cs.HashLen() != 32 {
		t.Fatalf("HashLen=%d, want 32", cs.HashLen())
	}
}

func TestHashAndMAC(t *testing.T) {
	cs, _ := Lookup(X25519_AES128GCM_SHA256_Ed25519)
	h1 := cs.Hash([]byte("abc"))
	h2 := cs.Hash([]byte("abc"))
	if !bytes.Equal(h1, h2) || len(h1) != 32 {
		t.Fatalf("Hash unstable or wrong length: %x / %x", h1, h2)
	}
	tag := cs.MAC([]byte("key"), []byte("msg"))
	if len(tag) != 32 {
		t.Fatalf("MAC length=%d, want 32", len(tag))
	}
}

func TestUnknownSuite(t *testing.T) {
	if _, ok := Lookup(CipherSuite(0xFFFF)); ok {
		t.Fatal("unknown suite should not resolve")
	}
}

func TestSuiteLookupBoth(t *testing.T) {
	for _, id := range []CipherSuite{X25519_AES128GCM_SHA256_Ed25519, P256_AES128GCM_SHA256_P256} {
		cs, ok := Lookup(id)
		if !ok {
			t.Fatalf("suite %#x not registered", id)
		}
		if cs.HashLen() != 32 {
			t.Fatalf("suite %#x HashLen=%d, want 32", id, cs.HashLen())
		}
		if cs.ID != id {
			t.Fatalf("suite %#x has ID %#x", id, cs.ID)
		}
	}
}
