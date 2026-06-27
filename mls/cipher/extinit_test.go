package cipher

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// RFC 9180 Appendix A.1.1 (DHKEM(X25519, HKDF-SHA256)) and A.3.1
// (DHKEM(P-256, HKDF-SHA256)) base-mode vectors: deterministic encap (fixed
// ephemeral) must reproduce enc + shared_secret exactly.
func TestExternalInitKAT(t *testing.T) {
	type vec struct {
		id              CipherSuite
		curve           ecdh.Curve
		skEm, pkRm      string
		wantEnc, wantSS string
	}
	vecs := []vec{
		{ // RFC 9180 §A.1.1
			id: X25519_AES128GCM_SHA256_Ed25519, curve: ecdh.X25519(),
			skEm:    "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
			pkRm:    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
			wantEnc: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
			wantSS:  "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
		},
		{ // RFC 9180 §A.3.1 (P-256). skEm/pkRm/enc are the SEC1 scalar / uncompressed points.
			id: P256_AES128GCM_SHA256_P256, curve: ecdh.P256(),
			skEm:    "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
			pkRm:    "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
			wantEnc: "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
			wantSS:  "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
		},
	}
	executed := 0
	for _, v := range vecs {
		suite, ok := Lookup(v.id)
		if !ok {
			t.Logf("suite %#x not registered, skipping", v.id)
			continue
		}
		executed++
		// Deterministic encap with the vector's fixed ephemeral key.
		skE, err := v.curve.NewPrivateKey(mustHex(t, v.skEm))
		if err != nil {
			t.Fatalf("%#x: skE: %v", v.id, err)
		}
		pkR, err := v.curve.NewPublicKey(mustHex(t, v.pkRm))
		if err != nil {
			t.Fatalf("%#x: pkR: %v", v.id, err)
		}
		dh, err := skE.ECDH(pkR)
		if err != nil {
			t.Fatalf("%#x: ECDH: %v", v.id, err)
		}
		enc := skE.PublicKey().Bytes()
		kemContext := append(append([]byte{}, enc...), mustHex(t, v.pkRm)...)
		ss, err := suite.extractAndExpand(dh, kemContext)
		if err != nil {
			t.Fatalf("%#x: extractAndExpand: %v", v.id, err)
		}
		if got := hex.EncodeToString(enc); got != v.wantEnc {
			t.Errorf("%#x enc:\n got %s\nwant %s", v.id, got, v.wantEnc)
		}
		if got := hex.EncodeToString(ss); got != v.wantSS {
			t.Errorf("%#x shared_secret:\n got %s\nwant %s", v.id, got, v.wantSS)
		}
	}
	if executed == 0 {
		t.Fatal("no registered suites executed")
	}
}

func TestExternalInitRoundTrip(t *testing.T) {
	executed := 0
	// Includes the X-Wing PQ suite 0xF001 — round-trip exercises the hybrid KEM.
	for _, id := range []CipherSuite{X25519_AES128GCM_SHA256_Ed25519, P256_AES128GCM_SHA256_P256, XWING_AES256GCM_SHA256_Ed25519} {
		suite, ok := Lookup(id)
		if !ok {
			continue
		}
		executed++
		// external_pub/priv from a random external_secret (here: a random keypair).
		priv, pub, err := suite.DeriveKeyPair(randomBytes(t, suite.HashLen()))
		if err != nil {
			t.Fatalf("%#x DeriveKeyPair: %v", id, err)
		}
		kemOut, ssEnc, err := suite.ExternalInitEncap(pub)
		if err != nil {
			t.Fatalf("%#x Encap: %v", id, err)
		}
		ssDec, err := suite.ExternalInitDecap(priv, kemOut)
		if err != nil {
			t.Fatalf("%#x Decap: %v", id, err)
		}
		if !bytes.Equal(ssEnc, ssDec) {
			t.Fatalf("%#x round-trip mismatch:\n encap %x\n decap %x", id, ssEnc, ssDec)
		}
	}
	if executed == 0 {
		t.Fatal("no registered suites executed")
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
