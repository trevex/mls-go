package keyschedule

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/tree"
)

func TestDeriveEpochSecretsEpoch0(t *testing.T) {
	// key-schedule.json case 0, epoch 0 (suite 1), psk_secret given directly.
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	gc := GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:                 hx(t, "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"),
		Epoch:                   0,
		TreeHash:                hx(t, "9769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818"),
		ConfirmedTranscriptHash: hx(t, "5e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f"),
	}
	gcBytes, _ := gc.MarshalMLS()
	es, err := DeriveEpochSecrets(s,
		hx(t, "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"), // init_secret
		hx(t, "a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509"), // commit_secret
		hx(t, "e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b"), // psk_secret
		gcBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(es.JoinerSecret, hx(t, "4fb996ba26b29a70f3ce6c310151ce8701cb812d027f4d4bbf5cc4e9f884638d")) {
		t.Errorf("joiner=%x", es.JoinerSecret)
	}
	if !bytes.Equal(es.WelcomeSecret, hx(t, "ddcd9ced2d264798f876cbd00a200cdc4d77311dfef96975257efb66b0ef2c4d")) {
		t.Errorf("welcome=%x", es.WelcomeSecret)
	}
	if !bytes.Equal(es.SenderDataSecret, hx(t, "9b3995e08589548b75e149190060cf35228df0eefe3527ea2fb39e49a84125b4")) {
		t.Errorf("sender_data=%x", es.SenderDataSecret)
	}
	if !bytes.Equal(es.EpochAuthenticator, hx(t, "7375d449cde2c5a856c13c8eb52c16bf9ef29eceef59b09d1f946bd1bac24643")) {
		t.Errorf("epoch_authenticator=%x", es.EpochAuthenticator)
	}
	if !bytes.Equal(es.InitSecret, hx(t, "505be2ce2ff922aa11e0a03d76346dda2981f1d9edf5cf98ecfc8757f69b00c9")) {
		t.Errorf("init=%x", es.InitSecret)
	}
	_, pub, err := ExternalPub(s, es.ExternalSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, hx(t, "640117516be304ac1160933c894a6df9290231f1843f3685c124fc42c785c02c")) {
		t.Errorf("external_pub=%x", pub)
	}
}

func TestEpochSecretsFromJoinerAgreesWithDeriveEpoch(t *testing.T) {
	// Both DeriveEpochSecrets and EpochSecretsFromJoiner must produce identical
	// results for a given (init, commit, psk, gc) tuple.
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	gc := GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.X25519_AES128GCM_SHA256_Ed25519,
		GroupID:                 hx(t, "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"),
		Epoch:                   0,
		TreeHash:                hx(t, "9769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818"),
		ConfirmedTranscriptHash: hx(t, "5e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f"),
	}
	gcBytes, _ := gc.MarshalMLS()
	initSecret := hx(t, "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e")
	commitSecret := hx(t, "a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509")
	pskSecret := hx(t, "e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b")

	full, err := DeriveEpochSecrets(s, initSecret, commitSecret, pskSecret, gcBytes)
	if err != nil {
		t.Fatal(err)
	}
	joiner, err := JoinerSecret(s, initSecret, commitSecret, gcBytes)
	if err != nil {
		t.Fatal(err)
	}
	fromJoiner, err := EpochSecretsFromJoiner(s, joiner, pskSecret, gcBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(full.WelcomeSecret, fromJoiner.WelcomeSecret) {
		t.Errorf("WelcomeSecret mismatch: full=%x joiner=%x", full.WelcomeSecret, fromJoiner.WelcomeSecret)
	}
	if !bytes.Equal(full.EpochAuthenticator, fromJoiner.EpochAuthenticator) {
		t.Errorf("EpochAuthenticator mismatch: full=%x joiner=%x", full.EpochAuthenticator, fromJoiner.EpochAuthenticator)
	}
	if !bytes.Equal(full.InitSecret, fromJoiner.InitSecret) {
		t.Errorf("InitSecret mismatch: full=%x joiner=%x", full.InitSecret, fromJoiner.InitSecret)
	}
}

func TestWelcomeKeyNonce(t *testing.T) {
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	welcomeSecret := make([]byte, s.HashLen())
	key, nonce, err := WelcomeKeyNonce(s, welcomeSecret)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != s.AEADKeySize() {
		t.Errorf("key length %d, want %d", len(key), s.AEADKeySize())
	}
	if len(nonce) != s.AEADNonceSize() {
		t.Errorf("nonce length %d, want %d", len(nonce), s.AEADNonceSize())
	}
}

func TestMLSExporter(t *testing.T) {
	// key-schedule.json case 0, epoch 0 exporter sub-case.
	// The label is the literal ASCII hex string from the KAT JSON (not decoded bytes).
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	out, err := MLSExporter(s,
		hx(t, "5a097e149f2a375d0b9e1d1f4dc3a9c6c1788df888e5441f41a8791f4dc56cea"), // exporter_secret
		"9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4",        // label (ASCII string)
		hx(t, "884f1af892ab002f5be4c5d5081ade9e0e6418c6ea7a9a92e90534f19dcef785"), // context
		32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, hx(t, "dbce4e25e59ab4dfa6f6200f113ed08393cf6e7286d024811141c6a4dd11c0cb")) {
		t.Fatalf("exporter=%x", out)
	}
}
