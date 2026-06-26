package keyschedule

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

func TestSenderDataKeyNonce(t *testing.T) {
	// secret-tree.json case 0 sender_data.
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	key, nonce, err := SenderDataKeyNonce(s,
		hx(t, "95684b805e1bbd9c71d1abaf8a1930c12112b9a06c12db937970be5bbb916573"),
		hx(t, "156f2eb3fa482cff20e3a090c267ce6481d4a0976aee2adb921d70ae8a04a6494339462ac049f185e7184d8245270e54e68b72bd5df66800367c50e423cafec0260ac4dc743c24cabfc6060fc5"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, hx(t, "92667d9c889a6b768c157538c0a79fed")) {
		t.Errorf("key=%x", key)
	}
	if !bytes.Equal(nonce, hx(t, "362785b1cc8bc775fcc216e7")) {
		t.Errorf("nonce=%x", nonce)
	}
}

func TestSecretTreeSingleLeafGeneration(t *testing.T) {
	// secret-tree.json case 0: 1 leaf, generations 0 and 15.
	s, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	st, err := NewSecretTree(s, 1, hx(t, "d69fcc35969e94680461974bd26c7cda7594cbf45985c4bf668c3b3118b765ab"))
	if err != nil {
		t.Fatal(err)
	}
	hk0, hn0, err := st.KeyNonce(0, HandshakeRatchet, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hk0, hx(t, "a2d6b8a9255478e9b79a076872ae3563")) || !bytes.Equal(hn0, hx(t, "8e8fc08a4eb5189b7b558527")) {
		t.Errorf("gen0 handshake key/nonce mismatch: %x %x", hk0, hn0)
	}
	ak0, _, err := st.KeyNonce(0, ApplicationRatchet, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ak0, hx(t, "442e691710646617a21e41482d868a4e")) {
		t.Errorf("gen0 application key mismatch: %x", ak0)
	}
}
