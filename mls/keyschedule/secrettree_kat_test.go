package keyschedule_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
)

type stSenderData struct {
	SenderDataSecret katutil.HexBytes `json:"sender_data_secret"`
	Ciphertext       katutil.HexBytes `json:"ciphertext"`
	Key              katutil.HexBytes `json:"key"`
	Nonce            katutil.HexBytes `json:"nonce"`
}

type stRatchet struct {
	Generation       uint32           `json:"generation"`
	HandshakeKey     katutil.HexBytes `json:"handshake_key"`
	HandshakeNonce   katutil.HexBytes `json:"handshake_nonce"`
	ApplicationKey   katutil.HexBytes `json:"application_key"`
	ApplicationNonce katutil.HexBytes `json:"application_nonce"`
}

type stCase struct {
	CipherSuite      uint16           `json:"cipher_suite"`
	SenderData       stSenderData     `json:"sender_data"`
	EncryptionSecret katutil.HexBytes `json:"encryption_secret"`
	Leaves           [][]stRatchet    `json:"leaves"`
}

func TestSecretTreeKAT(t *testing.T) {
	var cases []stCase
	katutil.Load(t, "secret-tree.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no secret-tree vectors loaded")
	}
	executed := 0
	for idx, c := range cases {
		t.Run(fmt.Sprintf("case=%d/suite=%d", idx, c.CipherSuite), func(t *testing.T) {
			s, ok := cipher.Lookup(cipher.CipherSuite(c.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", c.CipherSuite)
			}
			executed++
			key, nonce, err := keyschedule.SenderDataKeyNonce(s, c.SenderData.SenderDataSecret, c.SenderData.Ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(key, c.SenderData.Key) || !bytes.Equal(nonce, c.SenderData.Nonce) {
				t.Fatalf("sender_data key/nonce mismatch: %x %x", key, nonce)
			}

			st, err := keyschedule.NewSecretTree(s, uint32(len(c.Leaves)), c.EncryptionSecret)
			if err != nil {
				t.Fatal(err)
			}
			for i, ratchets := range c.Leaves {
				for _, r := range ratchets {
					hk, hn, err := st.KeyNonce(uint32(i), keyschedule.HandshakeRatchet, r.Generation)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(hk, r.HandshakeKey) || !bytes.Equal(hn, r.HandshakeNonce) {
						t.Fatalf("leaf %d gen %d handshake mismatch", i, r.Generation)
					}
					ak, an, err := st.KeyNonce(uint32(i), keyschedule.ApplicationRatchet, r.Generation)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(ak, r.ApplicationKey) || !bytes.Equal(an, r.ApplicationNonce) {
						t.Fatalf("leaf %d gen %d application mismatch", i, r.Generation)
					}
				}
			}
		})
	}
	if executed == 0 {
		t.Fatal("no vectors executed (all skipped) — check cipher suite registration")
	}
}
