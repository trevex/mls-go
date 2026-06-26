package keyschedule_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
)

type pskKATEntry struct {
	PSKID    katutil.HexBytes `json:"psk_id"`
	PSK      katutil.HexBytes `json:"psk"`
	PSKNonce katutil.HexBytes `json:"psk_nonce"`
}

type pskKATCase struct {
	CipherSuite uint16           `json:"cipher_suite"`
	PSKs        []pskKATEntry    `json:"psks"`
	PSKSecret   katutil.HexBytes `json:"psk_secret"`
}

func TestPSKSecretKAT(t *testing.T) {
	var cases []pskKATCase
	katutil.Load(t, "psk_secret.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no psk_secret vectors loaded")
	}
	executed := 0
	for idx, c := range cases {
		t.Run(fmt.Sprintf("case=%d/suite=%d", idx, c.CipherSuite), func(t *testing.T) {
			s, ok := cipher.Lookup(cipher.CipherSuite(c.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", c.CipherSuite)
			}
			executed++
			psks := make([]keyschedule.PSK, len(c.PSKs))
			for i, p := range c.PSKs {
				psks[i] = keyschedule.PSK{
					ID: keyschedule.PreSharedKeyID{
						PSKType:  keyschedule.PSKTypeExternal,
						PSKID:    p.PSKID,
						PSKNonce: p.PSKNonce,
					},
					PSK: p.PSK,
				}
			}
			got, err := keyschedule.PSKSecret(s, psks)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, c.PSKSecret) {
				t.Fatalf("psk_secret=%x want %x", got, []byte(c.PSKSecret))
			}
		})
	}
	if executed == 0 {
		t.Fatal("no vectors executed (all skipped) — check cipher suite registration")
	}
}
