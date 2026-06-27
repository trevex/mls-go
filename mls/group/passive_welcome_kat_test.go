package group_test

// passive-client-welcome.json KAT: join via Welcome and verify initial_epoch_authenticator.
// All 16 registered-suite (1 & 2) cases must reproduce initial_epoch_authenticator.
// Suites 3-7 are skipped as unregistered. Fails if zero cases are executed.

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
)

type pcEpoch struct {
	Proposals          []katutil.HexBytes `json:"proposals"`
	Commit             katutil.HexBytes   `json:"commit"`
	EpochAuthenticator katutil.HexBytes   `json:"epoch_authenticator"`
}

type pcExternalPSK struct {
	PSKID katutil.HexBytes `json:"psk_id"`
	PSK   katutil.HexBytes `json:"psk"`
}

type pcCase struct {
	CipherSuite               uint16           `json:"cipher_suite"`
	KeyPackage                katutil.HexBytes `json:"key_package"`
	SignaturePriv             katutil.HexBytes `json:"signature_priv"`
	EncryptionPriv            katutil.HexBytes `json:"encryption_priv"`
	InitPriv                  katutil.HexBytes `json:"init_priv"`
	Welcome                   katutil.HexBytes `json:"welcome"`
	RatchetTree               katutil.HexBytes `json:"ratchet_tree"`
	InitialEpochAuthenticator katutil.HexBytes `json:"initial_epoch_authenticator"`
	ExternalPSKs              []pcExternalPSK  `json:"external_psks"`
	Epochs                    []pcEpoch        `json:"epochs"`
}

func TestPassiveWelcome(t *testing.T) {
	var cases []pcCase
	katutil.Load(t, "passive-client-welcome.json", &cases)

	executed := 0
	for i, tc := range cases {
		suite, ok := cipher.Lookup(cipher.CipherSuite(tc.CipherSuite))
		if !ok {
			t.Logf("case[%d]: skipping unregistered suite %d", i, tc.CipherSuite)
			continue
		}

		tc := tc
		t.Run(fmt.Sprintf("suite%d_case%d", tc.CipherSuite, i), func(t *testing.T) {
			signer, _ := buildSigner(cipher.CipherSuite(tc.CipherSuite), tc.SignaturePriv)

			externalPSKs := make(map[string][]byte, len(tc.ExternalPSKs))
			for _, p := range tc.ExternalPSKs {
				externalPSKs[string(p.PSKID)] = p.PSK
			}

			opt := group.JoinOptions{
				KeyPackage:     tc.KeyPackage,
				InitPriv:       tc.InitPriv,
				EncryptionPriv: tc.EncryptionPriv,
				Signer:         signer,
				RatchetTree:    tc.RatchetTree, // nil if the JSON field is null
				ExternalPSKs:   externalPSKs,
			}

			g, err := group.JoinFromWelcome(suite, tc.Welcome, opt)
			if err != nil {
				t.Fatalf("JoinFromWelcome: %v", err)
			}

			if !bytes.Equal(g.EpochAuthenticator(), tc.InitialEpochAuthenticator) {
				t.Errorf("EpochAuthenticator mismatch:\n  got  %x\n  want %x",
					g.EpochAuthenticator(), tc.InitialEpochAuthenticator)
			}
		})

		executed++
	}

	if executed == 0 {
		t.Fatal("TestPassiveWelcome: no cases executed (no registered suites found)")
	}
	t.Logf("passive-client-welcome.json: %d/%d cases executed", executed, len(cases))
}
