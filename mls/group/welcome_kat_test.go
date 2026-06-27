package group_test

// welcome.json decrypt + GroupInfo signature KAT (RFC 9420 §12.4.3.1).
//
// For each case (skip unregistered suites):
//  1. Parse the Welcome MLSMessage envelope.
//  2. Compute our KeyPackageRef from the key_package blob (body only, no envelope).
//  3. Select the matching EncryptedGroupSecrets entry.
//  4. DecryptWithLabel(init_priv, "Welcome", encrypted_group_info, ...) → bare GroupSecrets.
//  5. Derive welcome_key/welcome_nonce from joiner_secret + zero psk_secret.
//  6. Open(welcome_key, welcome_nonce, aad="", encrypted_group_info) → bare GroupInfo.
//  7. VerifySignature(signer_pub, "GroupInfoTBS") must return true.

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
)

type welcomeCase struct {
	CipherSuite uint16           `json:"cipher_suite"`
	KeyPackage  katutil.HexBytes `json:"key_package"`
	InitPriv    katutil.HexBytes `json:"init_priv"`
	SignerPub   katutil.HexBytes `json:"signer_pub"`
	Welcome     katutil.HexBytes `json:"welcome"`
}

func TestWelcomeKAT(t *testing.T) {
	var cases []welcomeCase
	katutil.Load(t, "welcome.json", &cases)

	executed := 0

	for i, tc := range cases {
		suite, ok := cipher.Lookup(cipher.CipherSuite(tc.CipherSuite))
		if !ok {
			t.Logf("case[%d]: skipping unregistered suite %d", i, tc.CipherSuite)
			continue
		}

		t.Run("suite"+string(rune('0'+tc.CipherSuite)), func(t *testing.T) {
			// Step 1: Decode the Welcome MLSMessage envelope.
			w, err := group.DecodeWelcomeMessage(tc.Welcome)
			if err != nil {
				t.Fatalf("DecodeWelcomeMessage: %v", err)
			}

			// Step 2: Compute our KeyPackageRef from the bare KeyPackage
			// (tc.KeyPackage is an MLSMessage envelope; strip the 4-byte header).
			kp, err := group.DecodeKeyPackageMessage(tc.KeyPackage)
			if err != nil {
				t.Fatalf("DecodeKeyPackageMessage: %v", err)
			}
			ref, err := kp.Ref(suite)
			if err != nil {
				t.Fatalf("kp.Ref: %v", err)
			}

			// Step 3: Select the EncryptedGroupSecrets entry for our KeyPackageRef.
			var egs *group.EncryptedGroupSecrets
			for idx := range w.Secrets {
				if bytes.Equal(w.Secrets[idx].NewMember, ref) {
					egs = &w.Secrets[idx]
					break
				}
			}
			if egs == nil {
				t.Fatalf("no EncryptedGroupSecrets found for our KeyPackageRef %x", ref)
			}

			// Step 4: Decrypt GroupSecrets with HPKE.
			// DecryptWithLabel(init_priv, "Welcome", context=encrypted_group_info,
			//                  kem_output, ciphertext) → bare GroupSecrets bytes.
			gsBytes, err := suite.DecryptWithLabel(
				tc.InitPriv,
				"Welcome",
				w.EncryptedGroupInfo,
				egs.EncryptedGroupSecrets.KemOutput,
				egs.EncryptedGroupSecrets.Ciphertext,
			)
			if err != nil {
				t.Fatalf("DecryptWithLabel (GroupSecrets): %v", err)
			}
			var gs group.GroupSecrets
			if err := gs.UnmarshalMLS(gsBytes); err != nil {
				t.Fatalf("GroupSecrets.UnmarshalMLS: %v", err)
			}

			// Step 5: Derive welcome_key and welcome_nonce.
			// psk_secret = zeros(HashLen) because there are no PSKs in this KAT.
			pskSecret := make([]byte, suite.HashLen())
			member, err := suite.Extract(gs.JoinerSecret, pskSecret)
			if err != nil {
				t.Fatalf("Extract(joiner, psk): %v", err)
			}
			welcomeSecret, err := suite.DeriveSecret(member, "welcome")
			if err != nil {
				t.Fatalf("DeriveSecret(member, welcome): %v", err)
			}
			wk, wn, err := keyschedule.WelcomeKeyNonce(suite, welcomeSecret)
			if err != nil {
				t.Fatalf("WelcomeKeyNonce: %v", err)
			}

			// Step 6: AEAD-decrypt the GroupInfo. AAD is empty.
			giBytes, err := suite.Open(wk, wn, nil, w.EncryptedGroupInfo)
			if err != nil {
				t.Fatalf("Open(encrypted_group_info): %v", err)
			}

			// The decrypted payload is a bare GroupInfo (NOT an MLSMessage envelope).
			var gi group.GroupInfo
			if err := gi.UnmarshalMLS(giBytes); err != nil {
				t.Fatalf("GroupInfo.UnmarshalMLS: %v", err)
			}

			// Step 7: Verify the GroupInfoTBS signature.
			ok2, err := gi.VerifySignature(suite, tc.SignerPub)
			if err != nil {
				t.Fatalf("VerifySignature: %v", err)
			}
			if !ok2 {
				t.Fatal("GroupInfo signature verification failed")
			}
		})

		executed++
	}

	if executed == 0 {
		t.Fatal("no welcome.json cases executed (no registered suites)")
	}
	t.Logf("welcome.json: %d/%d cases executed and verified", executed, len(cases))
}
