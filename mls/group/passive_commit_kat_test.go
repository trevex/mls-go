package group_test

// passive-client-handling-commit.json and passive-client-random.json KATs:
// join via Welcome then process each epoch's commit, verifying the
// epoch_authenticator after each epoch. Both KATs use the same pcCase/pcEpoch
// schema and the same driver logic.

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
)

// runPassiveClientFile drives the passive-client KAT for the given JSON file.
// It joins via Welcome (verifying initial_epoch_authenticator) then processes
// every epoch's proposals + commit (verifying per-epoch epoch_authenticator).
// It requires at least one case to be executed across registered suites.
func runPassiveClientFile(t *testing.T, filename string) {
	t.Helper()

	var cases []pcCase
	katutil.Load(t, filename, &cases)

	executedCases := 0
	totalEpochs := 0

	for i, tc := range cases {
		tc := tc
		suite, ok := cipher.Lookup(cipher.CipherSuite(tc.CipherSuite))
		if !ok {
			t.Logf("case[%d]: skipping unregistered suite %d", i, tc.CipherSuite)
			continue
		}

		executedCases++
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
				RatchetTree:    tc.RatchetTree,
				ExternalPSKs:   externalPSKs,
			}

			g, err := group.JoinFromWelcome(suite, tc.Welcome, opt)
			if err != nil {
				t.Fatalf("JoinFromWelcome: %v", err)
			}

			if !bytes.Equal(g.EpochAuthenticator(), tc.InitialEpochAuthenticator) {
				t.Errorf("initial EpochAuthenticator mismatch:\n  got  %x\n  want %x",
					g.EpochAuthenticator(), tc.InitialEpochAuthenticator)
			}

			for j, ep := range tc.Epochs {
				props := make([][]byte, len(ep.Proposals))
				for k, p := range ep.Proposals {
					props[k] = p
				}
				if err := g.ProcessCommit(props, ep.Commit); err != nil {
					t.Fatalf("epoch[%d] ProcessCommit: %v", j, err)
				}
				if !bytes.Equal(g.EpochAuthenticator(), ep.EpochAuthenticator) {
					t.Errorf("epoch[%d] EpochAuthenticator mismatch:\n  got  %x\n  want %x",
						j, g.EpochAuthenticator(), ep.EpochAuthenticator)
				}
				totalEpochs++
			}
		})
	}

	if executedCases == 0 {
		t.Fatalf("%s: no cases executed (no registered suites found)", filename)
	}
	t.Logf("%s: %d/%d cases executed, %d epochs processed",
		filename, executedCases, len(cases), totalEpochs)
}

// TestPassiveCommit is the gate test for passive-client-handling-commit.json.
// It verifies every registered-suite case: join + process all epochs.
func TestPassiveCommit(t *testing.T) {
	runPassiveClientFile(t, "passive-client-handling-commit.json")
}

// TestPassiveRandom is the gate test for passive-client-random.json.
// It exercises long mixed-proposal sequences (Add/Remove/Update/PSK,
// by-value and by-reference proposals, path-less commits) — the definitive
// end-to-end stress test for the MLS receiver engine.
func TestPassiveRandom(t *testing.T) {
	runPassiveClientFile(t, "passive-client-random.json")
}
