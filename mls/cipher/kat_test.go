package cipher_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
)

type refHashVec struct {
	Label string           `json:"label"`
	Value katutil.HexBytes `json:"value"`
	Out   katutil.HexBytes `json:"out"`
}
type expandVec struct {
	Secret  katutil.HexBytes `json:"secret"`
	Label   string           `json:"label"`
	Context katutil.HexBytes `json:"context"`
	Length  int              `json:"length"`
	Out     katutil.HexBytes `json:"out"`
}
type deriveSecretVec struct {
	Secret katutil.HexBytes `json:"secret"`
	Label  string           `json:"label"`
	Out    katutil.HexBytes `json:"out"`
}
type deriveTreeVec struct {
	Secret     katutil.HexBytes `json:"secret"`
	Label      string           `json:"label"`
	Generation uint32           `json:"generation"`
	Length     int              `json:"length"`
	Out        katutil.HexBytes `json:"out"`
}
type signVec struct {
	Priv      katutil.HexBytes `json:"priv"`
	Pub       katutil.HexBytes `json:"pub"`
	Content   katutil.HexBytes `json:"content"`
	Label     string           `json:"label"`
	Signature katutil.HexBytes `json:"signature"`
}
type cryptoBasicsCase struct {
	CipherSuite      cipher.CipherSuite `json:"cipher_suite"`
	RefHash          refHashVec         `json:"ref_hash"`
	ExpandWithLabel  expandVec          `json:"expand_with_label"`
	DeriveSecret     deriveSecretVec    `json:"derive_secret"`
	DeriveTreeSecret deriveTreeVec      `json:"derive_tree_secret"`
	SignWithLabel    signVec            `json:"sign_with_label"`
	// encrypt_with_label is deferred to a later plan (needs HPKE).
}

func TestCryptoBasicsKAT(t *testing.T) {
	var cases []cryptoBasicsCase
	katutil.Load(t, "crypto-basics.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no crypto-basics vectors loaded")
	}
	var executed int
	for i, c := range cases {
		cs, ok := cipher.Lookup(c.CipherSuite)
		if !ok {
			continue // suites added in later plans are skipped here
		}
		executed++
		i, c, cs := i, c, cs
		t.Run(fmt.Sprintf("suite-0x%04x", uint16(c.CipherSuite)), func(t *testing.T) {
			if got, err := cs.RefHash(c.RefHash.Label, c.RefHash.Value); err != nil || !bytes.Equal(got, c.RefHash.Out) {
				t.Fatalf("case %d RefHash: got %x err %v, want %x", i, got, err, c.RefHash.Out)
			}

			ewl := c.ExpandWithLabel
			if got, err := cs.ExpandWithLabel(ewl.Secret, ewl.Label, ewl.Context, ewl.Length); err != nil || !bytes.Equal(got, ewl.Out) {
				t.Fatalf("case %d ExpandWithLabel: got %x err %v, want %x", i, got, err, ewl.Out)
			}

			ds := c.DeriveSecret
			if got, err := cs.DeriveSecret(ds.Secret, ds.Label); err != nil || !bytes.Equal(got, ds.Out) {
				t.Fatalf("case %d DeriveSecret: got %x err %v, want %x", i, got, err, ds.Out)
			}

			dt := c.DeriveTreeSecret
			if got, err := cs.DeriveTreeSecret(dt.Secret, dt.Label, dt.Generation, dt.Length); err != nil || !bytes.Equal(got, dt.Out) {
				t.Fatalf("case %d DeriveTreeSecret: got %x err %v, want %x", i, got, err, dt.Out)
			}

			// Signatures are randomized, so verify rather than re-sign.
			sw := c.SignWithLabel
			if !cs.VerifyWithLabel(sw.Pub, sw.Label, sw.Content, sw.Signature) {
				t.Fatalf("case %d SignWithLabel: VerifyWithLabel rejected the vector signature", i)
			}
		})
	}
	if executed == 0 {
		t.Fatal("no registered suites exercised assertions; check cipher registry")
	}
}
