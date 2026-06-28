package keyschedule_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/internal/katutil"
	"github.com/trevex/mls-go/mls/keyschedule"
	"github.com/trevex/mls-go/mls/tree"
)

type ksExporter struct {
	Label   string           `json:"label"` // ASCII string used verbatim as MLS-Exporter label
	Context katutil.HexBytes `json:"context"`
	Length  int              `json:"length"`
	Secret  katutil.HexBytes `json:"secret"`
}

type ksEpoch struct {
	TreeHash                katutil.HexBytes `json:"tree_hash"`
	CommitSecret            katutil.HexBytes `json:"commit_secret"`
	PSKSecret               katutil.HexBytes `json:"psk_secret"`
	ConfirmedTranscriptHash katutil.HexBytes `json:"confirmed_transcript_hash"`
	GroupContext            katutil.HexBytes `json:"group_context"`
	JoinerSecret            katutil.HexBytes `json:"joiner_secret"`
	WelcomeSecret           katutil.HexBytes `json:"welcome_secret"`
	InitSecret              katutil.HexBytes `json:"init_secret"`
	SenderDataSecret        katutil.HexBytes `json:"sender_data_secret"`
	EncryptionSecret        katutil.HexBytes `json:"encryption_secret"`
	ExporterSecret          katutil.HexBytes `json:"exporter_secret"`
	EpochAuthenticator      katutil.HexBytes `json:"epoch_authenticator"`
	ExternalSecret          katutil.HexBytes `json:"external_secret"`
	ConfirmationKey         katutil.HexBytes `json:"confirmation_key"`
	MembershipKey           katutil.HexBytes `json:"membership_key"`
	ResumptionPSK           katutil.HexBytes `json:"resumption_psk"`
	ExternalPub             katutil.HexBytes `json:"external_pub"`
	Exporter                ksExporter       `json:"exporter"`
}

type ksCase struct {
	CipherSuite       uint16           `json:"cipher_suite"`
	GroupID           katutil.HexBytes `json:"group_id"`
	InitialInitSecret katutil.HexBytes `json:"initial_init_secret"`
	Epochs            []ksEpoch        `json:"epochs"`
}

func eq(t *testing.T, name string, got []byte, want katutil.HexBytes) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s=%x want %x", name, got, []byte(want))
	}
}

func TestKeyScheduleKAT(t *testing.T) {
	var cases []ksCase
	katutil.Load(t, "key-schedule.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no key-schedule vectors loaded")
	}
	executed := 0
	for idx, c := range cases {
		t.Run(fmt.Sprintf("case=%d/suite=%d", idx, c.CipherSuite), func(t *testing.T) {
			s, ok := cipher.Lookup(cipher.CipherSuite(c.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", c.CipherSuite)
			}
			executed++
			initSecret := []byte(c.InitialInitSecret)
			for e, ep := range c.Epochs {
				gc := keyschedule.GroupContext{
					Version:                 tree.ProtocolVersionMLS10,
					CipherSuite:             cipher.CipherSuite(c.CipherSuite),
					GroupID:                 c.GroupID,
					Epoch:                   uint64(e),
					TreeHash:                ep.TreeHash,
					ConfirmedTranscriptHash: ep.ConfirmedTranscriptHash,
				}
				gcBytes, err := gc.MarshalMLS()
				if err != nil {
					t.Fatal(err)
				}
				eq(t, fmt.Sprintf("ep%d.group_context", e), gcBytes, ep.GroupContext)

				es, err := keyschedule.DeriveEpochSecrets(s, initSecret, ep.CommitSecret, ep.PSKSecret, gcBytes)
				if err != nil {
					t.Fatal(err)
				}
				eq(t, "joiner_secret", es.JoinerSecret, ep.JoinerSecret)
				eq(t, "welcome_secret", es.WelcomeSecret, ep.WelcomeSecret)
				eq(t, "sender_data_secret", es.SenderDataSecret, ep.SenderDataSecret)
				eq(t, "encryption_secret", es.EncryptionSecret, ep.EncryptionSecret)
				eq(t, "exporter_secret", es.ExporterSecret, ep.ExporterSecret)
				eq(t, "external_secret", es.ExternalSecret, ep.ExternalSecret)
				eq(t, "confirmation_key", es.ConfirmationKey, ep.ConfirmationKey)
				eq(t, "membership_key", es.MembershipKey, ep.MembershipKey)
				eq(t, "resumption_psk", es.ResumptionPSK, ep.ResumptionPSK)
				eq(t, "epoch_authenticator", es.EpochAuthenticator, ep.EpochAuthenticator)
				eq(t, "init_secret", es.InitSecret, ep.InitSecret)

				_, pub, err := keyschedule.ExternalPub(s, es.ExternalSecret)
				if err != nil {
					t.Fatal(err)
				}
				eq(t, "external_pub", pub, ep.ExternalPub)

				out, err := keyschedule.MLSExporter(s, es.ExporterSecret,
					ep.Exporter.Label, ep.Exporter.Context, ep.Exporter.Length)
				if err != nil {
					t.Fatal(err)
				}
				eq(t, "exporter", out, ep.Exporter.Secret)

				initSecret = es.InitSecret // carry forward to the next epoch
			}
		})
	}
	if executed == 0 {
		t.Fatal("no vectors executed (all skipped) — check cipher suite registration")
	}
}
