package keyschedule_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
)

type thCase struct {
	CipherSuite                  uint16           `json:"cipher_suite"`
	ConfirmationKey              katutil.HexBytes `json:"confirmation_key"`
	AuthenticatedContent         katutil.HexBytes `json:"authenticated_content"`
	InterimTranscriptHashBefore  katutil.HexBytes `json:"interim_transcript_hash_before"`
	ConfirmedTranscriptHashAfter katutil.HexBytes `json:"confirmed_transcript_hash_after"`
	InterimTranscriptHashAfter   katutil.HexBytes `json:"interim_transcript_hash_after"`
}

func TestTranscriptHashesKAT(t *testing.T) {
	var cases []thCase
	katutil.Load(t, "transcript-hashes.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no transcript-hashes vectors loaded")
	}
	executed := 0
	for idx, c := range cases {
		t.Run(fmt.Sprintf("case=%d/suite=%d", idx, c.CipherSuite), func(t *testing.T) {
			s, ok := cipher.Lookup(cipher.CipherSuite(c.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", c.CipherSuite)
			}
			executed++
			confirmedInput, confTag, err := keyschedule.SplitAuthenticatedContent(s, c.AuthenticatedContent)
			if err != nil {
				t.Fatal(err)
			}
			confirmed := keyschedule.ConfirmedTranscriptHash(s, c.InterimTranscriptHashBefore, confirmedInput)
			if !bytes.Equal(confirmed, c.ConfirmedTranscriptHashAfter) {
				t.Fatalf("confirmed_transcript_hash_after=%x want %x", confirmed, []byte(c.ConfirmedTranscriptHashAfter))
			}
			// The peeled tag must equal MAC(confirmation_key, confirmed_after).
			if want := keyschedule.ConfirmationTag(s, c.ConfirmationKey, confirmed); !bytes.Equal(confTag, want) {
				t.Fatalf("confirmation_tag mismatch: peeled %x vs computed %x", confTag, want)
			}
			interim, err := keyschedule.InterimTranscriptHash(s, confirmed, confTag)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(interim, c.InterimTranscriptHashAfter) {
				t.Fatalf("interim_transcript_hash_after=%x want %x", interim, []byte(c.InterimTranscriptHashAfter))
			}
		})
	}
	if executed == 0 {
		t.Fatal("no vectors executed (all skipped) — check cipher suite registration")
	}
}
