package group_test

// messages.json wire round-trip KAT (RFC 9420 §10/§12).
//
// Each *_proposal field is a bare proposal BODY (not wrapped in a Proposal
// type tag): add_proposal = bare KeyPackage, update_proposal = bare LeafNode,
// remove_proposal = bare uint32, pre_shared_key_proposal = bare PreSharedKeyID,
// re_init_proposal = bare { group_id<V>; version; cs; extensions<V> },
// external_init_proposal = bare opaque<V> (KEM output),
// group_context_extensions_proposal = bare extensions<V>.

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/framing"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

type messagesCase struct {
	MLSWelcome                     katutil.HexBytes `json:"mls_welcome"`
	MLSGroupInfo                   katutil.HexBytes `json:"mls_group_info"`
	MLSKeyPackage                  katutil.HexBytes `json:"mls_key_package"`
	RatchetTree                    katutil.HexBytes `json:"ratchet_tree"`
	GroupSecrets                   katutil.HexBytes `json:"group_secrets"`
	AddProposal                    katutil.HexBytes `json:"add_proposal"`
	UpdateProposal                 katutil.HexBytes `json:"update_proposal"`
	RemoveProposal                 katutil.HexBytes `json:"remove_proposal"`
	PreSharedKeyProposal           katutil.HexBytes `json:"pre_shared_key_proposal"`
	ReInitProposal                 katutil.HexBytes `json:"re_init_proposal"`
	ExternalInitProposal           katutil.HexBytes `json:"external_init_proposal"`
	GroupContextExtensionsProposal katutil.HexBytes `json:"group_context_extensions_proposal"`
	Commit                         katutil.HexBytes `json:"commit"`
	PublicMessageApplication       katutil.HexBytes `json:"public_message_application"`
	PublicMessageCommit            katutil.HexBytes `json:"public_message_commit"`
	PublicMessageProposal          katutil.HexBytes `json:"public_message_proposal"`
	PrivateMessage                 katutil.HexBytes `json:"private_message"`
}

func TestMessagesKAT(t *testing.T) {
	var cases []messagesCase
	katutil.Load(t, "messages.json", &cases)

	// suite1 is used for ratchet_tree parsing (bytes are suite-independent but
	// ParseRatchetTree requires a suite instance).
	suite1, ok := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	if !ok {
		t.Fatal("suite 1 not found")
	}

	total := 0

	roundtrip := func(t *testing.T, label string, blob []byte, enc func([]byte) ([]byte, error)) {
		t.Helper()
		if len(blob) == 0 {
			return
		}
		got, err := enc(blob)
		if err != nil {
			t.Errorf("%s: %v", label, err)
			return
		}
		if !bytes.Equal(blob, got) {
			t.Errorf("%s: round-trip mismatch\n  want: %x\n  got:  %x", label, blob, got)
			return
		}
		total++
	}

	// roundtripReInit decodes a bare ReInit body:
	// { group_id<V>; version(uint16); cipher_suite(uint16); extensions<V> }
	roundtripReInit := func(blob []byte) ([]byte, error) {
		c := syntax.NewCursor(blob)
		groupID, err := c.ReadOpaqueV()
		if err != nil {
			return nil, fmt.Errorf("re_init group_id: %w", err)
		}
		version, err := c.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("re_init version: %w", err)
		}
		cs, err := c.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("re_init cipher_suite: %w", err)
		}
		exts, err := syntax.ReadVectorV(c, tree.DecodeExtension)
		if err != nil {
			return nil, fmt.Errorf("re_init extensions: %w", err)
		}
		if !c.Empty() {
			return nil, fmt.Errorf("re_init: %d trailing bytes", c.Remaining())
		}
		b := syntax.NewBuilder()
		if err := b.WriteOpaqueV(groupID); err != nil {
			return nil, err
		}
		b.WriteUint16(version)
		b.WriteUint16(cs)
		if err := syntax.WriteVectorV(b, exts, func(b *syntax.Builder, e tree.Extension) error {
			return e.MarshalTo(b)
		}); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}

	// roundtripPSK decodes a bare PreSharedKeyID body.
	roundtripPSK := func(blob []byte) ([]byte, error) {
		c := syntax.NewCursor(blob)
		psk, err := keyschedule.DecodePreSharedKeyID(c)
		if err != nil {
			return nil, fmt.Errorf("psk: %w", err)
		}
		if !c.Empty() {
			return nil, fmt.Errorf("psk: %d trailing bytes", c.Remaining())
		}
		b := syntax.NewBuilder()
		if err := psk.MarshalTo(b); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}

	for i, tc := range cases {
		label := func(field string) string { return fmt.Sprintf("case[%d].%s", i, field) }

		// ── MLSMessage envelopes ────────────────────────────────────────────
		roundtrip(t, label("mls_welcome"), tc.MLSWelcome, func(blob []byte) ([]byte, error) {
			w, err := group.DecodeWelcomeMessage(blob)
			if err != nil {
				return nil, err
			}
			return group.EncodeWelcomeMessage(w)
		})
		roundtrip(t, label("mls_group_info"), tc.MLSGroupInfo, func(blob []byte) ([]byte, error) {
			gi, err := group.DecodeGroupInfoMessage(blob)
			if err != nil {
				return nil, err
			}
			return group.EncodeGroupInfoMessage(gi)
		})
		roundtrip(t, label("mls_key_package"), tc.MLSKeyPackage, func(blob []byte) ([]byte, error) {
			kp, err := group.DecodeKeyPackageMessage(blob)
			if err != nil {
				return nil, err
			}
			return group.EncodeKeyPackageMessage(kp)
		})

		// ── Bare objects ────────────────────────────────────────────────────
		roundtrip(t, label("ratchet_tree"), tc.RatchetTree, func(blob []byte) ([]byte, error) {
			rt, err := tree.ParseRatchetTree(suite1, blob)
			if err != nil {
				return nil, err
			}
			return rt.MarshalMLS()
		})
		roundtrip(t, label("group_secrets"), tc.GroupSecrets, func(blob []byte) ([]byte, error) {
			var gs group.GroupSecrets
			if err := gs.UnmarshalMLS(blob); err != nil {
				return nil, err
			}
			return gs.MarshalMLS()
		})
		roundtrip(t, label("commit"), tc.Commit, func(blob []byte) ([]byte, error) {
			var cm group.Commit
			if err := cm.UnmarshalMLS(blob); err != nil {
				return nil, err
			}
			return cm.MarshalMLS()
		})

		// ── Bare proposal bodies (no proposal type prefix) ──────────────────
		//
		// add_proposal    = bare KeyPackage
		// update_proposal = bare LeafNode
		// remove_proposal = bare uint32 (leaf index)
		// pre_shared_key_proposal = bare PreSharedKeyID
		// re_init_proposal = bare { group_id<V>; version; cs; extensions<V> }
		// external_init_proposal = bare opaque<V> (KEM output)
		// group_context_extensions_proposal = bare extensions<V>

		roundtrip(t, label("add_proposal"), tc.AddProposal, func(blob []byte) ([]byte, error) {
			var kp group.KeyPackage
			if err := kp.UnmarshalMLS(blob); err != nil {
				return nil, err
			}
			return kp.MarshalMLS()
		})
		roundtrip(t, label("update_proposal"), tc.UpdateProposal, func(blob []byte) ([]byte, error) {
			var ln tree.LeafNode
			if err := ln.UnmarshalMLS(blob); err != nil {
				return nil, err
			}
			return ln.MarshalMLS()
		})
		roundtrip(t, label("remove_proposal"), tc.RemoveProposal, func(blob []byte) ([]byte, error) {
			c := syntax.NewCursor(blob)
			removed, err := c.ReadUint32()
			if err != nil {
				return nil, fmt.Errorf("remove: %w", err)
			}
			if !c.Empty() {
				return nil, fmt.Errorf("remove: %d trailing bytes", c.Remaining())
			}
			b := syntax.NewBuilder()
			b.WriteUint32(removed)
			return b.Bytes(), nil
		})
		roundtrip(t, label("pre_shared_key_proposal"), tc.PreSharedKeyProposal, roundtripPSK)
		roundtrip(t, label("re_init_proposal"), tc.ReInitProposal, roundtripReInit)
		roundtrip(t, label("external_init_proposal"), tc.ExternalInitProposal, func(blob []byte) ([]byte, error) {
			c := syntax.NewCursor(blob)
			kemOutput, err := c.ReadOpaqueV()
			if err != nil {
				return nil, fmt.Errorf("external_init: %w", err)
			}
			if !c.Empty() {
				return nil, fmt.Errorf("external_init: %d trailing bytes", c.Remaining())
			}
			b := syntax.NewBuilder()
			if err := b.WriteOpaqueV(kemOutput); err != nil {
				return nil, err
			}
			return b.Bytes(), nil
		})
		roundtrip(t, label("group_context_extensions_proposal"), tc.GroupContextExtensionsProposal, func(blob []byte) ([]byte, error) {
			c := syntax.NewCursor(blob)
			exts, err := syntax.ReadVectorV(c, tree.DecodeExtension)
			if err != nil {
				return nil, fmt.Errorf("gce extensions: %w", err)
			}
			if !c.Empty() {
				return nil, fmt.Errorf("gce: %d trailing bytes", c.Remaining())
			}
			b := syntax.NewBuilder()
			if err := syntax.WriteVectorV(b, exts, func(b *syntax.Builder, e tree.Extension) error {
				return e.MarshalTo(b)
			}); err != nil {
				return nil, err
			}
			return b.Bytes(), nil
		})

		// ── Framing messages ────────────────────────────────────────────────
		framingRoundtrip := func(field string, blob []byte) {
			roundtrip(t, label(field), blob, func(blob []byte) ([]byte, error) {
				var m framing.MLSMessage
				if err := m.UnmarshalMLS(blob); err != nil {
					return nil, err
				}
				return m.MarshalMLS()
			})
		}
		framingRoundtrip("public_message_application", tc.PublicMessageApplication)
		framingRoundtrip("public_message_commit", tc.PublicMessageCommit)
		framingRoundtrip("public_message_proposal", tc.PublicMessageProposal)
		framingRoundtrip("private_message", tc.PrivateMessage)
	}

	if total == 0 {
		t.Fatal("no messages.json assertions executed")
	}
	t.Logf("messages.json: %d assertions executed across %d cases", total, len(cases))
}
