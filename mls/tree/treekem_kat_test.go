package tree_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

type tkPathSecret struct {
	Node       uint32           `json:"node"`
	PathSecret katutil.HexBytes `json:"path_secret"`
}
type tkLeafPrivate struct {
	Index          uint32           `json:"index"`
	EncryptionPriv katutil.HexBytes `json:"encryption_priv"`
	SignaturePriv  katutil.HexBytes `json:"signature_priv"`
	PathSecrets    []tkPathSecret   `json:"path_secrets"`
}
type tkUpdatePath struct {
	Sender        uint32              `json:"sender"`
	UpdatePath    katutil.HexBytes    `json:"update_path"`
	PathSecrets   []*katutil.HexBytes `json:"path_secrets"`
	CommitSecret  katutil.HexBytes    `json:"commit_secret"`
	TreeHashAfter katutil.HexBytes    `json:"tree_hash_after"`
}
type tkScenario struct {
	CipherSuite             uint16           `json:"cipher_suite"`
	GroupID                 katutil.HexBytes `json:"group_id"`
	Epoch                   uint64           `json:"epoch"`
	ConfirmedTranscriptHash katutil.HexBytes `json:"confirmed_transcript_hash"`
	RatchetTree             katutil.HexBytes `json:"ratchet_tree"`
	LeavesPrivate           []tkLeafPrivate  `json:"leaves_private"`
	UpdatePaths             []tkUpdatePath   `json:"update_paths"`
}

// buildSigner constructs a crypto.Signer from the vector's raw signature_priv.
// ok is false for cipher suites whose signature scheme is not handled here.
func buildSigner(cs cipher.CipherSuite, raw []byte) (crypto.Signer, bool) {
	switch cs {
	case cipher.X25519_AES128GCM_SHA256_Ed25519:
		return ed25519.NewKeyFromSeed(raw), true
	case cipher.P256_AES128GCM_SHA256_P256:
		sk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
		if err != nil {
			return nil, false
		}
		return sk, true
	default:
		return nil, false
	}
}

func provisionalGC(cs uint16, sc tkScenario, treeHash []byte) ([]byte, error) {
	gc := keyschedule.GroupContext{
		Version:                 tree.ProtocolVersionMLS10,
		CipherSuite:             cipher.CipherSuite(cs),
		GroupID:                 sc.GroupID,
		Epoch:                   sc.Epoch,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: sc.ConfirmedTranscriptHash,
		Extensions:              nil,
	}
	return gc.MarshalMLS()
}

// buildPrivates returns a TreeKEMPrivate per non-blank leaf index.
func buildPrivates(t *testing.T, suite cipher.Suite, sc tkScenario) map[uint32]*tree.TreeKEMPrivate {
	t.Helper()
	out := map[uint32]*tree.TreeKEMPrivate{}
	for _, lp := range sc.LeavesPrivate {
		priv := tree.NewTreeKEMPrivate(lp.Index, lp.EncryptionPriv)
		for _, ps := range lp.PathSecrets {
			if err := priv.AddPathSecret(suite, ps.Node, ps.PathSecret); err != nil {
				t.Fatalf("AddPathSecret: %v", err)
			}
		}
		out[lp.Index] = priv
	}
	return out
}

func TestTreeKEMKAT(t *testing.T) {
	var scenarios []tkScenario
	katutil.Load(t, "treekem.json", &scenarios)
	if len(scenarios) == 0 {
		t.Fatal("no treekem vectors loaded")
	}
	executed := 0
	for si, sc := range scenarios {
		sc := sc
		t.Run(fmt.Sprintf("scenario=%d/suite=%d", si, sc.CipherSuite), func(t *testing.T) {
			suite, ok := cipher.Lookup(cipher.CipherSuite(sc.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", sc.CipherSuite)
			}
			executed++
			privs := buildPrivates(t, suite, sc)

			for ui, up := range sc.UpdatePaths {
				var path tree.UpdatePath
				if err := path.UnmarshalMLS(up.UpdatePath); err != nil {
					t.Fatalf("up %d: unmarshal update_path: %v", ui, err)
				}
				// Re-encode must reproduce the bytes.
				if enc, err := path.MarshalMLS(); err != nil || !bytes.Equal(enc, up.UpdatePath) {
					t.Fatalf("up %d: update_path round-trip mismatch (err=%v)", ui, err)
				}

				// Merge into a fresh tree → tree_hash_after + parent-hash validity.
				merged, err := tree.ParseRatchetTree(suite, sc.RatchetTree)
				if err != nil {
					t.Fatalf("parse tree: %v", err)
				}
				if err := merged.Merge(up.Sender, &path); err != nil {
					t.Fatalf("up %d: merge: %v", ui, err)
				}
				mergedHash, err := merged.RootTreeHash()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(mergedHash, up.TreeHashAfter) {
					t.Fatalf("up %d: tree_hash_after:\n got %x\nwant %x", ui, mergedHash, up.TreeHashAfter)
				}
				if okPH, err := merged.VerifyParentHashes(); err != nil || !okPH {
					t.Fatalf("up %d: merged tree not parent-hash valid: %v, %v", ui, okPH, err)
				}

				gc, err := provisionalGC(sc.CipherSuite, sc, mergedHash)
				if err != nil {
					t.Fatal(err)
				}

				// PROCESS direction: every non-blank, non-sender leaf.
				for j := uint32(0); j < merged.Width(); j += 2 {
					leaf := j / 2
					if leaf == up.Sender {
						continue
					}
					if int(leaf) >= len(up.PathSecrets) || up.PathSecrets[leaf] == nil {
						continue // blank leaf / no expected secret
					}
					priv, ok := privs[leaf]
					if !ok {
						t.Fatalf("up %d: leaf %d has expected secret but no private state", ui, leaf)
					}
					rt, _ := tree.ParseRatchetTree(suite, sc.RatchetTree)
					ps, commit, err := rt.ProcessUpdatePath(up.Sender, &path, priv, gc)
					if err != nil {
						t.Fatalf("up %d leaf %d: process: %v", ui, leaf, err)
					}
					if !bytes.Equal(ps, *up.PathSecrets[leaf]) {
						t.Fatalf("up %d leaf %d: path_secret\n got %x\nwant %x", ui, leaf, ps, *up.PathSecrets[leaf])
					}
					if !bytes.Equal(commit, up.CommitSecret) {
						t.Fatalf("up %d leaf %d: commit_secret\n got %x\nwant %x", ui, leaf, commit, up.CommitSecret)
					}
				}

				// GENERATE direction: re-create an UpdatePath and re-process it.
				signer, ok := buildSigner(cipher.CipherSuite(sc.CipherSuite), sigPrivFor(sc, up.Sender))
				if !ok {
					continue // signature scheme not handled; process direction already gated
				}
				genTree, _ := tree.ParseRatchetTree(suite, sc.RatchetTree)
				leafSecret := make([]byte, suite.HashLen())
				if _, err := rand.Read(leafSecret); err != nil {
					t.Fatal(err)
				}
				mkGC := func(treeHash []byte) ([]byte, error) { return provisionalGC(sc.CipherSuite, sc, treeHash) }
				newUP, newCommit, err := genTree.GenerateUpdatePath(up.Sender, leafSecret, signer, sc.GroupID, mkGC)
				if err != nil {
					t.Fatalf("up %d: generate: %v", ui, err)
				}
				if okPH, err := genTree.VerifyParentHashes(); err != nil || !okPH {
					t.Fatalf("up %d: generated tree not parent-hash valid: %v, %v", ui, okPH, err)
				}
				genHash, _ := genTree.RootTreeHash()
				genGC, _ := provisionalGC(sc.CipherSuite, sc, genHash)
				for leaf, priv := range privs {
					if leaf == up.Sender {
						continue
					}
					rt, _ := tree.ParseRatchetTree(suite, sc.RatchetTree)
					_, commit, err := rt.ProcessUpdatePath(up.Sender, newUP, priv, genGC)
					if err != nil {
						t.Fatalf("up %d leaf %d: re-process generated: %v", ui, leaf, err)
					}
					if !bytes.Equal(commit, newCommit) {
						t.Fatalf("up %d leaf %d: regenerated commit mismatch\n got %x\nwant %x", ui, leaf, commit, newCommit)
					}
				}
			}
		})
	}
	if executed == 0 {
		t.Fatal("no treekem scenarios executed (all suites skipped)")
	}
}

func sigPrivFor(sc tkScenario, leaf uint32) []byte {
	for _, lp := range sc.LeavesPrivate {
		if lp.Index == leaf {
			return lp.SignaturePriv
		}
	}
	return nil
}
