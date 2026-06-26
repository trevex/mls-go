package tree

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/syntax"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// --- minimal loader for scenario-0 fixtures shared by the internal unit tests ---
type tkPS struct {
	Node       uint32 `json:"node"`
	PathSecret string `json:"path_secret"`
}
type tkLeafPriv struct {
	Index          uint32 `json:"index"`
	EncryptionPriv string `json:"encryption_priv"`
	SignaturePriv  string `json:"signature_priv"`
	PathSecrets    []tkPS `json:"path_secrets"`
}
type tkUP struct {
	Sender        uint32    `json:"sender"`
	UpdatePath    string    `json:"update_path"`
	PathSecrets   []*string `json:"path_secrets"`
	CommitSecret  string    `json:"commit_secret"`
	TreeHashAfter string    `json:"tree_hash_after"`
}
type tkCase struct {
	CipherSuite             uint16       `json:"cipher_suite"`
	GroupID                 string       `json:"group_id"`
	Epoch                   uint64       `json:"epoch"`
	ConfirmedTranscriptHash string       `json:"confirmed_transcript_hash"`
	RatchetTree             string       `json:"ratchet_tree"`
	LeavesPrivate           []tkLeafPriv `json:"leaves_private"`
	UpdatePaths             []tkUP       `json:"update_paths"`
}

func loadTreeKEM(t *testing.T) []tkCase {
	t.Helper()
	raw, err := os.ReadFile("../testdata/treekem.json")
	if err != nil {
		t.Fatalf("read treekem.json: %v", err)
	}
	var cases []tkCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return cases
}

func TestCommitSecretDerivation(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	// scenario 0: path_secret at root (decrypted by leaf 1) -> commit_secret.
	pathSecret := hx(t, "e8608097b9da1863d6a6b540542af95b96ab95bcd9a9c04763313b61c2c99d44")
	got, err := CommitSecret(suite, pathSecret)
	if err != nil {
		t.Fatal(err)
	}
	want := hx(t, "5ccc25c82569cc9731283abbdb9265187c17503e6f9c4ba2484a9e210e83f5a3")
	if !bytes.Equal(got, want) {
		t.Fatalf("commit_secret = %x, want %x", got, want)
	}
}

func TestFilteredDirectPathScenario0(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	c := loadTreeKEM(t)[0]
	rt, err := ParseRatchetTree(suite, hx(t, c.RatchetTree))
	if err != nil {
		t.Fatal(err)
	}
	if got := rt.filteredDirectPath(0); len(got) != 1 || got[0] != 1 {
		t.Fatalf("filteredDirectPath(0) = %v, want [1]", got)
	}
}

func TestTreeKEMPrivateDerivesNodeKey(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	c := loadTreeKEM(t)[0]
	lp := c.LeavesPrivate[0] // leaf with a path secret at node 1
	priv := NewTreeKEMPrivate(lp.Index, hx(t, lp.EncryptionPriv))
	for _, ps := range lp.PathSecrets {
		if err := priv.AddPathSecret(suite, ps.Node, hx(t, ps.PathSecret)); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := priv.privateKey(2 * lp.Index); !ok {
		t.Fatalf("missing leaf private key at node %d", 2*lp.Index)
	}
	if _, ok := priv.privateKey(1); !ok {
		t.Fatalf("missing derived private key at node 1")
	}
}

// newProvisionalGC serializes a GroupContext{version=mls10, ...} with empty
// extensions, matching keyschedule.GroupContext's wire form (RFC 9420 §8.1).
func newProvisionalGC(cs uint16, gid []byte, epoch uint64, treeHash, cth []byte) []byte {
	b := syntax.NewBuilder()
	b.WriteUint16(uint16(ProtocolVersionMLS10))
	b.WriteUint16(cs)
	_ = b.WriteOpaqueV(gid)
	b.WriteUint64(epoch)
	_ = b.WriteOpaqueV(treeHash)
	_ = b.WriteOpaqueV(cth)
	_ = syntax.WriteVectorV(b, []Extension{}, func(b *syntax.Builder, e Extension) error { return e.marshal(b) })
	return b.Bytes()
}

// provisionalGroupContext builds the serialized provisional GroupContext used as
// HPKE context for an UpdatePath (RFC 9420 §7.6): version=mls10, the scenario's
// cipher_suite/group_id/epoch/confirmed_transcript_hash, tree_hash = the merged
// tree's root hash, empty extensions. Built by hand here to avoid importing
// keyschedule into the internal (package tree) test.
func provisionalGroupContext(t *testing.T, suite cipher.Suite, c tkCase, mergedTreeHash []byte) []byte {
	t.Helper()
	b := newProvisionalGC(c.CipherSuite, hx(t, c.GroupID), c.Epoch, mergedTreeHash, hx(t, c.ConfirmedTranscriptHash))
	return b
}

func TestProcessUpdatePathScenario0(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	c := loadTreeKEM(t)[0]
	up := c.UpdatePaths[0] // sender 0
	var path UpdatePath
	if err := path.UnmarshalMLS(hx(t, up.UpdatePath)); err != nil {
		t.Fatal(err)
	}
	// provisional group context: merge a fresh copy to get the tree hash.
	merged, _ := ParseRatchetTree(suite, hx(t, c.RatchetTree))
	if err := merged.Merge(up.Sender, &path); err != nil {
		t.Fatal(err)
	}
	mergedHash, _ := merged.RootTreeHash()
	gc := provisionalGroupContext(t, suite, c, mergedHash)

	// receiver = leaf 1.
	lp := c.LeavesPrivate[1]
	if lp.Index != 1 {
		t.Fatalf("expected leaves_private[1].index == 1, got %d", lp.Index)
	}
	priv := NewTreeKEMPrivate(lp.Index, hx(t, lp.EncryptionPriv))
	for _, ps := range lp.PathSecrets {
		if err := priv.AddPathSecret(suite, ps.Node, hx(t, ps.PathSecret)); err != nil {
			t.Fatal(err)
		}
	}
	rt, _ := ParseRatchetTree(suite, hx(t, c.RatchetTree))
	pathSecret, commit, err := rt.ProcessUpdatePath(up.Sender, &path, priv, gc)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if want := up.PathSecrets[1]; want == nil || !bytes.Equal(pathSecret, hx(t, *want)) {
		t.Fatalf("path_secret = %x, want %v", pathSecret, want)
	}
	if !bytes.Equal(commit, hx(t, up.CommitSecret)) {
		t.Fatalf("commit_secret = %x, want %s", commit, up.CommitSecret)
	}
}

func TestMergeReproducesTreeHashAfter(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	c := loadTreeKEM(t)[0]
	up := c.UpdatePaths[0]
	rt, err := ParseRatchetTree(suite, hx(t, c.RatchetTree))
	if err != nil {
		t.Fatal(err)
	}
	var path UpdatePath
	if err := path.UnmarshalMLS(hx(t, up.UpdatePath)); err != nil {
		t.Fatal(err)
	}
	if err := rt.Merge(up.Sender, &path); err != nil {
		t.Fatalf("merge: %v", err)
	}
	th, err := rt.RootTreeHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(th, hx(t, up.TreeHashAfter)) {
		t.Fatalf("tree_hash_after:\n got %x\nwant %x", th, hx(t, up.TreeHashAfter))
	}
	if ok, err := rt.VerifyParentHashes(); err != nil || !ok {
		t.Fatalf("VerifyParentHashes = %v, %v; want true, nil", ok, err)
	}
}
