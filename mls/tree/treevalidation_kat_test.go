package tree_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

type treeValidationCase struct {
	CipherSuite uint16             `json:"cipher_suite"`
	GroupID     katutil.HexBytes   `json:"group_id"`
	Tree        katutil.HexBytes   `json:"tree"`
	Resolutions [][]uint32         `json:"resolutions"`
	TreeHashes  []katutil.HexBytes `json:"tree_hashes"`
}

func eqU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTreeValidationKAT(t *testing.T) {
	var cases []treeValidationCase
	katutil.Load(t, "tree-validation.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no tree-validation vectors loaded")
	}
	executed := 0
	for idx, c := range cases {
		c := c
		t.Run(fmt.Sprintf("case=%d/suite=%d", idx, c.CipherSuite), func(t *testing.T) {
			suite, ok := cipher.Lookup(cipher.CipherSuite(c.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", c.CipherSuite)
			}
			executed++
			rt, err := tree.ParseRatchetTree(suite, c.Tree)
			if err != nil {
				t.Fatalf("parse tree: %v", err)
			}
			if int(rt.Width()) != len(c.Resolutions) {
				t.Fatalf("width %d != len(resolutions) %d", rt.Width(), len(c.Resolutions))
			}
			if int(rt.Width()) != len(c.TreeHashes) {
				t.Fatalf("width %d != len(tree_hashes) %d", rt.Width(), len(c.TreeHashes))
			}
			for i := uint32(0); i < rt.Width(); i++ {
				if got := rt.Resolution(i); !eqU32(got, c.Resolutions[i]) {
					t.Fatalf("resolution[%d]=%v want %v", i, got, c.Resolutions[i])
				}
				got, err := rt.TreeHash(i)
				if err != nil {
					t.Fatalf("tree hash[%d]: %v", i, err)
				}
				if !bytes.Equal(got, c.TreeHashes[i]) {
					t.Fatalf("tree_hash[%d]=%x want %x", i, got, []byte(c.TreeHashes[i]))
				}
			}
			ok2, err := rt.VerifyParentHashes()
			if err != nil {
				t.Fatalf("verify parent hashes: %v", err)
			}
			if !ok2 {
				t.Fatal("parent hash verification failed")
			}
			if err := rt.VerifyLeafSignatures(c.GroupID); err != nil {
				t.Fatalf("leaf signatures: %v", err)
			}
		})
	}
	if executed == 0 {
		t.Fatal("no vectors executed (all skipped) — check cipher suite registration")
	}
}
