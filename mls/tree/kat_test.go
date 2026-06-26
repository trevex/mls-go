package tree_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/internal/katutil"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// nodeRef models a JSON element that is either a node index or null.
type nodeRef struct {
	val uint32
	set bool
}

func (n *nodeRef) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		n.set = false
		return nil
	}
	var v uint32
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	n.val, n.set = v, true
	return nil
}

type treeMathCase struct {
	NLeaves uint32    `json:"n_leaves"`
	NNodes  uint32    `json:"n_nodes"`
	Root    uint32    `json:"root"`
	Left    []nodeRef `json:"left"`
	Right   []nodeRef `json:"right"`
	Parent  []nodeRef `json:"parent"`
	Sibling []nodeRef `json:"sibling"`
}

func check(t *testing.T, idx int, name string, want nodeRef, gotVal uint32, gotOK bool) {
	t.Helper()
	if want.set != gotOK || (gotOK && want.val != gotVal) {
		t.Fatalf("node %d %s: got (%d,%v), want (%d,%v)", idx, name, gotVal, gotOK, want.val, want.set)
	}
}

func TestTreeMathKAT(t *testing.T) {
	var cases []treeMathCase
	katutil.Load(t, "tree-math.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no tree-math vectors loaded")
	}
	for _, c := range cases {
		c := c
		t.Run(fmt.Sprintf("nLeaves=%d", c.NLeaves), func(t *testing.T) {
			if got := tree.NodeWidth(c.NLeaves); got != c.NNodes {
				t.Fatalf("NodeWidth(%d)=%d, want %d", c.NLeaves, got, c.NNodes)
			}
			if got := tree.Root(c.NLeaves); got != c.Root {
				t.Fatalf("Root(%d)=%d, want %d", c.NLeaves, got, c.Root)
			}
			for i := uint32(0); i < c.NNodes; i++ {
				lv, lok := tree.Left(i)
				check(t, int(i), "left", c.Left[i], lv, lok)
				rv, rok := tree.Right(i, c.NLeaves)
				check(t, int(i), "right", c.Right[i], rv, rok)
				pv, pok := tree.Parent(i, c.NLeaves)
				check(t, int(i), "parent", c.Parent[i], pv, pok)
				sv, sok := tree.Sibling(i, c.NLeaves)
				check(t, int(i), "sibling", c.Sibling[i], sv, sok)
			}
		})
	}
}
