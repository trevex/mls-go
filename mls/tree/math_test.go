package tree

import "testing"

func TestNodeWidth(t *testing.T) {
	cases := map[uint32]uint32{1: 1, 2: 3, 3: 5, 4: 7, 5: 9}
	for n, want := range cases {
		if got := NodeWidth(n); got != want {
			t.Fatalf("NodeWidth(%d)=%d, want %d", n, got, want)
		}
	}
}

func TestParentNonPowerOfTwo(t *testing.T) {
	// nLeaves=5 => width 9, root 7. Node 8's naive parentStep lands out of
	// range, so Parent must walk up to the root. Exercises the walk-up loop.
	if p, ok := Parent(8, 5); !ok || p != 7 {
		t.Fatalf("Parent(8,5)=(%d,%v), want (7,true)", p, ok)
	}
	if p, ok := Parent(6, 5); !ok || p != 5 {
		t.Fatalf("Parent(6,5)=(%d,%v), want (5,true)", p, ok)
	}
	if s, ok := Sibling(8, 5); !ok || s != 3 {
		t.Fatalf("Sibling(8,5)=(%d,%v), want (3,true)", s, ok)
	}
	// Right child of the root in a 5-leaf tree must be clamped into the tree.
	if r, ok := Right(7, 5); !ok || r != 8 {
		t.Fatalf("Right(7,5)=(%d,%v), want (8,true)", r, ok)
	}
	// Sibling of node 3 (the previously-buggy left-branch case).
	if s, ok := Sibling(3, 5); !ok || s != 8 {
		t.Fatalf("Sibling(3,5)=(%d,%v), want (8,true)", s, ok)
	}
}

func TestRootAndParentSmall(t *testing.T) {
	if got := Root(4); got != 3 {
		t.Fatalf("Root(4)=%d, want 3", got)
	}
	p, ok := Parent(0, 4)
	if !ok || p != 1 {
		t.Fatalf("Parent(0,4)=(%d,%v), want (1,true)", p, ok)
	}
	if _, ok := Parent(3, 4); ok {
		t.Fatal("Parent(root) should be none")
	}
	if _, ok := Left(0); ok {
		t.Fatal("Left(leaf) should be none")
	}
}
