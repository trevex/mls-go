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
