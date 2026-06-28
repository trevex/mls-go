package tree

import (
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/syntax"
)

// NodeType discriminates a populated ratchet-tree node (RFC 9420 §7.8/§12.4.3.1).
type NodeType uint8

const (
	NodeTypeReserved NodeType = 0
	NodeTypeLeaf     NodeType = 1
	NodeTypeParent   NodeType = 2
)

// Node is a populated ratchet-tree node. Exactly one of Leaf / Parent is set.
type Node struct {
	Leaf   *LeafNode
	Parent *ParentNode
}

func (n Node) marshal(b *syntax.Builder) error {
	switch {
	case n.Leaf != nil:
		b.WriteUint8(uint8(NodeTypeLeaf))
		return n.Leaf.marshal(b)
	case n.Parent != nil:
		b.WriteUint8(uint8(NodeTypeParent))
		return n.Parent.marshal(b)
	default:
		return fmt.Errorf("tree: empty Node")
	}
}

func decodeNode(c *syntax.Cursor) (Node, error) {
	var n Node
	t, err := c.ReadUint8()
	if err != nil {
		return n, err
	}
	switch NodeType(t) {
	case NodeTypeLeaf:
		l, err := decodeLeafNode(c)
		if err != nil {
			return n, err
		}
		n.Leaf = &l
	case NodeTypeParent:
		p, err := decodeParentNode(c)
		if err != nil {
			return n, err
		}
		n.Parent = &p
	default:
		return n, fmt.Errorf("tree: invalid node type %d", t)
	}
	return n, nil
}

// MarshalMLS encodes a single populated Node (RFC 9420 §12.4.3.1). To decode
// a full tree, use ParseRatchetTree (or RatchetTree.UnmarshalMLS), which carries
// the required cipher suite; a bare Node has no standalone UnmarshalMLS for
// that reason.
func (n Node) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := n.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// RatchetTree is the public ratchet tree for an epoch (RFC 9420 §7). nodes has
// length NodeWidth(leafCount); a nil entry is a blank node.
type RatchetTree struct {
	suite cipher.Suite
	nodes []*Node
}

// fullWidth returns the smallest complete-tree node width (2^k - 1) >= n.
func fullWidth(n uint32) uint32 {
	w := uint32(1)
	for w < n {
		w = 2*w + 1
	}
	return w
}

// ParseRatchetTree decodes the ratchet_tree extension wire form (the KAT
// "tree" field): optional<Node><V>, extended to full width (RFC 9420 §12.4.3.1).
func ParseRatchetTree(suite cipher.Suite, data []byte) (*RatchetTree, error) {
	c := syntax.NewCursor(data)
	nodes, err := syntax.ReadVectorV(c, func(c *syntax.Cursor) (*Node, error) {
		return syntax.ReadOptional(c, decodeNode)
	})
	if err != nil {
		return nil, err
	}
	if !c.Empty() {
		return nil, fmt.Errorf("tree: trailing bytes after ratchet_tree")
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("tree: empty ratchet_tree")
	}
	if nodes[len(nodes)-1] == nil {
		return nil, fmt.Errorf("tree: ratchet_tree must not end with a blank node")
	}
	w := fullWidth(uint32(len(nodes)))
	nodes = append(nodes, make([]*Node, w-uint32(len(nodes)))...)
	return &RatchetTree{suite: suite, nodes: nodes}, nil
}

// MarshalMLS serializes the tree to ratchet_tree wire form, truncating trailing
// blanks (RFC 9420 §12.4.3.1).
func (t *RatchetTree) MarshalMLS() ([]byte, error) {
	end := len(t.nodes)
	for end > 0 && t.nodes[end-1] == nil {
		end--
	}
	nodes := t.nodes[:end]
	b := syntax.NewBuilder()
	if err := syntax.WriteVectorV(b, nodes, func(b *syntax.Builder, n *Node) error {
		return syntax.WriteOptional(b, n, func(b *syntax.Builder, nn Node) error {
			return nn.marshal(b)
		})
	}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Width returns the number of array slots (NodeWidth of the tree).
func (t *RatchetTree) Width() uint32 { return uint32(len(t.nodes)) }

// leafCount returns the number of leaves: (width + 1) / 2.
func (t *RatchetTree) leafCount() uint32 { return (uint32(len(t.nodes)) + 1) / 2 }
