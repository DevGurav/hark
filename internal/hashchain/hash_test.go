package hashchain

import "testing"

// The whole point of the domain bytes is that a leaf, a node and a chain step
// over identical-looking input produce different digests. If this ever passes
// by accident the second-preimage defence is gone.
func TestDomainsAreSeparated(t *testing.T) {
	var a, b Hash
	a[0], b[0] = 1, 2

	leafOverPair := Leaf(0, 0, append(a[:], b[:]...))
	node := Node(a, b)
	chain := Chain(a, b)

	if leafOverPair == node {
		t.Fatal("a leaf over two concatenated hashes collided with an interior node")
	}
	if node == chain {
		t.Fatal("node and chain constructions collided")
	}
	if leafOverPair == chain {
		t.Fatal("leaf and chain constructions collided")
	}
}

// A leaf binds its position and kind, not just its bytes. Moving an event
// elsewhere in the log, or relabelling it, must change its hash.
func TestLeafBindsSeqAndKind(t *testing.T) {
	payload := []byte("same bytes")

	base := Leaf(7, 5, payload)
	if Leaf(8, 5, payload) == base {
		t.Fatal("changing the sequence number did not change the leaf hash")
	}
	if Leaf(7, 6, payload) == base {
		t.Fatal("changing the kind did not change the leaf hash")
	}
	if Leaf(7, 5, []byte("other bytes")) == base {
		t.Fatal("changing the payload did not change the leaf hash")
	}
}

func TestDeterministic(t *testing.T) {
	p := []byte("payload")
	if Leaf(3, 2, p) != Leaf(3, 2, p) {
		t.Fatal("Leaf is not deterministic")
	}
	var a, b Hash
	a[0], b[0] = 9, 9
	if Node(a, b) != Node(a, b) {
		t.Fatal("Node is not deterministic")
	}
}

// Node is intentionally order-sensitive: swapping children is a different tree.
func TestNodeIsOrdered(t *testing.T) {
	var a, b Hash
	a[0], b[0] = 1, 2
	if Node(a, b) == Node(b, a) {
		t.Fatal("Node ignored child order")
	}
}

func TestChainAdvances(t *testing.T) {
	l1 := Leaf(0, 1, []byte("one"))
	l2 := Leaf(1, 1, []byte("two"))

	c1 := Chain(Zero, l1)
	c2 := Chain(c1, l2)

	if c1 == Zero || c2 == c1 {
		t.Fatal("the chain did not advance")
	}
	// Feeding the same leaves in the other order must land somewhere else,
	// otherwise reordering a log would go undetected.
	if Chain(Chain(Zero, l2), l1) == c2 {
		t.Fatal("chain is insensitive to event order")
	}
}
