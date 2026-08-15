package mmr

import (
	"fmt"
	"testing"

	"github.com/DevGurav/hark/internal/hashchain"
)

func leaf(i int) hashchain.Hash {
	return hashchain.Leaf(uint64(i), 1, []byte(fmt.Sprintf("event-%d", i)))
}

func build(n int) *MMR {
	m := New()
	for i := 0; i < n; i++ {
		m.Add(leaf(i))
	}
	return m
}

// The node count is the sum over set bits of the leaf count, which is what makes
// the flat post-order layout addressable at all. If this drifts, every offset
// computation in Prove and climb is silently wrong.
func TestNodeCountMatchesLayout(t *testing.T) {
	for n := 0; n <= 300; n++ {
		m := build(n)
		if got := uint64(len(m.nodes)); got != nodeCount(uint64(n)) {
			t.Fatalf("n=%d: %d nodes stored, formula says %d", n, got, nodeCount(uint64(n)))
		}
	}
}

func TestKnownLayout(t *testing.T) {
	// Four leaves must produce exactly L0 L1 P01 L2 L3 P23 P0123.
	m := build(4)
	if len(m.nodes) != 7 {
		t.Fatalf("expected 7 nodes, got %d", len(m.nodes))
	}
	p01 := hashchain.Node(leaf(0), leaf(1))
	p23 := hashchain.Node(leaf(2), leaf(3))
	want := []hashchain.Hash{leaf(0), leaf(1), p01, leaf(2), leaf(3), p23, hashchain.Node(p01, p23)}
	for i := range want {
		if m.nodes[i] != want[i] {
			t.Fatalf("node %d differs from the hand-computed value", i)
		}
	}
	// With a single peak, the root is that peak -- no bagging happens.
	if m.Root() != want[6] {
		t.Fatal("root of a perfect tree should be its only peak")
	}
}

// Every leaf of every range size must produce a proof that verifies. This is the
// test that actually exercises the peak arithmetic, since ranges that are not a
// power of two are where the bagging path matters.
func TestProofRoundTrip(t *testing.T) {
	for n := 1; n <= 130; n++ {
		m := build(n)
		root := m.Root()
		for i := 0; i < n; i++ {
			p, err := m.Prove(uint64(i))
			if err != nil {
				t.Fatalf("n=%d leaf=%d: %v", n, i, err)
			}
			if !Verify(root, leaf(i), p) {
				t.Fatalf("n=%d leaf=%d: proof did not verify", n, i)
			}
		}
	}
}

// A proof must not verify against a leaf it was not issued for. Without this,
// the structure would prove membership of the tree rather than of a position.
func TestProofRejectsWrongLeaf(t *testing.T) {
	for n := 2; n <= 40; n++ {
		m := build(n)
		root := m.Root()
		for i := 0; i < n; i++ {
			p, err := m.Prove(uint64(i))
			if err != nil {
				t.Fatal(err)
			}
			other := (i + 1) % n
			if Verify(root, leaf(other), p) {
				t.Fatalf("n=%d: proof for leaf %d accepted leaf %d", n, i, other)
			}
		}
	}
}

func TestProofRejectsTamperedSibling(t *testing.T) {
	m := build(37)
	root := m.Root()
	p, err := m.Prove(9)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Siblings) == 0 {
		t.Fatal("expected a non-empty sibling path")
	}
	p.Siblings[0][0] ^= 0x01
	if Verify(root, leaf(9), p) {
		t.Fatal("a modified sibling still verified")
	}
}

func TestProofRejectsWrongRoot(t *testing.T) {
	m := build(21)
	p, err := m.Prove(5)
	if err != nil {
		t.Fatal(err)
	}
	bad := m.Root()
	bad[31] ^= 0x01
	if Verify(bad, leaf(5), p) {
		t.Fatal("proof verified against an unrelated root")
	}
}

// A proof carries the leaf count it was issued under. Changing it must invalidate
// the proof, otherwise an old proof could be presented against a later root.
func TestProofRejectsAlteredLeafCount(t *testing.T) {
	m := build(19)
	root := m.Root()
	p, err := m.Prove(4)
	if err != nil {
		t.Fatal(err)
	}
	p.LeafCount = 20
	if Verify(root, leaf(4), p) {
		t.Fatal("proof verified after its leaf count was altered")
	}
}

func TestProveOutOfRange(t *testing.T) {
	m := build(5)
	if _, err := m.Prove(5); err == nil {
		t.Fatal("expected an out-of-range error")
	}
	empty := New()
	if _, err := empty.Prove(0); err == nil {
		t.Fatal("expected an out-of-range error on an empty range")
	}
}

func TestEmptyRoot(t *testing.T) {
	if New().Root() != hashchain.Zero {
		t.Fatal("an empty range should hash to zero")
	}
}

// Appending must never rewrite history: the root after n leaves has to be
// reproducible by building from scratch, and every earlier node must be
// untouched.
func TestAppendIsImmutable(t *testing.T) {
	m := New()
	var snapshots []hashchain.Hash
	for i := 0; i < 64; i++ {
		m.Add(leaf(i))
		snapshots = append(snapshots, m.Root())
	}
	for n := 1; n <= 64; n++ {
		if got := build(n).Root(); got != snapshots[n-1] {
			t.Fatalf("n=%d: incremental root differs from a fresh build", n)
		}
	}
}

func TestLoadRejectsMismatchedCounts(t *testing.T) {
	m := build(6)
	if _, err := Load(m.Nodes(), 7); err == nil {
		t.Fatal("expected Load to reject an inconsistent leaf count")
	}
	if _, err := Load(m.Nodes(), 6); err != nil {
		t.Fatalf("Load rejected a consistent range: %v", err)
	}
}

func BenchmarkAdd(b *testing.B) {
	m := New()
	l := leaf(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Add(l)
	}
}

func BenchmarkProve(b *testing.B) {
	m := build(100000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.Prove(uint64(i % 100000)); err != nil {
			b.Fatal(err)
		}
	}
}
