// Package mmr implements a Merkle Mountain Range over the event log.
//
// Why an MMR rather than a plain Merkle tree: the log is append-only and its
// final length is unknown while recording. A balanced Merkle tree has to be
// rebuilt from scratch every time the leaf count changes, which would make
// emitting a signed tree head every K events quadratic. An MMR appends in
// amortised O(1), keeps every historical node immutable once written, and still
// yields O(log n) inclusion proofs.
//
// # Layout
//
// Nodes are stored in a single flat slice in post-order: both children are
// written before their parent. Appending leaf number n (1-based) triggers
// exactly TrailingZeros(n) merges, because a merge happens precisely when the
// new leaf completes a perfect subtree.
//
//	leaves  nodes
//	1       [L0]
//	2       [L0 L1 P01]
//	3       [L0 L1 P01 L2]
//	4       [L0 L1 P01 L2 L3 P23 P0123]
//
// The structure is therefore a forest of perfect binary trees ("mountains") of
// strictly decreasing height, one per set bit of the leaf count. Their roots are
// the peaks, and the MMR root is those peaks folded right-to-left ("bagging").
package mmr

import (
	"errors"
	"math/bits"

	"github.com/DevGurav/hark/internal/hashchain"
)

// MMR is an append-only Merkle Mountain Range. The zero value is ready to use.
type MMR struct {
	nodes  []hashchain.Hash
	leaves uint64
}

// New returns an empty MMR.
func New() *MMR { return &MMR{} }

// Leaves reports how many leaves have been appended.
func (m *MMR) Leaves() uint64 { return m.leaves }

// Nodes reports the total node count, interior nodes included. Exposed for the
// bundle writer, which persists the node slice so proofs can be generated later
// without replaying the whole log.
func (m *MMR) Nodes() []hashchain.Hash { return m.nodes }

// Load reconstructs an MMR from a persisted node slice and leaf count. It is the
// inverse of Nodes plus Leaves, and it validates that the two agree.
func Load(nodes []hashchain.Hash, leaves uint64) (*MMR, error) {
	if uint64(len(nodes)) != nodeCount(leaves) {
		return nil, errors.New("mmr: node count does not match leaf count")
	}
	return &MMR{nodes: nodes, leaves: leaves}, nil
}

// Add appends a leaf and returns its 0-based leaf index.
func (m *MMR) Add(leaf hashchain.Hash) uint64 {
	index := m.leaves
	m.nodes = append(m.nodes, leaf)
	m.leaves++

	// A merge happens once for each trailing zero bit of the new leaf count.
	// Leaf 4 (binary 100) closes two subtrees: the L2/L3 pair and then the
	// P01/P23 pair above it.
	merges := bits.TrailingZeros64(m.leaves)
	for h := 0; h < merges; h++ {
		right := m.nodes[len(m.nodes)-1]
		// The left sibling of a height-h node sits one whole subtree behind it,
		// and a perfect subtree of height h+1 occupies 2^(h+2)-1 nodes... but we
		// only need to skip back over the right subtree we just closed, which is
		// 2^(h+1)-1 nodes.
		left := m.nodes[len(m.nodes)-1-((1<<(h+1))-1)]
		m.nodes = append(m.nodes, hashchain.Node(left, right))
	}
	return index
}

// Root returns the MMR root: the peaks bagged right-to-left. An empty MMR hashes
// to the zero hash.
func (m *MMR) Root() hashchain.Hash {
	peaks := m.peakHashes()
	if len(peaks) == 0 {
		return hashchain.Zero
	}
	return bag(peaks)
}

// bag folds a peak list into a single root, right to left, so that the tallest
// mountain ends up outermost. The order is fixed by the format; reversing it
// would produce a different-but-valid-looking root, so it is spelled out in
// docs/protocol.md.
func bag(peaks []hashchain.Hash) hashchain.Hash {
	acc := peaks[len(peaks)-1]
	for i := len(peaks) - 2; i >= 0; i-- {
		acc = hashchain.Node(peaks[i], acc)
	}
	return acc
}

// peak describes one mountain in the range.
type peak struct {
	height    int    // 0 means a single leaf
	nodeIndex int    // flat-slice index of this mountain's root
	baseNode  int    // flat-slice index of this mountain's first node
	baseLeaf  uint64 // 0-based index of this mountain's leftmost leaf
}

// peaks walks the mountains left to right, tallest first. The heights are
// exactly the set bits of the leaf count, read from the top down.
func (m *MMR) peaks() []peak {
	var out []peak
	var nodePos int
	var leafPos uint64
	for h := 63; h >= 0; h-- {
		if m.leaves&(1<<uint(h)) == 0 {
			continue
		}
		size := (1 << uint(h+1)) - 1 // nodes in a perfect subtree of height h
		out = append(out, peak{
			height:    h,
			nodeIndex: nodePos + size - 1, // post-order: the root is last
			baseNode:  nodePos,
			baseLeaf:  leafPos,
		})
		nodePos += size
		leafPos += 1 << uint(h)
	}
	return out
}

func (m *MMR) peakHashes() []hashchain.Hash {
	ps := m.peaks()
	out := make([]hashchain.Hash, len(ps))
	for i, p := range ps {
		out[i] = m.nodes[p.nodeIndex]
	}
	return out
}

// nodeCount returns how many nodes an MMR with the given leaf count holds.
// Each perfect subtree of height h contributes 2^(h+1)-1 nodes.
func nodeCount(leaves uint64) uint64 {
	var n uint64
	for h := 0; h < 64; h++ {
		if leaves&(1<<uint(h)) != 0 {
			n += (1 << uint(h+1)) - 1
		}
	}
	return n
}
