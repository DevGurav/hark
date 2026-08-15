package mmr

import (
	"errors"

	"github.com/DevGurav/hark/internal/hashchain"
)

// Proof is an inclusion proof: evidence that one specific leaf sits at one
// specific position in an MMR with a given root.
//
// It deliberately carries no direction bits. Whether a sibling joins from the
// left or the right is derived during verification from LeafIndex and
// LeafCount, which are already bound into the statement being proved. Storing
// directions explicitly would let a forger choose them, widening the search
// space for a second preimage; deriving them removes that freedom entirely.
type Proof struct {
	LeafIndex uint64           `cbor:"1,keyasint"`
	LeafCount uint64           `cbor:"2,keyasint"`
	Siblings  []hashchain.Hash `cbor:"3,keyasint"` // bottom-up, within the leaf's own mountain
	Left      []hashchain.Hash `cbor:"4,keyasint"` // peaks to the left, in order
	Right     []hashchain.Hash `cbor:"5,keyasint"` // peaks to the right, in order
}

// ErrOutOfRange is returned when a proof is requested for a leaf that does not
// exist in the range.
var ErrOutOfRange = errors.New("mmr: leaf index out of range")

// Prove builds an inclusion proof for the given 0-based leaf index.
//
// The proof has two parts. First the path up the leaf's own mountain, collecting
// the sibling at each level. Second the other peaks, which are needed to redo
// the bagging step and arrive back at the root.
func (m *MMR) Prove(leafIndex uint64) (*Proof, error) {
	if leafIndex >= m.leaves {
		return nil, ErrOutOfRange
	}

	ps := m.peaks()
	var (
		owner    int // which peak contains this leaf
		ownerSet bool
	)
	for i, p := range ps {
		if leafIndex < p.baseLeaf+(1<<uint(p.height)) {
			owner, ownerSet = i, true
			break
		}
	}
	if !ownerSet {
		return nil, ErrOutOfRange
	}

	p := ps[owner]
	siblings := m.climb(p.baseNode, p.height, leafIndex-p.baseLeaf)

	proof := &Proof{
		LeafIndex: leafIndex,
		LeafCount: m.leaves,
		Siblings:  siblings,
	}
	for i, q := range ps {
		switch {
		case i < owner:
			proof.Left = append(proof.Left, m.nodes[q.nodeIndex])
		case i > owner:
			proof.Right = append(proof.Right, m.nodes[q.nodeIndex])
		}
	}
	return proof, nil
}

// climb walks from a leaf up to the root of one perfect subtree, returning the
// sibling hash at each level, bottom first.
//
// The subtree occupies nodes [base, base+2^(h+1)-1) in post-order, which means
// the left child subtree starts at base, the right child subtree starts
// 2^h-1 nodes later, and each child's own root is the last node of its block.
//
// The descent is naturally top-down, so the collected siblings are reversed
// before returning: callers and the verifier both work bottom-up, where the
// direction at level i is simply bit i of the leaf's offset.
func (m *MMR) climb(base, height int, localLeaf uint64) []hashchain.Hash {
	out := make([]hashchain.Hash, 0, height)
	for h := height; h > 0; h-- {
		childNodes := (1 << uint(h)) - 1 // nodes in each child subtree
		leftBase := base
		rightBase := base + childNodes
		half := uint64(1) << uint(h-1) // leaves under the left child

		if localLeaf < half {
			// Descending left; the sibling is the right child's root.
			out = append(out, m.nodes[rightBase+childNodes-1])
			base = leftBase
		} else {
			out = append(out, m.nodes[leftBase+childNodes-1])
			base = rightBase
			localLeaf -= half
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Verify checks a proof against a root without access to the MMR itself. This is
// the function a third party runs: it needs the leaf, the proof, and a root they
// obtained independently (from a signed tree head, or from a transparency log).
func Verify(root, leaf hashchain.Hash, p *Proof) bool {
	if p == nil || p.LeafIndex >= p.LeafCount {
		return false
	}

	// Re-derive which mountain the leaf belongs to, and how far along it sits.
	// This is the same walk as peaks(), done without the node slice.
	var (
		height   = -1
		baseLeaf uint64
		found    bool
		leftCnt  int
		rightCnt int
	)
	var seen int
	for h := 63; h >= 0; h-- {
		if p.LeafCount&(1<<uint(h)) == 0 {
			continue
		}
		size := uint64(1) << uint(h)
		if !found && p.LeafIndex < baseLeaf+size {
			height, found = h, true
			leftCnt = seen
		} else if !found {
			baseLeaf += size
		} else {
			rightCnt++
		}
		if !found {
			seen++
		}
	}
	if !found {
		return false
	}

	// The sibling path must be exactly as tall as the mountain.
	if len(p.Siblings) != height || len(p.Left) != leftCnt || len(p.Right) != rightCnt {
		return false
	}

	// Fold the leaf up to its mountain's root. The direction at each level is the
	// corresponding bit of the leaf's offset within the mountain, read from the
	// bottom up: bit 0 decides the first join.
	local := p.LeafIndex - baseLeaf
	acc := leaf
	for i, sib := range p.Siblings {
		if local&(1<<uint(i)) == 0 {
			acc = hashchain.Node(acc, sib) // we are the left child
		} else {
			acc = hashchain.Node(sib, acc) // we are the right child
		}
	}

	// Re-bag with our recomputed peak in place.
	peaks := make([]hashchain.Hash, 0, len(p.Left)+1+len(p.Right))
	peaks = append(peaks, p.Left...)
	peaks = append(peaks, acc)
	peaks = append(peaks, p.Right...)

	return bag(peaks) == root
}
