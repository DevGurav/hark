package bundle

import (
	"errors"
	"fmt"
	"io"

	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/mmr"
	"github.com/DevGurav/hark/internal/signer"
)

// Status is the overall outcome of verifying a bundle.
type Status string

const (
	// StatusSealed means the run completed, the footer is present, and every
	// check passed.
	StatusSealed Status = "sealed"

	// StatusTruncated means the chain verified for every frame present, but the
	// bundle has no footer. The run was killed. This is a legitimate state, and
	// the events that survived are as trustworthy as they would have been in a
	// sealed bundle -- there is simply no signed root over them.
	StatusTruncated Status = "truncated"

	// StatusBroken means a check failed. FirstBadSeq says where.
	StatusBroken Status = "broken"
)

// Result reports what verification found.
type Result struct {
	Status     Status
	RunID      string
	LeafCount  uint64
	Root       hashchain.Hash
	FinalChain hashchain.Hash

	Signed      bool
	SignatureOK bool
	PublicKey   []byte
	RekorEntry  string
	RekorIndex  int64

	// STH is the sealed tree head itself, kept so a caller can check it against
	// what a transparency log holds. The log stores the signed bytes, and
	// rebuilding them from the fields above would be a second definition of what
	// was signed.
	STH *signer.STH

	// FirstBadSeq is the sequence number of the first frame that failed, and
	// Problem describes it. Reporting where a log diverges is more useful than a
	// bare pass/fail: it distinguishes a corrupt payload from a spliced chain
	// from a rewritten tail.
	FirstBadSeq int64
	Problem     string

	KindCounts map[logfmt.Kind]uint64
}

// Verify walks a bundle end to end and checks every invariant it can check
// locally.
//
// What this proves: the frames are internally consistent, they form an unbroken
// chain, they hash to the sealed root, and whoever holds the embedded key signed
// that root.
//
// What this does not prove: that the bundle is the *only* one the operator
// produced for this run. A local check cannot establish non-equivocation. That
// requires an inclusion proof against a log the operator does not control, which
// is what the Rekor fields are for and why they are reported separately rather
// than folded into a single boolean.
func Verify(path string) (*Result, error) {
	r, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	res := &Result{
		RunID:       r.Header().RunID,
		FirstBadSeq: -1,
		KindCounts:  make(map[logfmt.Kind]uint64),
	}

	tree := mmr.New()
	var (
		chain    hashchain.Hash
		expected uint64
	)

	for {
		f, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// Truncated final frame. Everything before it already verified, so
			// keep the prefix and say so.
			res.Status = StatusTruncated
			res.Problem = fmt.Sprintf("final frame truncated after seq %d", int64(expected)-1)
			res.LeafCount = expected
			res.Root = tree.Root()
			res.FinalChain = chain
			return res, nil
		}
		if err != nil {
			return nil, err
		}

		// On a fault, report the prefix that did verify rather than zeroes. The
		// events before the damage are still evidence, and an operator needs to
		// know how much of the run survived.
		if f.Seq != expected {
			res.Status = StatusBroken
			res.FirstBadSeq = int64(f.Seq)
			res.Problem = fmt.Sprintf("expected seq %d, found %d: events are missing or reordered", expected, f.Seq)
			res.LeafCount, res.Root, res.FinalChain = expected, tree.Root(), chain
			return res, nil
		}
		if err := f.Validate(chain); err != nil {
			res.Status = StatusBroken
			res.FirstBadSeq = int64(f.Seq)
			res.Problem = err.Error()
			res.LeafCount, res.Root, res.FinalChain = expected, tree.Root(), chain
			return res, nil
		}

		chain = f.Chain
		tree.Add(f.Leaf)
		res.KindCounts[f.Kind]++
		expected++
	}

	res.LeafCount = expected
	res.Root = tree.Root()
	res.FinalChain = chain

	foot := r.Footer()
	if foot == nil {
		res.Status = StatusTruncated
		res.Problem = "no footer: run did not seal"
		return res, nil
	}

	if foot.LeafCount != expected {
		res.Status = StatusBroken
		res.Problem = fmt.Sprintf("footer claims %d events, found %d", foot.LeafCount, expected)
		return res, nil
	}
	if !equalHash(foot.Root, res.Root) {
		res.Status = StatusBroken
		res.Problem = "recomputed Merkle root does not match the sealed root"
		return res, nil
	}
	if !equalHash(foot.FinalChain, res.FinalChain) {
		res.Status = StatusBroken
		res.Problem = "recomputed chain value does not match the sealed chain"
		return res, nil
	}

	res.RekorEntry = foot.RekorEntry
	res.RekorIndex = foot.RekorIndex

	if foot.STH != nil {
		res.Signed = true
		res.STH = foot.STH
		res.PublicKey = foot.STH.PublicKey
		if err := foot.STH.Verify(); err != nil {
			res.Status = StatusBroken
			res.Problem = "signed tree head: " + err.Error()
			return res, nil
		}
		// The signature is over a root; that root must be the one we recomputed,
		// otherwise a valid signature over an unrelated tree would pass.
		sthRoot, err := foot.STH.RootHash()
		if err != nil {
			res.Status = StatusBroken
			res.Problem = "signed tree head: " + err.Error()
			return res, nil
		}
		if sthRoot != res.Root {
			res.Status = StatusBroken
			res.Problem = "signed tree head covers a different root than the bundle contains"
			return res, nil
		}
		if foot.STH.LeafCount != expected {
			res.Status = StatusBroken
			res.Problem = "signed tree head covers a different event count"
			return res, nil
		}
		res.SignatureOK = true
	}

	res.Status = StatusSealed
	return res, nil
}

// Prove produces an inclusion proof for one event by replaying the bundle's
// leaves into a fresh MMR.
func Prove(path string, seq uint64) (*mmr.Proof, hashchain.Hash, hashchain.Hash, error) {
	r, err := Open(path)
	if err != nil {
		return nil, hashchain.Zero, hashchain.Zero, err
	}
	defer r.Close()

	tree := mmr.New()
	var target hashchain.Hash
	var found bool

	for {
		f, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, hashchain.Zero, hashchain.Zero, err
		}
		if f.Seq == seq {
			target, found = f.Leaf, true
		}
		tree.Add(f.Leaf)
	}
	if !found {
		return nil, hashchain.Zero, hashchain.Zero, fmt.Errorf("bundle: no event with seq %d", seq)
	}

	p, err := tree.Prove(seq)
	if err != nil {
		return nil, hashchain.Zero, hashchain.Zero, err
	}
	return p, target, tree.Root(), nil
}

func equalHash(b []byte, h hashchain.Hash) bool {
	if len(b) != hashchain.Size {
		return false
	}
	for i := range h {
		if b[i] != h[i] {
			return false
		}
	}
	return true
}
