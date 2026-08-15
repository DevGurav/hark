// Package hashchain provides the domain-separated hash primitives used by every
// other package in hark.
//
// Three distinct hash constructions appear in a bundle, and they must never be
// confusable with one another:
//
//	leaf  = H(0x00 || seq || kind || payload)   one recorded event
//	node  = H(0x01 || left || right)            an interior Merkle node
//	chain = H(0x02 || prev || leaf)             the running append-only chain
//
// The leading domain byte is what keeps them apart. Without it an attacker who
// controls event payloads could craft a payload whose bytes happen to equal the
// concatenation of two child hashes, and then present that leaf as if it were an
// interior node -- the classic second-preimage attack on Merkle trees that
// RFC 6962 fixes the same way for Certificate Transparency.
package hashchain

import (
	"encoding/binary"

	"lukechampine.com/blake3"
)

// Size is the length of every hash hark produces, in bytes.
const Size = 32

// Hash is a 32-byte BLAKE3 digest.
type Hash [Size]byte

// Domain separation prefixes. These values are part of the on-disk format:
// changing one invalidates every bundle ever written, so they are frozen.
const (
	domainLeaf  byte = 0x00
	domainNode  byte = 0x01
	domainChain byte = 0x02
)

// Zero is the all-zero hash. It is the chain predecessor of the first event and
// the root of an empty Merkle Mountain Range.
var Zero Hash

// Leaf computes the hash of a single recorded event.
//
// seq and kind are bound into the digest alongside the payload so that an event
// cannot be replayed at a different position in the log, or reinterpreted as a
// different kind of event, without changing its hash.
func Leaf(seq uint64, kind uint8, payload []byte) Hash {
	h := blake3.New(Size, nil)
	var scratch [9]byte
	scratch[0] = domainLeaf
	binary.BigEndian.PutUint64(scratch[1:9], seq)
	h.Write(scratch[:])
	h.Write([]byte{kind})
	h.Write(payload)
	return sum(h)
}

// Node computes the hash of an interior Merkle node from its two children.
func Node(left, right Hash) Hash {
	h := blake3.New(Size, nil)
	h.Write([]byte{domainNode})
	h.Write(left[:])
	h.Write(right[:])
	return sum(h)
}

// Chain advances the running hash chain by one event.
//
// The chain is what gives O(1) streaming integrity: every frame carries the
// chain value of its predecessor, so a reader can validate a partially written
// log up to the point where it was truncated. A run killed by SIGKILL still
// leaves a verifiable prefix, which the Merkle root alone would not provide
// because the root is only sealed at the end.
func Chain(prev, leaf Hash) Hash {
	h := blake3.New(Size, nil)
	h.Write([]byte{domainChain})
	h.Write(prev[:])
	h.Write(leaf[:])
	return sum(h)
}

func sum(h *blake3.Hasher) Hash {
	var out Hash
	h.Sum(out[:0])
	return out
}
