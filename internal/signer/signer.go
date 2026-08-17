// Package signer produces and checks signed tree heads over the event log.
//
// A signed tree head (STH) is a statement of the form "at leaf count N, the MMR
// root was R, and I assert this at time T". It is the unit a transparency log
// anchors, and the unit a verifier checks.
//
// A caveat stated plainly, because it is the whole reason hark bothers with a
// transparency log at all: an STH signed by the operator's own key proves only
// that the operator signed it. Nothing stops that operator from discarding a
// run, rewriting its events, and signing the replacement. Signatures give
// integrity against third parties, not against the log's author. Non-equivocation
// requires an independent witness -- see docs/decisions/0004.
package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/DevGurav/hark/internal/hashchain"
)

// STH is a signed tree head.
type STH struct {
	RunID     string `cbor:"1,keyasint"`
	LeafCount uint64 `cbor:"2,keyasint"`
	Root      []byte `cbor:"3,keyasint"`
	SignedAt  int64  `cbor:"4,keyasint"` // Unix nanoseconds
	PublicKey []byte `cbor:"5,keyasint"`
	Signature []byte `cbor:"6,keyasint"`
}

// sthContext domain-separates the signing input, so an STH signature can never
// be replayed as a signature over some other hark structure that happens to
// serialise to the same bytes.
const sthContext = "hark/sth/v1"

// signingBytes builds the exact byte string that gets signed. Field lengths are
// fixed or length-prefixed so that no two distinct STHs can produce the same
// input -- concatenating variable-length fields without prefixes is how these
// schemes usually break.
func signingBytes(runID string, leafCount uint64, root hashchain.Hash, signedAt int64) []byte {
	b := make([]byte, 0, len(sthContext)+8+len(runID)+8+hashchain.Size+8)
	b = append(b, sthContext...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(runID)))
	b = append(b, runID...)
	b = binary.BigEndian.AppendUint64(b, leafCount)
	b = append(b, root[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(signedAt))
	return b
}

// Key is an Ed25519 keypair used to sign tree heads.
type Key struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// Generate creates a fresh keypair.
func Generate() (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv, pub: pub}, nil
}

// Public returns the verifying key.
func (k *Key) Public() ed25519.PublicKey { return k.pub }

// Sign produces a signed tree head.
func (k *Key) Sign(runID string, leafCount uint64, root hashchain.Hash, signedAt int64) *STH {
	msg := signingBytes(runID, leafCount, root, signedAt)
	return &STH{
		RunID:     runID,
		LeafCount: leafCount,
		Root:      root[:],
		SignedAt:  signedAt,
		PublicKey: k.pub,
		Signature: ed25519.Sign(k.priv, msg),
	}
}

// Verify checks an STH against the key embedded in it.
//
// Embedding the key means this only proves internal consistency: it says the
// holder of *some* key signed this root, not that it was a key you trust. The
// caller decides whether PublicKey is one it accepts. Callers that skip that
// step get no security from this function at all.
func (s *STH) Verify() error {
	if s == nil {
		return errors.New("signer: nil tree head")
	}
	if len(s.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("signer: public key is %d bytes, want %d", len(s.PublicKey), ed25519.PublicKeySize)
	}
	if len(s.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("signer: signature is %d bytes, want %d", len(s.Signature), ed25519.SignatureSize)
	}
	if len(s.Root) != hashchain.Size {
		return fmt.Errorf("signer: root is %d bytes, want %d", len(s.Root), hashchain.Size)
	}

	var root hashchain.Hash
	copy(root[:], s.Root)
	msg := signingBytes(s.RunID, s.LeafCount, root, s.SignedAt)

	if !ed25519.Verify(ed25519.PublicKey(s.PublicKey), msg, s.Signature) {
		return errors.New("signer: signature does not verify")
	}
	return nil
}

// SignedBytes returns the exact byte string the signature covers.
//
// A transparency log needs the message, not the root: an Ed25519 signature is
// over the whole message and cannot be checked against a digest of it. Exposing
// this rather than reconstructing it in the anchoring code keeps one definition
// of what was signed -- two would drift, and the failure would be a log entry
// that verifies against nothing.
func (s *STH) SignedBytes() ([]byte, error) {
	root, err := s.RootHash()
	if err != nil {
		return nil, err
	}
	return signingBytes(s.RunID, s.LeafCount, root, s.SignedAt), nil
}

// RootHash returns the STH's root as a fixed-size hash.
func (s *STH) RootHash() (hashchain.Hash, error) {
	var h hashchain.Hash
	if len(s.Root) != hashchain.Size {
		return h, fmt.Errorf("signer: root is %d bytes, want %d", len(s.Root), hashchain.Size)
	}
	copy(h[:], s.Root)
	return h, nil
}

const (
	pemTypePrivate = "HARK PRIVATE KEY"
	pemTypePublic  = "HARK PUBLIC KEY"
)

// Save writes the private key to path with owner-only permissions.
func (k *Key) Save(path string) error {
	block := &pem.Block{Type: pemTypePrivate, Bytes: k.priv}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// LoadKey reads a private key written by Save.
func LoadKey(path string) (*Key, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != pemTypePrivate {
		return nil, errors.New("signer: file does not contain a hark private key")
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer: private key is %d bytes, want %d", len(block.Bytes), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(block.Bytes)
	return &Key{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// EncodePublic renders a public key as PEM, for pinning in a config or pasting
// into an issue.
func EncodePublic(pub ed25519.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePublic, Bytes: pub})
}
