// Package rekor anchors a sealed tree head in a public transparency log.
//
// Why at all: an operator-signed root proves only that the operator signed it.
// They can discard a run, rewrite its events, sign the replacement, and present
// it as the only run that ever happened. An entry in a log the operator does
// not run turns "I promise this is what happened" into "this commitment was
// public at time T and cannot be changed now without detection". That is the
// property, and it is the whole reason for the network dependency --
// [ADR-0004](../../docs/decisions/0004-transparency-log-over-operator-signed-receipts.md).
//
// Anchoring is optional and never fatal. Rekor being unreachable must not mean
// a run cannot be recorded, so a failed anchor seals the bundle unanchored and
// says so.
package rekor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"time"

	"github.com/DevGurav/hark/internal/signer"
)

// PublicLog is the Sigstore public instance.
const PublicLog = "https://rekor.sigstore.dev"

// Client talks to one Rekor instance.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New builds a client with a bounded timeout. Sealing must not hang on a log
// that has stopped answering: the bundle is already complete by then, and the
// anchor is the optional part.
func New(baseURL string) *Client {
	if baseURL == "" {
		baseURL = PublicLog
	}
	return &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// Entry is a log entry as hark cares about it.
type Entry struct {
	UUID string

	// LogIndex is the entry's position across the whole log, spanning every
	// shard it has ever had. It identifies the entry and is what a person looks
	// it up by -- but it is *not* the index the inclusion proof is against, and
	// mixing the two produces a report that contradicts itself: a public log has
	// long since passed the point where the global index exceeds the current
	// tree's size.
	LogIndex int64

	LogID          string
	IntegratedTime int64

	// Body is the canonicalised entry the log actually stored, base64-decoded.
	// It is what the Merkle leaf covers, so inclusion is checked against these
	// bytes rather than against what was submitted.
	Body []byte

	Proof *InclusionProof
}

// InclusionProof is the log's evidence that an entry is in its tree.
type InclusionProof struct {
	// LogIndex here is the leaf's position within TreeSize, in the currently
	// active shard -- a different number from Entry.LogIndex, and the only one
	// the proof arithmetic is valid against.
	LogIndex   int64
	RootHash   []byte
	TreeSize   int64
	Hashes     [][]byte
	Checkpoint string
}

// ---------- submission ----------

// Anchor submits a signed tree head and returns the log entry.
//
// The submitted artifact is the STH's signed bytes -- run id, leaf count, root
// and timestamp -- not the bundle. The bundle can be enormous and can contain
// the full text of model traffic; the commitment is what needs to be public,
// and it is the thing a later verifier compares against.
func (c *Client) Anchor(ctx context.Context, sth *signer.STH) (*Entry, error) {
	if sth == nil {
		return nil, fmt.Errorf("rekor: nothing to anchor: the bundle is unsigned")
	}
	signed, err := sth.SignedBytes()
	if err != nil {
		return nil, err
	}
	pubPEM, err := publicKeyPEM(sth.PublicKey)
	if err != nil {
		return nil, err
	}

	// The "rekord" type carries the signed content, so the log verifies the
	// signature itself. Its "hashedrekord" sibling carries only a digest, which
	// cannot work here: Ed25519 signs the message, and a verifier handed a
	// digest has nothing to check it against.
	proposed := map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "rekord",
		"spec": map[string]any{
			"data": map[string]any{
				"content": base64.StdEncoding.EncodeToString(signed),
			},
			"signature": map[string]any{
				"format":  "x509",
				"content": base64.StdEncoding.EncodeToString(sth.Signature),
				"publicKey": map[string]any{
					"content": base64.StdEncoding.EncodeToString(pubPEM),
				},
			},
		},
	}
	body, err := json.Marshal(proposed)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rekor: submitting to %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
	case http.StatusConflict:
		// The log already holds this exact entry. Not an error: the commitment
		// is public either way, which is the only thing being claimed.
		return nil, fmt.Errorf("rekor: this tree head is already in the log (%s)", resp.Header.Get("Location"))
	default:
		return nil, fmt.Errorf("rekor: %s said %s: %s", c.BaseURL, resp.Status, snippet(raw))
	}

	return parseEntries(raw)
}

// ---------- retrieval and checking ----------

// Fetch reads one entry back by UUID.
func (c *Client) Fetch(ctx context.Context, uuid string) (*Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/v1/log/entries/"+uuid, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rekor: fetching from %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rekor: %s said %s: %s", c.BaseURL, resp.Status, snippet(raw))
	}
	return parseEntries(raw)
}

// ErrNotFound means the log does not hold the entry the bundle names. That is a
// verification failure rather than a network problem: the bundle claims an
// anchor it does not have.
var ErrNotFound = fmt.Errorf("rekor: the log has no such entry")

// Covers checks that this entry is the log's record of sth.
//
// Without it, "the log holds entry X" and "entry X is this run" are two claims
// with nothing joining them, and a bundle could name any entry at all.
func (e *Entry) Covers(sth *signer.STH) error {
	var body struct {
		Spec struct {
			Data struct {
				Hash struct {
					Algorithm string `json:"algorithm"`
					Value     string `json:"value"`
				} `json:"hash"`
			} `json:"data"`
			Signature struct {
				Content string `json:"content"`
			} `json:"signature"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(e.Body, &body); err != nil {
		return fmt.Errorf("rekor: the log entry is not a rekord: %w", err)
	}

	signed, err := sth.SignedBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(signed)
	if got := body.Spec.Data.Hash.Value; got != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("rekor: the log entry covers different content (%s)", got)
	}
	if got := body.Spec.Signature.Content; got != base64.StdEncoding.EncodeToString(sth.Signature) {
		return fmt.Errorf("rekor: the log entry carries a different signature")
	}
	return nil
}

// VerifyInclusion recomputes the log's root from the entry and its proof.
//
// The log's word for it is not evidence. Recomputing the root from the leaf and
// the sibling hashes is what turns "the API returned 200" into a check, and it
// is the same reason hark verifies its own inclusion proofs rather than
// trusting the bundle that carries them.
func (e *Entry) VerifyInclusion() error {
	if e.Proof == nil {
		return fmt.Errorf("rekor: the log returned no inclusion proof")
	}
	p := e.Proof
	if p.TreeSize <= 0 || p.LogIndex < 0 || p.LogIndex >= p.TreeSize {
		return fmt.Errorf("rekor: index %d is not inside a tree of %d", p.LogIndex, p.TreeSize)
	}

	root, err := rootFromProof(uint64(p.LogIndex), uint64(p.TreeSize), leafHash(e.Body), p.Hashes)
	if err != nil {
		return err
	}
	if !bytes.Equal(root, p.RootHash) {
		return fmt.Errorf("rekor: the proof does not reconstruct the log's root")
	}
	return nil
}

// ---------- RFC 6962 Merkle arithmetic ----------
//
// This is the log's tree, not hark's: SHA-256 with RFC 6962's 0x00/0x01 domain
// prefixes, where a hark bundle uses BLAKE3 with its own. Reusing
// internal/hashchain here would produce hashes that are correct for the wrong
// tree, so the two constructions stay deliberately separate.

func leafHash(body []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(body)
	return h.Sum(nil)
}

func hashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// rootFromProof folds an inclusion proof back into a root.
//
// The proof carries no direction bits -- direction is derived from the leaf
// index and the tree size, exactly as in hark's own MMR proofs, so a forger
// cannot choose which side a sibling goes on.
func rootFromProof(index, size uint64, leaf []byte, proof [][]byte) ([]byte, error) {
	// inner is how many steps stay inside the tree's perfect subtrees; border is
	// how many bagged peaks remain above them.
	inner := bits.Len64(index ^ (size - 1))
	border := bits.OnesCount64(index >> uint(inner))
	if len(proof) != inner+border {
		return nil, fmt.Errorf("rekor: inclusion proof has %d hashes, expected %d for leaf %d of %d",
			len(proof), inner+border, index, size)
	}

	res := leaf
	for i, h := range proof[:inner] {
		if (index>>uint(i))&1 == 0 {
			res = hashChildren(res, h)
		} else {
			res = hashChildren(h, res)
		}
	}
	for _, h := range proof[inner:] {
		res = hashChildren(h, res)
	}
	return res, nil
}

// ---------- wire decoding ----------

// parseEntries reads Rekor's map-keyed response, which holds one entry under
// its own UUID.
func parseEntries(raw []byte) (*Entry, error) {
	var wire map[string]struct {
		Body           string `json:"body"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
		IntegratedTime int64  `json:"integratedTime"`
		Verification   struct {
			InclusionProof struct {
				LogIndex   int64    `json:"logIndex"`
				RootHash   string   `json:"rootHash"`
				TreeSize   int64    `json:"treeSize"`
				Hashes     []string `json:"hashes"`
				Checkpoint string   `json:"checkpoint"`
			} `json:"inclusionProof"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("rekor: unreadable response: %w", err)
	}
	if len(wire) == 0 {
		return nil, fmt.Errorf("rekor: the response carries no entry")
	}

	for uuid, v := range wire {
		body, err := base64.StdEncoding.DecodeString(v.Body)
		if err != nil {
			return nil, fmt.Errorf("rekor: entry body is not base64: %w", err)
		}
		e := &Entry{
			UUID:           uuid,
			LogIndex:       v.LogIndex,
			LogID:          v.LogID,
			IntegratedTime: v.IntegratedTime,
			Body:           body,
		}
		ip := v.Verification.InclusionProof
		if ip.TreeSize > 0 {
			root, err := hex.DecodeString(ip.RootHash)
			if err != nil {
				return nil, fmt.Errorf("rekor: inclusion proof root is not hex: %w", err)
			}
			proof := &InclusionProof{
				LogIndex: ip.LogIndex, RootHash: root,
				TreeSize: ip.TreeSize, Checkpoint: ip.Checkpoint,
			}
			for _, h := range ip.Hashes {
				b, err := hex.DecodeString(h)
				if err != nil {
					return nil, fmt.Errorf("rekor: inclusion proof hash is not hex: %w", err)
				}
				proof.Hashes = append(proof.Hashes, b)
			}
			e.Proof = proof
		}
		return e, nil
	}
	return nil, fmt.Errorf("rekor: the response carries no entry")
}

// publicKeyPEM renders an Ed25519 key the way the log expects it: PKIX/SPKI in
// PEM. hark's own key files use a different PEM label and carry the raw key, so
// this conversion belongs here rather than in the signer -- it is a detail of
// the log's wire format, not of how hark stores keys.
func publicKeyPEM(pub []byte) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("rekor: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func snippet(b []byte) string {
	const max = 300
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}
