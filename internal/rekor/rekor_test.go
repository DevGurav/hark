package rekor

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/signer"
)

// A reference RFC 6962 tree, built the obvious way, so the proof folding is
// checked against an independent construction rather than against itself.
type refTree struct{ leaves [][]byte }

func (t *refTree) add(b []byte) { t.leaves = append(t.leaves, leafHash(b)) }

// root over leaves[lo:hi], the recursive definition straight from the RFC.
func (t *refTree) root(lo, hi int) []byte {
	if hi-lo == 1 {
		return t.leaves[lo]
	}
	k := largestPowerOfTwoLessThan(hi - lo)
	return hashChildren(t.root(lo, lo+k), t.root(lo+k, hi))
}

// proof for leaf i within leaves[lo:hi], as PATH(m, D[n]) in the RFC.
func (t *refTree) proof(i, lo, hi int) [][]byte {
	if hi-lo == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(hi - lo)
	if i-lo < k {
		return append(t.proof(i, lo, lo+k), t.root(lo+k, hi))
	}
	return append(t.proof(i, lo+k, hi), t.root(lo, lo+k))
}

func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// Every leaf of every tree size up to 33, so the awkward shapes -- a lone
// rightmost leaf, a tree one past a power of two -- are all covered rather than
// sampled. This is where an off-by-one in the border count hides.
func TestInclusionProofFoldsBackToTheRoot(t *testing.T) {
	for size := 1; size <= 33; size++ {
		tree := &refTree{}
		for i := 0; i < size; i++ {
			tree.add([]byte{byte(i), byte(size)})
		}
		root := tree.root(0, size)

		for i := 0; i < size; i++ {
			proof := tree.proof(i, 0, size)
			got, err := rootFromProof(uint64(i), uint64(size), tree.leaves[i], proof)
			if err != nil {
				t.Fatalf("size %d leaf %d: %v", size, i, err)
			}
			if !strings.EqualFold(hex.EncodeToString(got), hex.EncodeToString(root)) {
				t.Fatalf("size %d leaf %d: reconstructed the wrong root", size, i)
			}
		}
	}
}

// A proof for the wrong leaf, or with a sibling altered, must not verify --
// otherwise the check is decoration.
func TestInclusionProofRejectsTampering(t *testing.T) {
	tree := &refTree{}
	for i := 0; i < 9; i++ {
		tree.add([]byte{byte(i)})
	}
	root := tree.root(0, 9)
	proof := tree.proof(3, 0, 9)

	if got, err := rootFromProof(4, 9, tree.leaves[3], proof); err == nil && string(got) == string(root) {
		t.Fatal("a proof verified against the wrong index")
	}

	tampered := make([][]byte, len(proof))
	copy(tampered, proof)
	altered := append([]byte(nil), tampered[0]...)
	altered[0] ^= 0xFF
	tampered[0] = altered

	if got, _ := rootFromProof(3, 9, tree.leaves[3], tampered); string(got) == string(root) {
		t.Fatal("an altered sibling still produced the log's root")
	}
	if _, err := rootFromProof(3, 9, tree.leaves[3], proof[:len(proof)-1]); err == nil {
		t.Fatal("a short proof was accepted")
	}
}

// ---------- against a stub log ----------

func testSTH(t *testing.T) *signer.STH {
	t.Helper()
	key, err := signer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var root hashchain.Hash
	copy(root[:], []byte("a root that is thirty-two bytes."))
	return key.Sign("01TESTRUN", 17, root, 1755400000000000000)
}

// stubLog answers like Rekor for one submitted entry, including a real
// inclusion proof over a small tree with the entry in it.
func stubLog(t *testing.T, treeSize, index int) *httptest.Server {
	t.Helper()

	var stored []byte
	mux := http.NewServeMux()

	respond := func(w http.ResponseWriter, uuid string, status int) {
		tree := &refTree{}
		for i := 0; i < treeSize; i++ {
			if i == index {
				tree.add(stored)
				continue
			}
			tree.add([]byte{byte(i), 0x5A})
		}
		proof := tree.proof(index, 0, treeSize)
		hashes := make([]string, 0, len(proof))
		for _, h := range proof {
			hashes = append(hashes, hex.EncodeToString(h))
		}

		out := map[string]any{uuid: map[string]any{
			"body":           base64.StdEncoding.EncodeToString(stored),
			"logIndex":       index,
			"logID":          "c0ffee",
			"integratedTime": 1755400001,
			"verification": map[string]any{
				"inclusionProof": map[string]any{
					"logIndex": index,
					"rootHash": hex.EncodeToString(tree.root(0, treeSize)),
					"treeSize": treeSize,
					"hashes":   hashes,
				},
			},
		}}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	}

	mux.HandleFunc("/api/v1/log/entries", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)

		// The log canonicalises what it stores: a rekord keeps the hash of the
		// content, never the content itself. Reproduced here because hark checks
		// the entry against the STH, and checking against the submitted form
		// would pass over a log that stored something else.
		var sub struct {
			Spec struct {
				Data struct {
					Content string `json:"content"`
				} `json:"data"`
				Signature struct {
					Content   string `json:"content"`
					PublicKey struct {
						Content string `json:"content"`
					} `json:"publicKey"`
				} `json:"signature"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(raw, &sub); err != nil {
			t.Errorf("submitted entry is not JSON: %v", err)
		}
		content, err := base64.StdEncoding.DecodeString(sub.Spec.Data.Content)
		if err != nil {
			t.Errorf("submitted content is not base64: %v", err)
		}
		if key, _ := base64.StdEncoding.DecodeString(sub.Spec.Signature.PublicKey.Content); !strings.Contains(string(key), "BEGIN PUBLIC KEY") {
			t.Errorf("the public key was not submitted as PEM: %q", key)
		}
		sum := sha256.Sum256(content)

		canonical, _ := json.Marshal(map[string]any{
			"apiVersion": "0.0.1",
			"kind":       "rekord",
			"spec": map[string]any{
				"data": map[string]any{
					"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(sum[:])},
				},
				"signature": map[string]any{
					"format":  "x509",
					"content": sub.Spec.Signature.Content,
				},
			},
		})
		stored = canonical
		respond(w, "24296fb24b8ad77a", http.StatusCreated)
	})

	mux.HandleFunc("/api/v1/log/entries/", func(w http.ResponseWriter, r *http.Request) {
		if stored == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		respond(w, strings.TrimPrefix(r.URL.Path, "/api/v1/log/entries/"), http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestAnchorAndVerifyInclusion(t *testing.T) {
	sth := testSTH(t)
	srv := stubLog(t, 12, 5)
	c := New(srv.URL)

	entry, err := c.Anchor(context.Background(), sth)
	if err != nil {
		t.Fatal(err)
	}
	if entry.UUID == "" || entry.LogIndex != 5 {
		t.Fatalf("entry came back as %+v", entry)
	}

	fetched, err := c.Fetch(context.Background(), entry.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fetched.Covers(sth); err != nil {
		t.Fatalf("the entry does not tie back to the tree head: %v", err)
	}
	if err := fetched.VerifyInclusion(); err != nil {
		t.Fatalf("inclusion did not verify: %v", err)
	}
	if fetched.Proof.TreeSize != 12 {
		t.Fatalf("tree size %d", fetched.Proof.TreeSize)
	}
}

// An entry that is in the log but covers a different tree head must be
// rejected: "the log holds entry X" and "entry X is this run" are two claims,
// and only checking the first would let a bundle name any entry at all.
func TestEntryMustCoverThisTreeHead(t *testing.T) {
	srv := stubLog(t, 8, 2)
	c := New(srv.URL)

	if _, err := c.Anchor(context.Background(), testSTH(t)); err != nil {
		t.Fatal(err)
	}
	entry, err := c.Fetch(context.Background(), "24296fb24b8ad77a")
	if err != nil {
		t.Fatal(err)
	}
	if err := entry.Covers(testSTH(t)); err == nil {
		t.Fatal("an entry for a different tree head was accepted")
	}
}

func TestFetchReportsAMissingEntryDistinctly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	if _, err := New(srv.URL).Fetch(context.Background(), "nope"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// A log that is down must not be able to invalidate a bundle, so the error has
// to be one the caller can tell apart from a rejection.
func TestAnchorFailureIsAnOrdinaryError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream unavailable")
	}))
	t.Cleanup(srv.Close)

	_, err := New(srv.URL).Anchor(context.Background(), testSTH(t))
	if err == nil {
		t.Fatal("a failed submission reported success")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("the error should carry what the log said: %v", err)
	}
}

func TestAnchorRefusesAnUnsignedBundle(t *testing.T) {
	if _, err := New("http://127.0.0.1:1").Anchor(context.Background(), nil); err == nil {
		t.Fatal("anchored nothing")
	}
}
