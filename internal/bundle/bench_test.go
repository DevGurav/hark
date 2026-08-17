package bundle

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/signer"
)

// What a bundle costs to verify, to prove one event from, and to store.
//
//	go test ./internal/bundle -bench . -benchtime 10x -run '^$'
//
// The contrast the inclusion-proof numbers exist to show: proving one event
// happened costs a few hundred bytes and log2(N) hashes, against re-reading the
// whole log. Shipping the bundle to prove one line of it would also disclose
// the entire run to whoever you are trying to convince.

// benchScale is the event count the published figures use. Large enough that
// the log2 in the proof is visible; small enough that the fixture builds in a
// second or two.
const benchScale = 100_000

// buildScale writes a bundle of n events shaped like a real run: mostly
// response chunks, because that is what dominates in practice.
func buildScale(tb testing.TB, n int) string {
	tb.Helper()

	path := filepath.Join(tb.TempDir(), "scale.hark")
	w, err := Create(path, Header{RunID: "01BENCHRUN", Recorder: "hark bench"})
	if err != nil {
		tb.Fatal(err)
	}

	chunk := bytes.Repeat([]byte("x"), 512)
	for i := 0; i < n; i++ {
		var kind logfmt.Kind
		var payload any
		switch i % 10 {
		case 0:
			kind, payload = logfmt.KindLLMRequest, logfmt.LLMRequest{
				Host: "model.example", Method: "POST", Path: "/v1/complete",
				Body: []byte(`{"prompt":"summarise this page"}`), Exchange: uint64(i),
			}
		case 9:
			kind, payload = logfmt.KindLLMResponseEnd, logfmt.LLMResponseEnd{
				Status: 200, ChunkCount: 8, Exchange: uint64(i - 9),
			}
		default:
			kind, payload = logfmt.KindLLMResponseChunk, logfmt.LLMResponseChunk{
				Seq: uint32(i % 10), Data: chunk, SincePrev: 12_000_000, Exchange: uint64(i - i%10),
			}
		}
		if _, err := w.Append(kind, uint64(i)*1e6, payload); err != nil {
			tb.Fatal(err)
		}
	}

	key, err := signer.Generate()
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := w.Seal(key, 1755400000000000000, "", 0); err != nil {
		tb.Fatal(err)
	}
	return path
}

func BenchmarkVerifyAtScale(b *testing.B) {
	path := buildScale(b, benchScale)
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(info.Size())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := Verify(path)
		if err != nil {
			b.Fatal(err)
		}
		if res.Status != StatusSealed {
			b.Fatalf("status %s", res.Status)
		}
	}
}

func BenchmarkProveAtScale(b *testing.B) {
	path := buildScale(b, benchScale)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := Prove(path, uint64(benchScale/2)); err != nil {
			b.Fatal(err)
		}
	}
}

// The size figures, reported as a benchmark so they are produced by the same
// command as the timings. One iteration is enough: nothing here is timed.
func BenchmarkLogSize(b *testing.B) {
	const n = 1000
	path := buildScale(b, n)

	raw, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	var squeezed bytes.Buffer
	zw := gzip.NewWriter(&squeezed)
	if _, err := zw.Write(raw); err != nil {
		b.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		b.Fatal(err)
	}

	proof, _, _, err := Prove(path, n/2)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportMetric(float64(len(raw))/float64(n)*1000, "bytes/kevent")
	b.ReportMetric(float64(squeezed.Len())/float64(n)*1000, "gzipped-bytes/kevent")
	hashes := len(proof.Siblings) + len(proof.Left) + len(proof.Right)
	b.ReportMetric(float64(hashes), "proof-hashes")
	b.ReportMetric(float64(hashchain.Size*hashes), "proof-bytes")

	// gzip rather than zstd: adding a compression dependency to produce one
	// number is a poor trade, and the shape of the answer -- response chunks
	// dominate, and they compress well -- is the same either way. zstd would be
	// modestly better on both size and speed.
	b.Log(kindBreakdown(b, path))
}

// kindBreakdown reports how the bytes are distributed across event kinds.
// Response chunks dominate any real run, and showing that is more useful than a
// single total.
func kindBreakdown(tb testing.TB, path string) string {
	tb.Helper()

	r, err := Open(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer r.Close()

	bytesBy := map[logfmt.Kind]int{}
	countBy := map[logfmt.Kind]int{}
	total := 0
	for {
		f, err := r.Next()
		if err != nil {
			break
		}
		bytesBy[f.Kind] += len(f.Payload)
		countBy[f.Kind]++
		total += len(f.Payload)
	}

	kinds := make([]logfmt.Kind, 0, len(bytesBy))
	for k := range bytesBy {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return bytesBy[kinds[i]] > bytesBy[kinds[j]] })

	var out bytes.Buffer
	fmt.Fprintf(&out, "payload bytes by kind (%d total)", total)
	for _, k := range kinds {
		fmt.Fprintf(&out, "\n  %-18s %8d bytes  %5d events  %4.1f%%",
			k, bytesBy[k], countBy[k], 100*float64(bytesBy[k])/float64(total))
	}
	return out.String()
}
