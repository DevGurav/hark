package mediator

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DevGurav/hark/internal/logfmt"
)

// What mediation costs, measured against a local stub.
//
// Against a live endpoint this measurement would be meaningless: upstream
// latency varies by orders of magnitude with load and would swamp the thing
// being measured. The stub answers immediately, so what is left is the
// mediator -- two TLS terminations, the canonicalisation, the policy check and
// the recording.
//
// Percentiles rather than a mean. A mean latency for a proxy hides exactly the
// behaviour that matters, which is the tail.
//
//	go test ./internal/mediator -bench Call -benchtime 10s -run '^$'
//
// Read the delta between the two, never either number alone. The absolute
// figures are dominated by whatever the machine's TLS handshake costs.
//
// Run it on Linux. Go's monotonic clock on Windows advances in millisecond
// steps, so anything faster than that reads as zero and the percentiles are
// noise -- a p50 of 0 against a mean of 100µs is the signature.

const benchBody = `{"contents":[{"parts":[{"text":"summarise this"}]}],"generationConfig":{"temperature":0}}`

func BenchmarkDirectCall(b *testing.B) {
	upstream := httpsUpstream(b, stubHandler)

	// The same client shape as the mediated case -- one keep-alive TLS
	// connection to a local stub -- so the difference between the two
	// benchmarks is the mediator and nothing else.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}},
		},
		Timeout: 20 * time.Second,
	}

	measure(b, func() {
		req, err := http.NewRequest("POST", "https://"+upstream+"/v1/models", strings.NewReader(benchBody))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	})
}

func BenchmarkMediatedCall(b *testing.B) {
	upstream := httpsUpstream(b, stubHandler)

	m, _ := start(b, Config{
		Recorder: discard{},
		DialUpstream: func(string) (net.Conn, error) {
			return tls.Dial("tcp", upstream, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		},
	})
	client := agentClient(b, m)

	measure(b, func() {
		if _, status := doRequestB(b, client, "POST", "/v1/models", benchBody); status != 200 {
			b.Fatalf("status %d", status)
		}
	})
}

// A replayed call, for the third figure the README quotes: playback serves the
// recording and never dials, so this is the mediator's cost with the network
// taken out entirely.
func BenchmarkPlaybackCall(b *testing.B) {
	pb := &always{res: &PlaybackResponse{
		Status:  200,
		Headers: map[string]string{"Content-Type": "application/json"},
		Chunks:  [][]byte{[]byte(`{"candidates":[{"content":"recorded"}]}`)},
	}}

	m, _ := start(b, Config{
		Recorder: discard{},
		Playback: pb,
		DialUpstream: func(string) (net.Conn, error) {
			b.Fatal("playback dialled upstream")
			return nil, nil
		},
	})
	client := agentClient(b, m)

	measure(b, func() {
		if _, status := doRequestB(b, client, "POST", "/v1/models", benchBody); status != 200 {
			b.Fatalf("status %d", status)
		}
	})
}

// measure runs the operation b.N times and reports the median and the 99th
// percentile alongside Go's own mean.
func measure(b *testing.B, op func()) {
	b.Helper()

	// One outside the timer, so a first-call cost -- certificate generation,
	// connection setup -- is not counted in every percentile.
	op()

	samples := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		op()
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	b.ReportMetric(float64(percentile(samples, 50).Microseconds()), "p50-us")
	b.ReportMetric(float64(percentile(samples, 99).Microseconds()), "p99-us")
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := (len(sorted)*p + 99) / 100
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func stubHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = io.WriteString(w, `{"candidates":[{"content":"stub"}]}`)
}

// discard is a Recorder that keeps nothing. The benchmark measures mediation,
// not how fast a slice grows.
type discard struct{}

func (discard) Append(kind logfmt.Kind, payload any) (uint64, error) { return 0, nil }
func (discard) Sync() error                                          { return nil }

// always serves the same recorded response to every request.
type always struct{ res *PlaybackResponse }

func (a *always) Lookup([]byte) (*PlaybackResponse, error) { return a.res, nil }

func doRequestB(b *testing.B, client *http.Client, method, path, body string) (string, int) {
	b.Helper()
	resp, err := send(b, client, method, path, body)
	if err != nil {
		b.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out), resp.StatusCode
}
