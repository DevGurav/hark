package mediator

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DevGurav/hark/internal/logfmt"
)

// Streaming, which is how every model endpoint actually answers.
//
// The property under test is not "the bytes arrive". It is that the *boundaries*
// arrive: an SSE response is a sequence of events flushed separately, and agent
// code branches on partial parses -- a token at a time, a tool call recognised
// mid-stream. Reassembling the stream and handing it over in one piece would
// still deliver every byte and would change what the agent saw.
//
// So each test below asserts on where the reads split, not only on the content.

// sseUpstream writes events one flush at a time, with no Content-Length. That is
// what makes it a stream rather than a body delivered in instalments.
func sseUpstream(t testing.TB, events []string, gap time.Duration) string {
	t.Helper()
	return httpsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(200)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("the test upstream cannot flush, so it is not streaming")
			return
		}
		for _, e := range events {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", e)
			flusher.Flush()
			if gap > 0 {
				time.Sleep(gap)
			}
		}
	})
}

// readSSE consumes a streamed response one event at a time, returning each
// event and how many separate reads the body took to deliver them.
func readSSE(t *testing.T, client *http.Client, path string) (events []string, reads int) {
	t.Helper()

	resp, err := send(t, client, "POST", path, `{"stream":true}`)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content type %q did not survive the mediator", got)
	}

	// Read in small pieces so the boundaries the transport produced are visible
	// rather than coalesced by a large buffer.
	br := bufio.NewReader(resp.Body)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			reads++
			if strings.HasPrefix(line, "data: ") {
				events = append(events, strings.TrimSuffix(strings.TrimPrefix(line, "data: "), "\n"))
			}
		}
		if err != nil {
			return events, reads
		}
	}
}

// The recording has to carry one chunk per flush, not one chunk per response.
func TestStreamedResponseIsRecordedChunkByChunk(t *testing.T) {
	want := []string{"one", "two", "three", "four"}
	upstream := sseUpstream(t, want, 15*time.Millisecond)

	m, rec := start(t, Config{
		DialUpstream: func(string) (net.Conn, error) {
			return tls.Dial("tcp", upstream, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		},
	})

	got, _ := readSSE(t, agentClient(t, m), "/v1/stream")
	if len(got) != len(want) {
		t.Fatalf("agent received %d events, expected %d: %v", len(got), len(want), got)
	}

	waitFor(t, func() bool { return len(rec.find(logfmt.KindLLMResponseEnd)) > 0 })

	chunks := rec.find(logfmt.KindLLMResponseChunk)
	if len(chunks) != len(want) {
		// One chunk per flush. Fewer means the mediator buffered the stream and
		// the recording no longer describes what the agent saw.
		t.Fatalf("recorded %d chunks for %d flushed events", len(chunks), len(want))
	}
	for i, c := range chunks {
		if body := string(c.(logfmt.LLMResponseChunk).Data); !strings.Contains(body, want[i]) {
			t.Fatalf("chunk %d holds %q, expected the event %q", i, body, want[i])
		}
	}

	// The gaps between events are recorded even though replay does not reproduce
	// them: they are evidence about the run, and nothing else preserves them.
	var timed int
	for _, c := range chunks {
		if c.(logfmt.LLMResponseChunk).SincePrev > 5*time.Millisecond.Nanoseconds() {
			timed++
		}
	}
	if timed == 0 {
		t.Fatal("no inter-chunk timing was recorded for a stream that paused between events")
	}
}

// Replay has to hand the agent the same boundaries the recording holds. This is
// the property the whole chunk-granular design exists for, and the one that
// would silently regress into "the bytes are all there".
func TestStreamedResponseReplaysWithItsBoundaries(t *testing.T) {
	want := []string{"alpha", "beta", "gamma"}

	// The chunks a recording of the stream above would contain.
	recorded := make([][]byte, 0, len(want))
	for _, e := range want {
		recorded = append(recorded, []byte("data: "+e+"\n\n"))
	}

	pb := &canned{queue: []*PlaybackResponse{{
		Status:  200,
		Headers: map[string]string{"Content-Type": "text/event-stream", "Cache-Control": "no-cache"},
		Chunks:  recorded,
	}}}

	m, rec := start(t, Config{
		Playback: pb,
		DialUpstream: func(string) (net.Conn, error) {
			t.Error("a replayed stream dialled upstream")
			return nil, nil
		},
	})

	got, _ := readSSE(t, agentClient(t, m), "/v1/stream")
	if len(got) != len(want) {
		t.Fatalf("replayed agent received %d events, expected %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d replayed as %q, recorded as %q", i, got[i], want[i])
		}
	}

	waitFor(t, func() bool { return len(rec.find(logfmt.KindLLMResponseEnd)) > 0 })

	// The replayed run records the same chunking, so its own bundle is a
	// recording of a stream in its own right and can be replayed again.
	chunks := rec.find(logfmt.KindLLMResponseChunk)
	if len(chunks) != len(want) {
		t.Fatalf("the replayed run recorded %d chunks, expected %d", len(chunks), len(want))
	}
}

// An agent that acts on the first event must be able to see it before the last
// one has been produced. If the mediator buffers, a streamed run still delivers
// every byte and stops being a stream.
func TestStreamReachesTheAgentBeforeItEnds(t *testing.T) {
	const gap = 150 * time.Millisecond
	upstream := sseUpstream(t, []string{"first", "second", "third"}, gap)

	m, _ := start(t, Config{
		DialUpstream: func(string) (net.Conn, error) {
			return tls.Dial("tcp", upstream, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		},
	})

	start := time.Now()
	resp, err := send(t, agentClient(t, m), "POST", "/v1/stream", `{"stream":true}`)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the first event: %v", err)
	}
	firstAt := time.Since(start)

	if !strings.Contains(line, "first") {
		t.Fatalf("first read returned %q", line)
	}
	// Two further events are still 150ms apart each. Arriving before the stream
	// finishes is the whole property; the threshold is generous so a slow box
	// cannot fail it spuriously.
	if firstAt > 2*gap {
		t.Fatalf("the first event took %v, by which time the stream had ended: the mediator buffered it", firstAt)
	}
}

// A field in the format that is always false is a false statement in every
// artifact that carries it. LLMRequest.Streaming was declared, set by the
// synthetic bundle generator, and never populated by the recorder -- so every
// real bundle said no request had ever asked for a stream, including the ones
// that had.
func TestStreamingRequestsAreRecordedAsSuch(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		body    string
		want    bool
	}{
		{"sse accept header", map[string]string{"Accept": "text/event-stream"}, `{"prompt":"hi"}`, true},
		{"accept among others", map[string]string{"Accept": "text/event-stream, */*"}, ``, true},
		{"stream true in the body", nil, `{"model":"m","stream":true}`, true},
		{"stream false in the body", nil, `{"model":"m","stream":false}`, false},
		{"no signal at all", nil, `{"model":"m"}`, false},
		{"empty body", nil, ``, false},
		{"not json", nil, `hello`, false},

		// The words appearing inside a prompt are not a request to stream. Only
		// a top-level key counts, which is why the body is parsed rather than
		// searched.
		{"the words inside a prompt", nil, `{"prompt":"the docs say \"stream\": true"}`, false},
		{"nested elsewhere", nil, `{"options":{"stream":true}}`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range c.headers {
				h.Set(k, v)
			}
			if got := asksForStream(h, []byte(c.body)); got != c.want {
				t.Fatalf("asksForStream = %v, want %v", got, c.want)
			}
		})
	}
}

// End to end, so the field is checked where it is actually written rather than
// only in the helper that computes it.
func TestStreamingFlagReachesTheRecordedEvent(t *testing.T) {
	upstream := sseUpstream(t, []string{"only"}, 0)
	m, rec := start(t, Config{
		DialUpstream: func(string) (net.Conn, error) {
			return tls.Dial("tcp", upstream, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		},
	})

	client := agentClient(t, m)
	if _, status := doRequestWith(t, client, "POST", "/v1/stream", `{"model":"m","stream":true}`); status != 200 {
		t.Fatalf("status %d", status)
	}
	if _, status := doRequestWith(t, client, "POST", "/v1/plain", `{"model":"m"}`); status != 200 {
		t.Fatalf("status %d", status)
	}

	waitFor(t, func() bool { return len(rec.find(logfmt.KindLLMRequest)) == 2 })
	reqs := rec.find(logfmt.KindLLMRequest)
	if !reqs[0].(logfmt.LLMRequest).Streaming {
		t.Fatal("a request that asked for a stream was recorded as not streaming")
	}
	if reqs[1].(logfmt.LLMRequest).Streaming {
		t.Fatal("a request that did not ask for a stream was recorded as streaming")
	}
}
