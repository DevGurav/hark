package mediator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DevGurav/hark/internal/logfmt"
)

// canned is a Playback that serves a queue of responses in order.
//
// Deliberately not keyed on the canonical form. Matching a live request to a
// recorded one is exercised properly in internal/replay, against forms produced
// by the same canonicaliser; reproducing it here would mean predicting every
// header Go's http.Client adds -- User-Agent, Accept-Encoding -- which tests
// nothing about the mediator and breaks whenever the standard library changes.
//
// What these tests are for is the plumbing: that playback dials nothing, that
// chunk boundaries survive, that the replayed run records its own correlated
// events, and that a miss fails loudly.
type canned struct {
	queue     []*PlaybackResponse
	lookups   int
	canonSeen [][]byte
}

func (c *canned) Lookup(canonical []byte) (*PlaybackResponse, error) {
	c.canonSeen = append(c.canonSeen, canonical)
	if c.lookups >= len(c.queue) {
		c.lookups++
		return nil, errors.New("no recorded response for this request")
	}
	res := c.queue[c.lookups]
	c.lookups++
	return res, nil
}

// A replayed run must open no outbound connection at all. The dialer here fails
// unconditionally, so if playback ever fell through to the live path the test
// would fail rather than quietly succeed against a real endpoint.
func TestPlaybackServesRecordedResponseWithoutDialling(t *testing.T) {
	pb := &canned{queue: []*PlaybackResponse{{
		Status:  200,
		Headers: map[string]string{"Content-Type": "text/plain"},
		Chunks:  [][]byte{[]byte("recorded "), []byte("answer")},
	}}}

	var dialled bool
	m, rec := start(t, Config{
		Playback: pb,
		DialUpstream: func(string) (net.Conn, error) {
			dialled = true
			return nil, errors.New("playback must not dial upstream")
		},
	})

	body, status := doRequest(t, m, "POST", "/v1/models", `{"a":1}`)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if body != "recorded answer" {
		t.Fatalf("agent received %q, expected the recorded response", body)
	}
	if dialled {
		t.Fatal("playback dialled upstream")
	}
	if len(pb.canonSeen) == 0 || len(pb.canonSeen[0]) == 0 {
		t.Fatal("playback was asked for a response without a canonical form")
	}

	waitFor(t, func() bool { return len(rec.find(logfmt.KindLLMResponseEnd)) > 0 })

	// The replayed run records its own events, and they carry matching exchange
	// ids so the new bundle is itself replayable.
	req := rec.find(logfmt.KindLLMRequest)[0].(logfmt.LLMRequest)
	end := rec.find(logfmt.KindLLMResponseEnd)[0].(logfmt.LLMResponseEnd)
	if req.Exchange == 0 || req.Exchange != end.Exchange {
		t.Fatalf("exchange ids do not correlate: request %d, end %d", req.Exchange, end.Exchange)
	}

	// Chunk boundaries are reproduced, not reassembled. Agent code branches on
	// partial parses, so the framing is part of what was recorded.
	chunks := rec.find(logfmt.KindLLMResponseChunk)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	if string(chunks[0].(logfmt.LLMResponseChunk).Data) != "recorded " {
		t.Fatalf("chunk boundaries were not preserved: %q", chunks[0])
	}
}

// A request the recording does not contain must fail the replay rather than be
// answered with something approximate.
func TestPlaybackRefusesUnknownRequest(t *testing.T) {
	pb := &canned{} // nothing recorded

	m, rec := start(t, Config{
		Playback:     pb,
		DialUpstream: func(string) (net.Conn, error) { return nil, errors.New("must not dial") },
	})

	// The connection is dropped, so the client sees a failure rather than a
	// fabricated answer.
	_, _ = doRequestAllowingError(t, m, "POST", "/never-recorded", `{"a":1}`)

	waitFor(t, func() bool { return len(rec.find(logfmt.KindLLMResponseEnd)) > 0 })

	end := rec.find(logfmt.KindLLMResponseEnd)[0].(logfmt.LLMResponseEnd)
	if end.Error == "" {
		t.Fatal("the divergence was not recorded")
	}
	if !strings.Contains(end.Error, "no recorded response") {
		t.Fatalf("the recorded error should name the problem: %q", end.Error)
	}
}

// doRequest drives one request through the mediator as a client trusting the
// run's CA, and returns the body and status.
func doRequest(t *testing.T, m *Mediator, method, path, body string) (string, int) {
	t.Helper()
	resp, err := doRequestAllowingError(t, m, method, path, body)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out), resp.StatusCode
}

func doRequestAllowingError(t *testing.T, m *Mediator, method, path, body string) (*http.Response, error) {
	t.Helper()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(m.CACertPEM()) {
		t.Fatal("could not trust the mediator CA")
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return tls.Dial("tcp", m.TLSAddr().String(), &tls.Config{
					ServerName: allowedHost, RootCAs: pool, NextProtos: []string{"http/1.1"},
				})
			},
		},
		Timeout: 20 * time.Second,
	}

	req, err := http.NewRequest(method, "https://"+allowedHost+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}
