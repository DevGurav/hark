package replay

import (
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/reqkey"
)

func canonFor(path, body string) []byte {
	return reqkey.Canonicalise("POST", "api.example.com", path,
		http.Header{"Content-Type": []string{"application/json"}}, []byte(body))
}

// writer builds a bundle from a list of events.
type ev struct {
	kind    logfmt.Kind
	payload any
}

func write(t *testing.T, events []ev) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run.hark")

	w, err := bundle.Create(path, bundle.Header{RunID: "01TESTRUN", CreatedAt: time.Now().UnixNano()})
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range events {
		if _, err := w.Append(e.kind, uint64(i), e.payload); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Seal(nil, time.Now().UnixNano(), "", 0); err != nil {
		t.Fatal(err)
	}
	return path
}

// request builds the event trio for one exchange.
func request(canonical []byte, occ uint32, exchange uint64, status int, chunks ...string) []ev {
	key := hashchain.Leaf(0, 0, canonical)
	out := []ev{{logfmt.KindLLMRequest, logfmt.LLMRequest{
		Host: "api.example.com", Method: "POST",
		RequestKey: key[:], Occurrence: occ, Exchange: exchange,
	}}}
	for i, c := range chunks {
		out = append(out, ev{logfmt.KindLLMResponseChunk, logfmt.LLMResponseChunk{
			Seq: uint32(i), Data: []byte(c), Exchange: exchange,
		}})
	}
	out = append(out, ev{logfmt.KindLLMResponseEnd, logfmt.LLMResponseEnd{
		Status: status, ChunkCount: uint32(len(chunks)), Exchange: exchange,
	}})
	return out
}

func TestLookupReturnsRecordedResponse(t *testing.T) {
	c := canonFor("/v1/models", `{"a":1}`)
	path := write(t, request(c, 0, 1, 200, "hello ", "world"))

	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Exchanges() != 1 {
		t.Fatalf("indexed %d exchanges, expected 1", s.Exchanges())
	}

	res, err := s.Lookup(c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 {
		t.Fatalf("status %d", res.Status)
	}
	if len(res.Chunks) != 2 || string(res.Chunks[0]) != "hello " || string(res.Chunks[1]) != "world" {
		t.Fatalf("chunk boundaries not preserved: %q", res.Chunks)
	}
}

// The reason exchange ids exist. Concurrent connections interleave their events
// in the log, so grouping by position would splice one response onto another's
// request.
func TestInterleavedExchangesAreSeparated(t *testing.T) {
	a := canonFor("/first", `{"n":1}`)
	b := canonFor("/second", `{"n":2}`)

	keyA := hashchain.Leaf(0, 0, a)
	keyB := hashchain.Leaf(0, 0, b)

	// Both requests, then chunks alternating, then both ends -- the shape two
	// concurrent connections actually produce.
	events := []ev{
		{logfmt.KindLLMRequest, logfmt.LLMRequest{RequestKey: keyA[:], Occurrence: 0, Exchange: 1}},
		{logfmt.KindLLMRequest, logfmt.LLMRequest{RequestKey: keyB[:], Occurrence: 0, Exchange: 2}},
		{logfmt.KindLLMResponseChunk, logfmt.LLMResponseChunk{Seq: 0, Data: []byte("AAA"), Exchange: 1}},
		{logfmt.KindLLMResponseChunk, logfmt.LLMResponseChunk{Seq: 0, Data: []byte("BBB"), Exchange: 2}},
		{logfmt.KindLLMResponseChunk, logfmt.LLMResponseChunk{Seq: 1, Data: []byte("aaa"), Exchange: 1}},
		{logfmt.KindLLMResponseEnd, logfmt.LLMResponseEnd{Status: 201, ChunkCount: 1, Exchange: 2}},
		{logfmt.KindLLMResponseEnd, logfmt.LLMResponseEnd{Status: 200, ChunkCount: 2, Exchange: 1}},
	}

	s, err := Load(write(t, events))
	if err != nil {
		t.Fatal(err)
	}

	resA, err := s.Lookup(a)
	if err != nil {
		t.Fatal(err)
	}
	if resA.Status != 200 || len(resA.Chunks) != 2 ||
		string(resA.Chunks[0]) != "AAA" || string(resA.Chunks[1]) != "aaa" {
		t.Fatalf("exchange A picked up the wrong events: %d %q", resA.Status, resA.Chunks)
	}

	resB, err := s.Lookup(b)
	if err != nil {
		t.Fatal(err)
	}
	if resB.Status != 201 || len(resB.Chunks) != 1 || string(resB.Chunks[0]) != "BBB" {
		t.Fatalf("exchange B picked up the wrong events: %d %q", resB.Status, resB.Chunks)
	}
}

// A retry after a 429 sends a byte-identical request and gets a different
// answer. Replay has to serve them in order.
func TestRetriesAreServedInOrder(t *testing.T) {
	c := canonFor("/v1/models", `{"a":1}`)

	var events []ev
	events = append(events, request(c, 0, 1, 429, "rate limited")...)
	events = append(events, request(c, 1, 2, 200, "ok")...)

	s, err := Load(write(t, events))
	if err != nil {
		t.Fatal(err)
	}

	first, err := s.Lookup(c)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != 429 {
		t.Fatalf("first lookup returned %d, expected the 429", first.Status)
	}

	second, err := s.Lookup(c)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != 200 {
		t.Fatalf("second lookup returned %d, expected the retry's 200", second.Status)
	}

	// And a third has nothing left to serve.
	if _, err := s.Lookup(c); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("a third lookup should have failed, got %v", err)
	}
}

// Refusing is the whole point. A replayer that guesses can report success while
// the agent saw an answer it never received.
func TestUnknownRequestFails(t *testing.T) {
	recorded := canonFor("/known", `{"a":1}`)
	s, err := Load(write(t, request(recorded, 0, 1, 200, "x")))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Lookup(canonFor("/unknown", `{"a":1}`)); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("an unrecorded request was served: %v", err)
	}
	// The error should say which request, so a divergence is actionable.
	_, err = s.Lookup(canonFor("/unknown", `{"a":1}`))
	if err == nil || len(err.Error()) < 20 {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// An exchange whose end marker never arrived is one the run was killed during.
// Serving it would hand the agent half an answer.
func TestUnterminatedExchangeIsNotServed(t *testing.T) {
	c := canonFor("/v1", `{"a":1}`)
	key := hashchain.Leaf(0, 0, c)

	events := []ev{
		{logfmt.KindLLMRequest, logfmt.LLMRequest{RequestKey: key[:], Exchange: 1}},
		{logfmt.KindLLMResponseChunk, logfmt.LLMResponseChunk{Seq: 0, Data: []byte("half"), Exchange: 1}},
		// no LLMResponseEnd
	}
	s, err := Load(write(t, events))
	if err != nil {
		t.Fatal(err)
	}
	if s.Exchanges() != 0 {
		t.Fatal("an unterminated exchange was indexed")
	}
	if _, err := s.Lookup(c); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("a half-recorded response was served: %v", err)
	}
}

func TestUnconsumedCounting(t *testing.T) {
	a := canonFor("/a", "{}")
	b := canonFor("/b", "{}")

	var events []ev
	events = append(events, request(a, 0, 1, 200, "x")...)
	events = append(events, request(b, 0, 2, 200, "y")...)

	s, err := Load(write(t, events))
	if err != nil {
		t.Fatal(err)
	}
	if s.Unconsumed() != 2 {
		t.Fatalf("expected 2 unconsumed, got %d", s.Unconsumed())
	}
	if _, err := s.Lookup(a); err != nil {
		t.Fatal(err)
	}
	if s.Unconsumed() != 1 {
		t.Fatalf("expected 1 unconsumed after one lookup, got %d", s.Unconsumed())
	}
}

func TestLoadCarriesRunIdentity(t *testing.T) {
	s, err := Load(write(t, request(canonFor("/v1", "{}"), 0, 1, 200, "x")))
	if err != nil {
		t.Fatal(err)
	}
	if s.RunID != "01TESTRUN" {
		t.Fatalf("run id %q", s.RunID)
	}
	if s.LeafCount == 0 || s.Root == (hashchain.Hash{}) {
		t.Fatal("the sealed root was not carried over")
	}
}

func TestLoadRejectsNonBundle(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.hark")); err == nil {
		t.Fatal("Load accepted a missing file")
	}
}
