package reqkey

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/DevGurav/hark/internal/hashchain"
)

func canon(h http.Header, body string) []byte {
	return Canonicalise("POST", "api.example.com", "/v1/models", h, []byte(body))
}

// The property replay depends on: the same logical request must canonicalise
// identically no matter how the header map happened to be built or iterated.
//
// Go randomises map iteration deliberately, so running this many times is what
// actually exercises the ordering, not the single construction.
func TestCanonicalisationIsStable(t *testing.T) {
	build := func() http.Header {
		h := http.Header{}
		h.Set("Content-Type", "application/json")
		h.Set("X-Goog-Api-Key", "hark-placeholder-01RUN-api_key")
		h.Set("Accept", "application/json")
		h.Set("User-Agent", "hark-test/1.0")
		h.Add("X-Multi", "b")
		h.Add("X-Multi", "a")
		return h
	}

	first := canon(build(), `{"b":2,"a":1}`)
	for i := 0; i < 1000; i++ {
		if got := canon(build(), `{"b":2,"a":1}`); !bytes.Equal(first, got) {
			t.Fatalf("canonical form varied between constructions on iteration %d", i)
		}
	}
}

// Length prefixing exists so header pairs cannot be shifted into each other.
// Without it `a: bc` and `ab: c` concatenate to the same bytes.
func TestHeaderBoundariesAreUnambiguous(t *testing.T) {
	a := http.Header{"A": []string{"bc"}}
	b := http.Header{"Ab": []string{"c"}}
	if bytes.Equal(canon(a, ""), canon(b, "")) {
		t.Fatal("two different header sets produced the same canonical form")
	}
}

func TestMethodHostPathAreDistinguished(t *testing.T) {
	h := http.Header{}
	base := Canonicalise("POST", "api.example.com", "/v1/models", h, nil)

	for name, got := range map[string][]byte{
		"method": Canonicalise("GET", "api.example.com", "/v1/models", h, nil),
		"host":   Canonicalise("POST", "other.example.com", "/v1/models", h, nil),
		"path":   Canonicalise("POST", "api.example.com", "/v1/other", h, nil),
	} {
		if bytes.Equal(base, got) {
			t.Fatalf("changing the %s did not change the canonical form", name)
		}
	}
}

// A placeholder embeds the run id, so a replayed run produces a different
// literal. Normalising is what lets the two match; without it every request
// carrying a credential would fail to replay.
func TestPlaceholdersNormaliseAcrossRuns(t *testing.T) {
	recorded := http.Header{"X-Api-Key": []string{"hark-placeholder-01RUNAAA-api_key"}}
	replayed := http.Header{"X-Api-Key": []string{"hark-placeholder-01RUNBBB-api_key"}}

	if !bytes.Equal(canon(recorded, ""), canon(replayed, "")) {
		t.Fatal("the same request from two runs did not canonicalise identically")
	}

	// In the body too, which is where several providers put the key.
	rb := canon(http.Header{}, `{"key":"hark-placeholder-01RUNAAA-api_key"}`)
	pb := canon(http.Header{}, `{"key":"hark-placeholder-01RUNBBB-api_key"}`)
	if !bytes.Equal(rb, pb) {
		t.Fatal("placeholders in the body did not normalise")
	}

	// But two *different* secrets must stay distinguishable.
	one := canon(http.Header{"X-Api-Key": []string{"hark-placeholder-01RUN-api_key"}}, "")
	two := canon(http.Header{"X-Api-Key": []string{"real-value-not-a-placeholder"}}, "")
	if bytes.Equal(one, two) {
		t.Fatal("a placeholder and a literal value collapsed together")
	}
}

// Hop-by-hop headers describe a single network hop, and the mediator is one, so
// they legitimately differ on each side. Per-request headers would make every
// request unique and nothing would ever match.
func TestVolatileHeadersAreIgnored(t *testing.T) {
	bare := http.Header{"Content-Type": []string{"application/json"}}

	noisy := http.Header{"Content-Type": []string{"application/json"}}
	noisy.Set("Date", "Mon, 16 Aug 2026 12:00:00 GMT")
	noisy.Set("Connection", "keep-alive")
	noisy.Set("X-Request-Id", "abc-123")
	noisy.Set("Traceparent", "00-trace-span-01")
	noisy.Set("Content-Length", "42")
	noisy.Set("Host", "api.example.com")
	noisy.Set("Transfer-Encoding", "chunked")

	if !bytes.Equal(canon(bare, ""), canon(noisy, "")) {
		t.Fatal("a volatile header changed the canonical form")
	}
}

// A header that genuinely identifies the request must still count.
func TestMeaningfulHeadersAreKept(t *testing.T) {
	a := http.Header{"Content-Type": []string{"application/json"}}
	b := http.Header{"Content-Type": []string{"text/plain"}}
	if bytes.Equal(canon(a, ""), canon(b, "")) {
		t.Fatal("Content-Type was ignored")
	}
}

// Python does not sort dict keys on serialisation, so the same request can
// arrive with its JSON in a different order. Re-serialising removes that as a
// source of spurious mismatches.
func TestJSONKeyOrderDoesNotMatter(t *testing.T) {
	a := canon(http.Header{}, `{"model":"x","contents":[{"role":"user"}],"temp":0}`)
	b := canon(http.Header{}, `{"temp":0,"contents":[{"role":"user"}],"model":"x"}`)
	if !bytes.Equal(a, b) {
		t.Fatal("JSON key order changed the canonical form")
	}

	// Different values must still differ.
	c := canon(http.Header{}, `{"model":"y","contents":[{"role":"user"}],"temp":0}`)
	if bytes.Equal(a, c) {
		t.Fatal("a different JSON value produced the same canonical form")
	}
}

// Array order is meaningful in JSON and must not be normalised away -- the
// message list of a model request is an array.
func TestJSONArrayOrderIsPreserved(t *testing.T) {
	a := canon(http.Header{}, `{"messages":["first","second"]}`)
	b := canon(http.Header{}, `{"messages":["second","first"]}`)
	if bytes.Equal(a, b) {
		t.Fatal("array order was normalised away")
	}
}

// Numbers keep their original text. Decoding into float64 would rewrite 1 as
// 1e+00 and lose precision on large integers -- changing a request nobody asked
// us to rewrite.
func TestNumbersKeepTheirForm(t *testing.T) {
	big := canon(http.Header{}, `{"n":12345678901234567890}`)
	if !bytes.Contains(big, []byte("12345678901234567890")) {
		t.Fatalf("a large integer was rewritten: %s", big)
	}
	if bytes.Contains(canon(http.Header{}, `{"n":1}`), []byte("1e+00")) {
		t.Fatal("an integer was rewritten in exponential form")
	}
}

func TestNonJSONBodyIsOpaque(t *testing.T) {
	a := canon(http.Header{}, "not json at all")
	b := canon(http.Header{}, "not json either")
	if bytes.Equal(a, b) {
		t.Fatal("two different opaque bodies collided")
	}
	// Invalid JSON must not be silently reordered or truncated.
	if !bytes.Contains(canon(http.Header{}, `{"a":1} trailing`), []byte("trailing")) {
		t.Fatal("content after a JSON document was dropped")
	}
}

func TestEmptyBody(t *testing.T) {
	if !bytes.Equal(canon(http.Header{}, ""), canon(http.Header{}, "")) {
		t.Fatal("empty bodies are not stable")
	}
	if bytes.Equal(canon(http.Header{}, ""), canon(http.Header{}, "x")) {
		t.Fatal("an empty body matched a non-empty one")
	}
}

// The case a retry produces: identical requests, different responses. Replay has
// to serve them in order.
func TestOccurrenceCounting(t *testing.T) {
	seen := make(map[hashchain.Hash]uint32)
	c := canon(http.Header{}, `{"a":1}`)

	for i := uint32(0); i < 4; i++ {
		if got := Derive(c, seen).Occurrence; got != i {
			t.Fatalf("occurrence %d, expected %d", got, i)
		}
	}

	other := canon(http.Header{}, `{"a":2}`)
	if got := Derive(other, seen).Occurrence; got != 0 {
		t.Fatalf("a different request shared the counter: %d", got)
	}
}

// Peek is what replay uses to look a request up, so it must not consume.
func TestPeekDoesNotAdvance(t *testing.T) {
	seen := make(map[hashchain.Hash]uint32)
	c := canon(http.Header{}, `{"a":1}`)

	if Peek(c, seen).Occurrence != 0 || Peek(c, seen).Occurrence != 0 {
		t.Fatal("Peek advanced the counter")
	}
	Derive(c, seen)
	if Peek(c, seen).Occurrence != 1 {
		t.Fatal("Peek did not see the advance")
	}
}

func TestKeyString(t *testing.T) {
	seen := make(map[hashchain.Hash]uint32)
	k := Derive(canon(http.Header{}, ""), seen)
	if len(k.String()) == 0 || !bytes.Contains([]byte(k.String()), []byte("#0")) {
		t.Fatalf("unhelpful key rendering: %q", k.String())
	}
}

// Arbitrary input must not panic: bodies come from the agent.
func FuzzCanonicalise(f *testing.F) {
	f.Add("POST", "api.example.com", "/v1", `{"a":1}`)
	f.Add("GET", "h", "/", "")
	f.Add("", "", "", "{")

	f.Fuzz(func(t *testing.T, method, host, path, body string) {
		h := http.Header{"Content-Type": []string{"application/json"}}
		a := Canonicalise(method, host, path, h, []byte(body))
		b := Canonicalise(method, host, path, h, []byte(body))
		if !bytes.Equal(a, b) {
			t.Fatal("canonicalisation is not deterministic")
		}
	})
}
