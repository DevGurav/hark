// Package reqkey derives the identity of an outbound request, so a replayed
// request can be matched to the response that was recorded for it.
//
// This is the piece replay stands on. Get it too loose and two different
// requests share a key, so replay serves the wrong response and reports success.
// Get it too tight and a request that is logically the same as the recorded one
// fails to match, and replay refuses a run that should have worked. The second
// failure is loud; the first is silent, which is why everything here errs toward
// distinguishing.
package reqkey

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/DevGurav/hark/internal/hashchain"
)

// Key identifies one request within a run.
type Key struct {
	// Hash is the canonical form's digest.
	Hash hashchain.Hash

	// Occurrence counts how many byte-identical requests came before this one.
	//
	// Without it a retry after a 429 -- the ordinary case, and one UrbanHeat's
	// llm.py produces on its own -- would be indistinguishable from the call it
	// repeats, and replay would serve the first response twice.
	Occurrence uint32
}

// String renders a key for diagnostics.
func (k Key) String() string {
	return hex(k.Hash[:6]) + "#" + itoa(int(k.Occurrence))
}

// Headers dropped before hashing.
//
// Two groups, for two different reasons. Hop-by-hop headers describe a single
// network hop rather than the request, and the mediator is a hop -- they are
// legitimately different on each side. The rest vary per request by nature, so
// including them would make every request unique and no replay would ever match.
var droppedHeaders = map[string]bool{
	// Hop-by-hop, RFC 7230 §6.1.
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,

	// Varies per request or per hop.
	"date":              true,
	"content-length":    true, // implied by the body, and re-derived on the way out
	"host":              true, // already hashed separately, and rewritten by the mediator
	"x-request-id":      true,
	"x-correlation-id":  true,
	"x-amzn-trace-id":   true,
	"traceparent":       true,
	"tracestate":        true,
	"b3":                true,
	"x-b3-traceid":      true,
	"x-b3-spanid":       true,
	"x-b3-parentspanid": true,
	"x-b3-sampled":      true,
}

// placeholderPattern matches the broker's tokens.
//
// A placeholder embeds the run id, so the same agent doing the same thing in a
// replayed run produces a different literal string. Normalising to a constant is
// what lets the two canonicalise identically -- otherwise every request carrying
// a credential would fail to match, which is most of them.
//
// The real credential never appears here: the mediator canonicalises the agent's
// request, and injection happens afterwards on a copy.
var placeholderPattern = regexp.MustCompile(`hark-placeholder-[0-9A-Za-z]+-[0-9A-Za-z_]+`)

const placeholderSentinel = "hark-placeholder-X"

// Canonicalise renders a request in a stable form.
//
// Every variable-length field is length-prefixed. Without that, a header pair
// like `a: bc` and one like `ab: c` would concatenate to the same bytes, and two
// genuinely different requests would share a key.
func Canonicalise(method, host, path string, h http.Header, body []byte) []byte {
	var b bytes.Buffer

	writeField(&b, strings.ToUpper(method))
	writeField(&b, strings.ToLower(host))
	writeField(&b, path)

	type pair struct{ name, value string }
	var pairs []pair
	for name, values := range h {
		lower := strings.ToLower(name)
		if droppedHeaders[lower] {
			continue
		}
		for _, v := range values {
			pairs = append(pairs, pair{lower, normalisePlaceholders(v)})
		}
	}
	// Sort by name then value, so a header repeated with several values lands in
	// a fixed order regardless of how the map was iterated.
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].name != pairs[j].name {
			return pairs[i].name < pairs[j].name
		}
		return pairs[i].value < pairs[j].value
	})

	writeCount(&b, len(pairs))
	for _, p := range pairs {
		writeField(&b, p.name)
		writeField(&b, p.value)
	}

	writeField(&b, string(canonicalBody(body)))
	return b.Bytes()
}

// Derive computes the key, advancing the occurrence counter for this canonical
// form. seen is per-run state and must be the same map for the whole run.
func Derive(canonical []byte, seen map[hashchain.Hash]uint32) Key {
	h := hashchain.Leaf(0, 0, canonical)
	n := seen[h]
	seen[h] = n + 1
	return Key{Hash: h, Occurrence: n}
}

// Peek computes the key without advancing the counter, for lookups during
// replay.
func Peek(canonical []byte, seen map[hashchain.Hash]uint32) Key {
	h := hashchain.Leaf(0, 0, canonical)
	return Key{Hash: h, Occurrence: seen[h]}
}

// canonicalBody re-serialises a JSON body with sorted keys, and passes anything
// else through untouched.
//
// JSON matters because the agent's serialiser is not required to be stable. Go
// sorts map keys; Python does not by default, and a dict built in a different
// order produces different bytes for the same request. Re-serialising removes
// that as a source of spurious mismatches.
//
// Numbers are decoded as json.Number so their original text survives. Decoding
// into float64 would turn 1 into 1e+00 and lose precision on large integers --
// changing the body of a request nobody asked us to rewrite.
func canonicalBody(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return normalisePlaceholderBytes(body)
	}
	// Trailing content means this was not a single JSON document; treat the whole
	// thing as opaque rather than silently keeping only the first value.
	if dec.More() {
		return normalisePlaceholderBytes(body)
	}

	out, err := json.Marshal(v) // encoding/json sorts map keys
	if err != nil {
		return normalisePlaceholderBytes(body)
	}
	return normalisePlaceholderBytes(out)
}

func normalisePlaceholders(s string) string {
	if !strings.Contains(s, "hark-placeholder-") {
		return s
	}
	return placeholderPattern.ReplaceAllString(s, placeholderSentinel)
}

func normalisePlaceholderBytes(b []byte) []byte {
	if !bytes.Contains(b, []byte("hark-placeholder-")) {
		return b
	}
	return placeholderPattern.ReplaceAll(b, []byte(placeholderSentinel))
}

func writeField(b *bytes.Buffer, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	b.Write(n[:])
	b.WriteString(s)
}

func writeCount(b *bytes.Buffer, n int) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(n))
	b.Write(buf[:])
}

const hexDigits = "0123456789abcdef"

func hex(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0F]
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
