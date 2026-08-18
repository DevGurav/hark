package mediator

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/DevGurav/hark/internal/logfmt"
)

// An MCP server reached over streamable HTTP is, at the wire, just another
// allowed host receiving POST requests -- so it already goes through the same
// path proven for model traffic. These tests check the second, semantic layer:
// that a tools/call request and its result are additionally recognised and
// recorded as ToolCallRequest/ToolCallResult, correlated by exchange.

func TestParseToolCall(t *testing.T) {
	tool, args, ok := parseToolCall([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://example.com"}}}`))
	if !ok {
		t.Fatal("a well-formed tools/call was not recognised")
	}
	if tool != "fetch" {
		t.Fatalf("tool = %q", tool)
	}
	if !strings.Contains(string(args), `"url":"https://example.com"`) {
		t.Fatalf("arguments = %s", args)
	}

	cases := map[string][]byte{
		"missing jsonrpc":    []byte(`{"method":"tools/call","params":{"name":"fetch"}}`),
		"wrong version":      []byte(`{"jsonrpc":"1.0","method":"tools/call","params":{"name":"fetch"}}`),
		"different method":   []byte(`{"jsonrpc":"2.0","method":"tools/list"}`),
		"no tool name":       []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{}}`),
		"not json":           []byte(`not json at all`),
		"empty":              []byte(``),
		"unrelated api call": []byte(`{"model":"m","method":"tools/call"}`), // no jsonrpc key at all
	}
	for name, body := range cases {
		if _, _, ok := parseToolCall(body); ok {
			t.Fatalf("%s: recognised as a tool call", name)
		}
	}
}

func TestParseToolResult(t *testing.T) {
	result, isError, ok := parseToolResult([]byte(`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	if !ok || isError {
		t.Fatalf("ok=%v isError=%v", ok, isError)
	}
	if !strings.Contains(string(result), `"text":"ok"`) {
		t.Fatalf("result = %s", result)
	}

	_, isError, ok = parseToolResult([]byte(`{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"boom"}}`))
	if !ok || !isError {
		t.Fatalf("an error response was not recognised as one: ok=%v isError=%v", ok, isError)
	}

	if _, _, ok := parseToolResult([]byte(`{"status":"fine"}`)); ok {
		t.Fatal("a non-JSON-RPC body was accepted as a tool result")
	}
}

// The generic HTTP recording -- LlmRequest, chunks, LlmResponseEnd -- must be
// unaffected by any of this. That transcript is what replay actually matches
// against, and a tool call is additive on top of it.
func TestToolCallIsRecordedAlongsideTheOrdinaryTranscript(t *testing.T) {
	upstream := httpsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"tools/call"`) {
			t.Errorf("upstream did not receive the tool call: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"3 files"}]}}`)
	})

	m, rec := start(t, Config{
		DialUpstream: func(string) (net.Conn, error) {
			return tls.Dial("tcp", upstream, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		},
	})

	client := agentClient(t, m)
	body, status := doRequestWith(t, client, "POST", "/mcp",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_dir","arguments":{"path":"/tmp"}}}`)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if !strings.Contains(body, "3 files") {
		t.Fatalf("agent received %q", body)
	}

	waitFor(t, func() bool { return len(rec.find(logfmt.KindToolCallResult)) > 0 })

	// The ordinary transcript still exists and is unaffected.
	if len(rec.find(logfmt.KindLLMRequest)) != 1 {
		t.Fatal("the generic LlmRequest was not recorded alongside the semantic one")
	}
	if len(rec.find(logfmt.KindLLMResponseEnd)) != 1 {
		t.Fatal("the generic LlmResponseEnd was not recorded")
	}

	reqs := rec.find(logfmt.KindToolCallRequest)
	if len(reqs) != 1 {
		t.Fatalf("recorded %d ToolCallRequest events, expected 1", len(reqs))
	}
	req := reqs[0].(logfmt.ToolCallRequest)
	if req.Tool != "list_dir" || req.Server != allowedHost {
		t.Fatalf("unexpected request event: %+v", req)
	}
	if !strings.Contains(string(req.Arguments), `"path":"/tmp"`) {
		t.Fatalf("arguments not recorded: %s", req.Arguments)
	}

	res := rec.find(logfmt.KindToolCallResult)[0].(logfmt.ToolCallResult)
	if res.IsError {
		t.Fatal("a successful call was recorded as an error")
	}
	if !strings.Contains(string(res.Result), "3 files") {
		t.Fatalf("result not recorded: %s", res.Result)
	}

	// The two correlate, the same way LlmRequest/LlmResponseEnd do.
	if req.Exchange == 0 || req.Exchange != res.Exchange {
		t.Fatalf("exchange ids do not correlate: request %d, result %d", req.Exchange, res.Exchange)
	}
}

// An unrecognised request -- ordinary model traffic -- must record nothing
// extra. The semantic layer is additive only where it applies.
func TestOrdinaryTrafficRecordsNoToolCallEvents(t *testing.T) {
	upstream := httpsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "hello")
	})
	m, rec := start(t, Config{
		DialUpstream: func(string) (net.Conn, error) {
			return tls.Dial("tcp", upstream, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		},
	})

	if _, status := doRequest(t, m, "POST", "/v1/models", `{"prompt":"hi"}`); status != 200 {
		t.Fatalf("status %d", status)
	}
	waitFor(t, func() bool { return len(rec.find(logfmt.KindLLMResponseEnd)) > 0 })

	if got := len(rec.find(logfmt.KindToolCallRequest)); got != 0 {
		t.Fatalf("recorded %d ToolCallRequest events for a non-tool-call request", got)
	}
	if got := len(rec.find(logfmt.KindToolCallResult)); got != 0 {
		t.Fatalf("recorded %d ToolCallResult events", got)
	}
}

// Replaying a recorded tool call must reproduce both layers: the agent gets
// the recorded JSON-RPC result back, and the replayed run records its own
// ToolCallRequest/Result correlated the same way.
func TestToolCallReplaysWithBothLayers(t *testing.T) {
	resultBody := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"recorded"}]}}`
	pb := &canned{queue: []*PlaybackResponse{{
		Status:  200,
		Headers: map[string]string{"Content-Type": "application/json"},
		Chunks:  [][]byte{[]byte(resultBody)},
	}}}

	var dialled bool
	m, rec := start(t, Config{
		Playback: pb,
		DialUpstream: func(string) (net.Conn, error) {
			dialled = true
			return nil, nil
		},
	})

	body, status := doRequest(t, m, "POST", "/mcp",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_dir","arguments":{}}}`)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if !strings.Contains(body, "recorded") {
		t.Fatalf("agent received %q", body)
	}
	if dialled {
		t.Fatal("a replayed tool call dialled upstream")
	}

	waitFor(t, func() bool { return len(rec.find(logfmt.KindToolCallResult)) > 0 })

	req := rec.find(logfmt.KindToolCallRequest)[0].(logfmt.ToolCallRequest)
	res := rec.find(logfmt.KindToolCallResult)[0].(logfmt.ToolCallResult)
	if req.Exchange != res.Exchange {
		t.Fatal("replayed tool call events do not correlate")
	}
	if !strings.Contains(string(res.Result), "recorded") {
		t.Fatalf("replayed result not recorded: %s", res.Result)
	}
}

func TestCanonicalJSONSortsKeysAndPassesThroughNonJSON(t *testing.T) {
	got := canonicalJSON(json.RawMessage(`{"b":1,"a":2}`))
	if string(got) != `{"a":2,"b":1}` {
		t.Fatalf("got %s", got)
	}
	if got := canonicalJSON(nil); got != nil {
		t.Fatalf("nil input produced %v", got)
	}
}
