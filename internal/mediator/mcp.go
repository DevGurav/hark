package mediator

import (
	"encoding/json"
)

// Recognising an MCP tool call inside ordinary HTTP traffic.
//
// The mediator does not run an MCP transport of its own. An MCP server reached
// over "streamable HTTP" is, at the wire, a host in the allowlist receiving
// ordinary POST requests -- so it is already recorded exactly as a model
// endpoint is, in full, with replay already proven for it. What is added here
// is a second, semantic layer on top of that transcript: when a request's body
// is JSON-RPC 2.0 naming "tools/call", the mediator additionally records
// ToolCallRequest and ToolCallResult events describing which tool was called
// with what arguments, and what came back.
//
// Additive rather than a replacement is the point. The LlmRequest/
// LlmResponseChunk/LlmResponseEnd events are what replay actually matches
// against, and that path is untouched -- a tool call that this parser fails to
// recognise, or a JSON-RPC framing this mediator does not understand, still
// replays correctly. The worst failure mode here is a run that reads slightly
// less helpfully in `hark inspect`, never one that fails to replay.

// jsonrpcRequest is the subset of JSON-RPC 2.0 this needs to recognise a tool
// call. Extra fields in the real message are simply not decoded into it.
type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

// parseToolCall reports whether body is an MCP tools/call request, and if so
// the tool name and its canonicalised arguments.
//
// "jsonrpc": "2.0" is required rather than assumed: without it, any POST body
// that happens to contain a "method" key of "tools/call" -- plausible for an
// unrelated API -- would be misread as a tool call.
func parseToolCall(body []byte) (tool string, arguments []byte, ok bool) {
	if len(body) == 0 || !json.Valid(body) {
		return "", nil, false
	}
	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", nil, false
	}
	if req.JSONRPC != "2.0" || req.Method != "tools/call" || req.Params.Name == "" {
		return "", nil, false
	}
	return req.Params.Name, canonicalJSON(req.Params.Arguments), true
}

// jsonrpcResponse is the subset needed to recognise a tool call's result.
type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// parseToolResult reports whether body is a JSON-RPC 2.0 response, and if so
// its result (or error) as canonical JSON.
//
// A response carries no method name to check against, unlike the request --
// JSON-RPC does not repeat it -- so this is only ever called once the request
// on the same exchange has already been recognised as a tool call. Matching
// the two by exchange id, rather than trying to re-derive "was this a tool
// response" from the response alone, is what keeps this from misreading an
// unrelated JSON-RPC-shaped reply.
func parseToolResult(body []byte) (result []byte, isError bool, ok bool) {
	if len(body) == 0 || !json.Valid(body) {
		return nil, false, false
	}
	var resp jsonrpcResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, false, false
	}
	if resp.JSONRPC != "2.0" {
		return nil, false, false
	}
	if len(resp.Error) > 0 {
		return canonicalJSON(resp.Error), true, true
	}
	if len(resp.Result) > 0 {
		return canonicalJSON(resp.Result), false, true
	}
	return nil, false, false
}

// canonicalJSON re-serialises with sorted map keys, for the same reason
// reqkey.canonicalBody does it: the agent's serialiser is not required to
// produce stable key order, and two logically identical calls should record
// identically. Anything that fails to decode is kept as-is rather than
// dropped -- a tool argument need not be an object at all.
func canonicalJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}
