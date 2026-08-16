package logfmt

import (
	"github.com/fxamacker/cbor/v2"
)

// Payload structs.
//
// Every field carries an explicit integer CBOR key. Integer keys keep frames
// small, but the real reason is stability: renaming a Go field can never change
// the bytes that were hashed, because the wire key is the number, not the name.
//
// Encoding uses CBOR Core Deterministic Encoding (RFC 8949 §4.2.1): shortest-form
// integers, definite-length containers, and map keys sorted by encoded bytes.
// Without a canonical form, two encoders that disagree about map ordering would
// produce different leaf hashes for identical events, and replay would report a
// divergence that never happened.

// RunStart opens every log and pins down the conditions the run began under.
type RunStart struct {
	RunID       string   `cbor:"1,keyasint"`
	StartedAt   int64    `cbor:"2,keyasint"` // Unix nanoseconds, wall clock
	Recorder    string   `cbor:"3,keyasint"` // hark version that wrote this bundle
	ArgvHash    []byte   `cbor:"4,keyasint"`
	PolicyHash  []byte   `cbor:"5,keyasint"`
	WorkingDir  string   `cbor:"6,keyasint"`
	ProviderSet []string `cbor:"7,keyasint"` // hosts the mediator was prepared to broker
}

// PolicyLoaded records the effective policy in full, not just its hash, so a
// bundle is self-describing: a reviewer can see what was allowed without also
// needing the policy file that was on disk at the time.
type PolicyLoaded struct {
	Source     string   `cbor:"1,keyasint"`
	AllowHosts []string `cbor:"2,keyasint"`
	ReadPaths  []string `cbor:"3,keyasint"`
	WritePaths []string `cbor:"4,keyasint"`
	Raw        []byte   `cbor:"5,keyasint"`
}

// EnvSnapshot captures the agent's environment. Values known to hold secrets are
// replaced by the broker placeholder before this event is written; the real
// value never enters the log.
type EnvSnapshot struct {
	Vars map[string]string `cbor:"1,keyasint"`
}

// FsManifest hashes the read-set the agent was granted at start.
//
// This is manifest-level rather than per-read fidelity: hark asserts that the
// files the agent could read had these contents when the run began, not that
// each individual read returned particular bytes. Per-read interception needs
// FUSE or an eBPF LSM and is deliberately out of scope for v0.1.
type FsManifest struct {
	Entries map[string][]byte `cbor:"1,keyasint"` // path -> BLAKE3 of contents
	Root    string            `cbor:"2,keyasint"`
}

// LLMRequest is the full outbound request as it crossed the boundary, after
// credential injection but with the credential itself redacted.
type LLMRequest struct {
	Host       string            `cbor:"1,keyasint"`
	Method     string            `cbor:"2,keyasint"`
	Path       string            `cbor:"3,keyasint"`
	Headers    map[string]string `cbor:"4,keyasint"`
	Body       []byte            `cbor:"5,keyasint"`
	RequestKey []byte            `cbor:"6,keyasint"` // canonical hash used to match on replay
	Occurrence uint32            `cbor:"7,keyasint"` // nth identical request in this run
	Streaming  bool              `cbor:"8,keyasint"`

	// Exchange ties this request to its response events.
	//
	// Concurrent connections interleave in the log -- the mediator gives the log
	// a total order over crossings, not one whole exchange at a time -- so
	// "collect chunks until the next end marker" would splice two responses
	// together. Every event of one request/response pair carries the same number.
	Exchange uint64 `cbor:"9,keyasint"`
}

// LLMResponseChunk is one piece of a response as it was received, with the delay
// since the previous chunk. Replay reproduces the framing; it does not by
// default reproduce the timing, because sleeping through a recorded four-minute
// run would defeat the point of replay being fast.
type LLMResponseChunk struct {
	Seq       uint32 `cbor:"1,keyasint"`
	Data      []byte `cbor:"2,keyasint"`
	SincePrev int64  `cbor:"3,keyasint"` // nanoseconds
	Exchange  uint64 `cbor:"4,keyasint"`
}

// LLMResponseEnd closes a response and carries its terminal status.
type LLMResponseEnd struct {
	Status     int               `cbor:"1,keyasint"`
	Headers    map[string]string `cbor:"2,keyasint"`
	ChunkCount uint32            `cbor:"3,keyasint"`
	Error      string            `cbor:"4,keyasint"` // transport-level failure, if any
	Exchange   uint64            `cbor:"5,keyasint"`
}

// ToolCallRequest and ToolCallResult cover MCP and any other JSON-RPC tool
// surface the mediator understands well enough to key semantically.
type ToolCallRequest struct {
	Server     string `cbor:"1,keyasint"`
	Tool       string `cbor:"2,keyasint"`
	Arguments  []byte `cbor:"3,keyasint"` // canonical JSON as sent
	RequestKey []byte `cbor:"4,keyasint"`
	Occurrence uint32 `cbor:"5,keyasint"`
}

type ToolCallResult struct {
	Server  string `cbor:"1,keyasint"`
	Tool    string `cbor:"2,keyasint"`
	Result  []byte `cbor:"3,keyasint"`
	IsError bool   `cbor:"4,keyasint"`
}

// DNSQuery records a name lookup. Written before the decision, for the same
// reason EgressAttempt is: the attempt survives a crash between the two.
//
// This is the earliest point at which a destination can be attributed. An agent
// that ignores every proxy convention still has to resolve a name, and the only
// resolver it can reach is the mediator.
type DNSQuery struct {
	Name  string `cbor:"1,keyasint"`
	Type  string `cbor:"2,keyasint"` // "A", "AAAA", or "TYPE<n>"
	RawTy uint16 `cbor:"3,keyasint"`
}

// DNSDecision is the verdict and the answer given.
//
// Allowed reflects what the policy says about the name. The answer is the
// mediator's own address either way -- refusing at the DNS layer would stop the
// agent connecting, and with it the chance to record a proper egress attempt
// carrying the host. See ADR-0006.
type DNSDecision struct {
	Name    string `cbor:"1,keyasint"`
	Allowed bool   `cbor:"2,keyasint"`
	Rule    string `cbor:"3,keyasint"`
	Answer  string `cbor:"4,keyasint"`
	Reason  string `cbor:"5,keyasint"`
}

// EgressAttempt records a connection the agent tried to open. It is written
// before the policy decision, so an attempt is on the record even if the process
// dies between attempt and decision.
type EgressAttempt struct {
	Host     string `cbor:"1,keyasint"`
	Port     int    `cbor:"2,keyasint"`
	Protocol string `cbor:"3,keyasint"`
	SNI      string `cbor:"4,keyasint"`
}

// EgressDecision is the verdict, and the rule that produced it.
type EgressDecision struct {
	Host    string `cbor:"1,keyasint"`
	Allowed bool   `cbor:"2,keyasint"`
	Rule    string `cbor:"3,keyasint"`
	Reason  string `cbor:"4,keyasint"`
}

// SecretInjected notes that a credential was substituted on the way out. It
// records which secret by reference only. The log is an artifact meant to be
// shared -- with a reviewer, an auditor, a public transparency log -- so it must
// never be the thing that leaks the key.
type SecretInjected struct {
	Ref         string `cbor:"1,keyasint"` // logical name, e.g. "gemini_api_key"
	Placeholder string `cbor:"2,keyasint"` // what the agent actually held
	Host        string `cbor:"3,keyasint"`
	ValueHash   []byte `cbor:"4,keyasint"` // BLAKE3 of the real value, for equality checks only
}

// ClockRead and RandomRead are produced by the in-process shim.
type ClockRead struct {
	Source string `cbor:"1,keyasint"` // "time.time", "time.monotonic", ...
	Value  int64  `cbor:"2,keyasint"` // nanoseconds
}

type RandomRead struct {
	Source string `cbor:"1,keyasint"` // "random.random", "os.urandom", "uuid4"
	Data   []byte `cbor:"2,keyasint"`
}

// Checkpoint marks a resumable position. The agent's own state is stored as a
// hash rather than a copy: hark does not want to own the agent's state format,
// and a hash is enough to detect that a fork diverged from where it claimed.
type Checkpoint struct {
	Label     string `cbor:"1,keyasint"`
	StateHash []byte `cbor:"2,keyasint"`
}

// RunEnd closes the log.
type RunEnd struct {
	EndedAt  int64  `cbor:"1,keyasint"`
	ExitCode int    `cbor:"2,keyasint"`
	Reason   string `cbor:"3,keyasint"` // "exit", "signal", "policy-abort"
}

// canonical is the shared deterministic CBOR encoder. Built once: constructing
// an EncMode is comparatively expensive and it is safe for concurrent use.
var canonical cbor.EncMode

func init() {
	em, err := cbor.EncOptions{
		Sort:          cbor.SortCanonical,
		ShortestFloat: cbor.ShortestFloat16,
		NaNConvert:    cbor.NaNConvert7e00,
		InfConvert:    cbor.InfConvertFloat16,
		IndefLength:   cbor.IndefLengthForbidden,
		TagsMd:        cbor.TagsForbidden,
	}.EncMode()
	if err != nil {
		// Static options; a failure here is a programming error, not a runtime
		// condition, and there is no sane way to continue without an encoder.
		panic("logfmt: canonical encoder: " + err.Error())
	}
	canonical = em
}

// Marshal encodes an event payload in canonical form.
func Marshal(v any) ([]byte, error) { return canonical.Marshal(v) }

// Unmarshal decodes an event payload.
func Unmarshal(b []byte, v any) error { return cbor.Unmarshal(b, v) }
