package logfmt

// Kind identifies what a recorded event is. The numeric values are part of the
// on-disk format and are bound into every leaf hash, so they are frozen: new
// kinds get new numbers, existing numbers are never reused or renumbered.
type Kind uint8

const (
	KindInvalid Kind = 0

	// Run framing.
	KindRunStart     Kind = 1
	KindPolicyLoaded Kind = 2
	KindEnvSnapshot  Kind = 3
	KindFsManifest   Kind = 4

	// Model traffic. A response arrives as zero or more chunks followed by an
	// end marker, so that a streaming response replays with its original chunk
	// boundaries -- agent code frequently branches on partial parses, which
	// makes the boundaries themselves a source of nondeterminism.
	KindLLMRequest       Kind = 5
	KindLLMResponseChunk Kind = 6
	KindLLMResponseEnd   Kind = 7

	// Tool traffic, including MCP.
	KindToolCallRequest Kind = 8
	KindToolCallResult  Kind = 9

	// Containment. Every attempt to leave the namespace is recorded, whether it
	// was allowed or denied -- a denial is evidence, not an error to swallow.
	KindEgressAttempt  Kind = 10
	KindEgressDecision Kind = 11
	KindSecretInjected Kind = 12

	// Process-local nondeterminism captured by the language shim.
	KindClockRead  Kind = 13
	KindRandomRead Kind = 14

	// Checkpoint and termination.
	KindCheckpoint Kind = 15
	KindRunEnd     Kind = 16
)

var kindNames = map[Kind]string{
	KindRunStart:         "RunStart",
	KindPolicyLoaded:     "PolicyLoaded",
	KindEnvSnapshot:      "EnvSnapshot",
	KindFsManifest:       "FsManifest",
	KindLLMRequest:       "LlmRequest",
	KindLLMResponseChunk: "LlmResponseChunk",
	KindLLMResponseEnd:   "LlmResponseEnd",
	KindToolCallRequest:  "ToolCallRequest",
	KindToolCallResult:   "ToolCallResult",
	KindEgressAttempt:    "EgressAttempt",
	KindEgressDecision:   "EgressDecision",
	KindSecretInjected:   "SecretInjected",
	KindClockRead:        "ClockRead",
	KindRandomRead:       "RandomRead",
	KindCheckpoint:       "Checkpoint",
	KindRunEnd:           "RunEnd",
}

func (k Kind) String() string {
	if n, ok := kindNames[k]; ok {
		return n
	}
	return "Unknown"
}

// Valid reports whether k is a kind this build knows how to interpret.
//
// An unknown kind is not automatically a corrupt log: a newer recorder may have
// written events this binary predates. Verification stays possible regardless,
// because a leaf hash covers the opaque payload bytes and never needs them
// decoded. Replay, on the other hand, must refuse to proceed past a kind it
// cannot interpret rather than silently skipping it.
func (k Kind) Valid() bool {
	_, ok := kindNames[k]
	return ok
}
