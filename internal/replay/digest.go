package replay

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/logfmt"
)

// The replay digest: what "REPLAY-EQUAL" actually compares.
//
// It is not the Merkle root. Two runs of the same agent cannot produce the same
// root and never could -- a run id is fresh per run, wall-clock and monotonic
// timestamps differ, and a credential placeholder embeds the run id. Comparing
// roots would report a divergence on every replay, including a perfect one.
//
// So the comparison is over the *actions*, with the fields that are volatile by
// construction removed. The claim replay makes is precisely this and no more:
//
//	Given the same recorded external inputs, the agent produced the same
//	sequence of externally-visible actions.
//
// Anything excluded here is a thing the digest does not check, which is why the
// exclusions are individually justified rather than convenient.

// digestVolatile lists what is zeroed before hashing, and why:
//
//	RunStart.RunID, StartedAt, Recorder  fresh per run by definition
//	RunEnd.EndedAt                       wall clock
//	LLMResponseChunk.SincePrev           replay does not reproduce timing
//	ClockRead.Value                      the value is served back verbatim, and
//	                                     the log stores a lossy nanosecond
//	                                     rendering of it
//	placeholder tokens                   embed the run id
//
// Everything else participates. In particular the response bodies, the policy
// decisions, the hosts, the ordering and the exit code all do.
var placeholderPattern = regexp.MustCompile(`hark-placeholder-[0-9A-Za-z]+-[0-9A-Za-z_]+`)

const placeholderSentinel = "hark-placeholder-X"

// Digest is one run reduced to its comparable actions.
type Digest struct {
	// Root is the running hash over every normalised action.
	Root hashchain.Hash

	// Steps is one entry per event, so two digests can be compared to find the
	// first point at which they diverged. Reporting where a run diverged is what
	// makes a failed replay actionable rather than just a red result.
	Steps []Step
}

// Step is one normalised action.
type Step struct {
	Seq  uint64
	Kind logfmt.Kind
	Hash hashchain.Hash

	// Summary is a short human-readable rendering, used when reporting a
	// divergence. Two hashes tell you that something differs; these tell you
	// what.
	Summary string
}

// Compute reads a bundle and reduces it to its comparable actions.
func Compute(path string) (*Digest, error) {
	r, err := bundle.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	d := &Digest{}
	var acc Accumulator
	for {
		f, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			break // truncated: compare what survived
		}
		if err != nil {
			return nil, err
		}

		step, include := acc.Add(f.Kind, f.Payload)
		if !include {
			continue
		}
		step.Seq = f.Seq
		d.Root = step.Hash
		d.Steps = append(d.Steps, step)
	}
	return d, nil
}

// Accumulator folds normalised actions into a running digest.
//
// Compute needs a finished bundle; a fork needs the same arithmetic applied to a
// run that is still happening, so that it can abort the moment its prefix stops
// matching the recording rather than discovering it afterwards. Both go through
// here, which is what stops the two from drifting apart -- a second
// implementation of "what counts as the same action" would eventually disagree
// with this one, and the way that shows up is a fork claiming a verified prefix
// it never had.
type Accumulator struct {
	root hashchain.Hash
	n    uint64
}

// Add folds one event in and returns the step it produced. The bool reports
// whether the event participates at all; a step is returned only when it does.
//
// Seq is left zero: the caller knows the sequence number, and the accumulator
// deliberately indexes by action position rather than by it.
func (a *Accumulator) Add(kind logfmt.Kind, payload []byte) (Step, bool) {
	normalised, summary, include := normalise(kind, payload)
	if !include {
		return Step{}, false
	}
	leaf := hashchain.Leaf(a.n, uint8(kind), normalised)
	a.root = hashchain.Chain(a.root, leaf)
	a.n++
	return Step{Kind: kind, Hash: a.root, Summary: summary}, true
}

// Actions reports how many actions have been folded in.
func (a *Accumulator) Actions() uint64 { return a.n }

// Root is the running digest over everything added so far.
func (a *Accumulator) Root() hashchain.Hash { return a.root }

// normalise strips the volatile fields from one event and re-encodes it.
//
// The returned bool reports whether the event participates at all.
func normalise(kind logfmt.Kind, payload []byte) ([]byte, string, bool) {
	switch kind {
	case logfmt.KindRunStart:
		var v logfmt.RunStart
		if logfmt.Unmarshal(payload, &v) != nil {
			return payload, "unreadable RunStart", true
		}
		// The identity of the run is not part of what the run did.
		v.RunID, v.StartedAt, v.Recorder = "", 0, ""
		return remarshal(v), "start " + strings.Join(v.Argv, " "), true

	case logfmt.KindEnvSnapshot:
		var v logfmt.EnvSnapshot
		if logfmt.Unmarshal(payload, &v) != nil {
			return payload, "unreadable EnvSnapshot", true
		}
		for k, val := range v.Vars {
			v.Vars[k] = scrub(val)
		}
		return remarshal(v), fmt.Sprintf("env, %d vars", len(v.Vars)), true

	case logfmt.KindLLMRequest:
		var v logfmt.LLMRequest
		if logfmt.Unmarshal(payload, &v) != nil {
			return payload, "unreadable LlmRequest", true
		}
		v.Body = []byte(scrub(string(v.Body)))
		for k, val := range v.Headers {
			v.Headers[k] = scrub(val)
		}
		return remarshal(v), fmt.Sprintf("%s %s%s", v.Method, v.Host, v.Path), true

	case logfmt.KindLLMResponseChunk:
		var v logfmt.LLMResponseChunk
		if logfmt.Unmarshal(payload, &v) != nil {
			return payload, "unreadable chunk", true
		}
		// Replay reproduces framing, not timing.
		v.SincePrev = 0
		return remarshal(v), fmt.Sprintf("chunk %d, %d bytes", v.Seq, len(v.Data)), true

	case logfmt.KindSecretInjected:
		var v logfmt.SecretInjected
		if logfmt.Unmarshal(payload, &v) != nil {
			return payload, "unreadable SecretInjected", true
		}
		v.Placeholder = scrub(v.Placeholder)
		// The hash is of the real credential, which a replay deliberately does
		// not have -- it runs with dummy values precisely so it needs none. What
		// remains compared is that the same credential reference was substituted
		// for the same host, which is the part of the event that describes what
		// the boundary did.
		v.ValueHash = nil
		return remarshal(v), "inject " + v.Ref + " -> " + v.Host, true

	case logfmt.KindClockRead:
		var v logfmt.ClockRead
		if logfmt.Unmarshal(payload, &v) != nil {
			return payload, "unreadable ClockRead", true
		}
		// The value is served back verbatim over the shim channel, and the log
		// keeps only a lossy nanosecond rendering of it. Comparing the source and
		// the ordering is what matters; the number here would compare a rounding.
		v.Value = 0
		return remarshal(v), "clock " + v.Source, true

	case logfmt.KindRunEnd:
		var v logfmt.RunEnd
		if logfmt.Unmarshal(payload, &v) != nil {
			return payload, "unreadable RunEnd", true
		}
		v.EndedAt = 0
		return remarshal(v), fmt.Sprintf("end, exit %d", v.ExitCode), true

	case logfmt.KindToolCallRequest:
		var v logfmt.ToolCallRequest
		if logfmt.Unmarshal(payload, &v) == nil {
			return payload, fmt.Sprintf("call %s/%s", v.Server, v.Tool), true
		}

	case logfmt.KindToolCallResult:
		var v logfmt.ToolCallResult
		if logfmt.Unmarshal(payload, &v) == nil {
			verdict := "ok"
			if v.IsError {
				verdict = "error"
			}
			return payload, fmt.Sprintf("%s/%s -> %s", v.Server, v.Tool, verdict), true
		}

	case logfmt.KindDNSQuery:
		var v logfmt.DNSQuery
		if logfmt.Unmarshal(payload, &v) == nil {
			return payload, "dns " + v.Type + " " + v.Name, true
		}
	case logfmt.KindDNSDecision:
		var v logfmt.DNSDecision
		if logfmt.Unmarshal(payload, &v) == nil {
			verdict := "denied"
			if v.Allowed {
				verdict = "allowed"
			}
			return payload, "dns " + verdict + " " + v.Name, true
		}
	case logfmt.KindEgressAttempt:
		var v logfmt.EgressAttempt
		if logfmt.Unmarshal(payload, &v) == nil {
			return payload, "connect " + v.Host, true
		}
	case logfmt.KindEgressDecision:
		var v logfmt.EgressDecision
		if logfmt.Unmarshal(payload, &v) == nil {
			verdict := "DENIED"
			if v.Allowed {
				verdict = "allowed"
			}
			return payload, verdict + " " + v.Host, true
		}
	case logfmt.KindRandomRead:
		var v logfmt.RandomRead
		if logfmt.Unmarshal(payload, &v) == nil {
			return payload, "random " + v.Source, true
		}
	case logfmt.KindLLMResponseEnd:
		var v logfmt.LLMResponseEnd
		if logfmt.Unmarshal(payload, &v) == nil {
			return payload, fmt.Sprintf("response %d, %d chunks", v.Status, v.ChunkCount), true
		}
	}

	return payload, kind.String(), true
}

func remarshal(v any) []byte {
	out, err := logfmt.Marshal(v)
	if err != nil {
		return nil
	}
	return out
}

// scrub replaces placeholder tokens, which embed the run id.
func scrub(s string) string {
	if !strings.Contains(s, "hark-placeholder-") {
		return s
	}
	return placeholderPattern.ReplaceAllString(s, placeholderSentinel)
}

// Comparison is the result of checking a replay against its recording.
type Comparison struct {
	Equal bool

	// Divergence is the index of the first differing action, or -1.
	Divergence int

	Recorded *Digest
	Replayed *Digest
}

// Compare finds the first action at which two runs differ.
//
// The report names the step rather than only the outcome. A replay that says
// only "not equal" leaves the reader to diff two bundles by hand; one that says
// "step 14: recorded `connect evil.example`, replayed `connect other.example`"
// is a finding.
func Compare(recorded, replayed *Digest) Comparison {
	c := Comparison{Divergence: -1, Recorded: recorded, Replayed: replayed}

	if recorded.Root == replayed.Root && len(recorded.Steps) == len(replayed.Steps) {
		c.Equal = true
		return c
	}

	n := len(recorded.Steps)
	if len(replayed.Steps) < n {
		n = len(replayed.Steps)
	}
	for i := 0; i < n; i++ {
		if recorded.Steps[i].Hash != replayed.Steps[i].Hash {
			c.Divergence = i
			return c
		}
	}
	// Identical prefixes, different lengths: one run did more than the other.
	c.Divergence = n
	return c
}

// Describe renders a comparison for the operator.
func (c Comparison) Describe() string {
	if c.Equal {
		return fmt.Sprintf("REPLAY-EQUAL  %d actions, digest %x", len(c.Recorded.Steps), c.Recorded.Root)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "REPLAY-DIVERGED at action %d\n", c.Divergence)
	fmt.Fprintf(&b, "  recorded %d actions, replayed %d\n", len(c.Recorded.Steps), len(c.Replayed.Steps))

	at := func(d *Digest, i int) string {
		if i < len(d.Steps) {
			return fmt.Sprintf("%s (%s)", d.Steps[i].Summary, d.Steps[i].Kind)
		}
		return "(nothing -- the run ended here)"
	}
	fmt.Fprintf(&b, "  recorded: %s\n", at(c.Recorded, c.Divergence))
	fmt.Fprintf(&b, "  replayed: %s\n", at(c.Replayed, c.Divergence))

	// The few actions before the split are usually what explains it.
	from := c.Divergence - 3
	if from < 0 {
		from = 0
	}
	if from < c.Divergence {
		b.WriteString("  leading up to it:\n")
		for i := from; i < c.Divergence; i++ {
			fmt.Fprintf(&b, "    %d  %s\n", i, c.Recorded.Steps[i].Summary)
		}
	}
	return b.String()
}
