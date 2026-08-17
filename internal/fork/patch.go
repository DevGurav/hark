// Package fork branches a recorded run.
//
// A fork re-executes an agent against its own recording up to a chosen event,
// checks as it goes that the re-execution is producing what was recorded,
// changes one thing at that point, and lets the run go live from there. It
// answers a counterfactual -- "what would this agent have done if the page had
// not carried that instruction?" -- with a run rather than an argument.
//
// The claim a fork makes is exactly this and no more:
//
//	provably identical prefix, live suffix
//
// Never bit-exact. Everything after the branch point is a fresh run against a
// live upstream, and the parent's root says nothing about it. Saying otherwise
// would be the most inviting overclaim in the project, which is why the phrase
// is fixed and appears in the output verbatim.
package fork

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/DevGurav/hark/internal/hashchain"
)

// Patch is the one change a fork makes at its branch point.
//
// It edits a recorded response on its way to the agent, so the agent sees the
// world it would have seen had the response been different. It cannot edit the
// agent, the policy or the log: a counterfactual worth running is one where
// only the input changed.
type Patch struct {
	// At, if set, is the event this patch was written for. Optional, and
	// checked against -at rather than replacing it -- a saved patch applied to
	// the wrong event of the wrong bundle is a silent wrong answer, and the file
	// is the only place that mistake is detectable.
	At uint64 `json:"at"`

	// Note is why this patch exists. It travels in the child bundle's audit
	// trail by way of the patch hash, so it is worth writing.
	Note string `json:"note"`

	// Status overrides the recorded response status. Zero leaves it alone.
	Status int `json:"status"`

	Ops []Op `json:"ops"`

	raw  []byte
	hash hashchain.Hash
}

// Op is one edit to the recorded response body.
type Op struct {
	// Op is "replace" or "body".
	Op   string `json:"op"`
	Find string `json:"find"`
	With string `json:"with"`
}

const (
	OpReplace = "replace"
	OpBody    = "body"
)

// LoadPatch reads and validates a patch file.
func LoadPatch(path string) (*Patch, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var p Patch
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	// An unknown field is an error for the same reason it is in the policy
	// loader: a misspelt key is a change the author believes they made.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	if len(p.Ops) == 0 && p.Status == 0 {
		return nil, fmt.Errorf("%s: the patch changes nothing", path)
	}
	for i, op := range p.Ops {
		switch op.Op {
		case OpReplace:
			if op.Find == "" {
				return nil, fmt.Errorf("%s: ops[%d]: replace needs something to find", path, i)
			}
		case OpBody:
			if op.Find != "" {
				return nil, fmt.Errorf("%s: ops[%d]: body replaces the whole response and takes no find", path, i)
			}
		default:
			return nil, fmt.Errorf("%s: ops[%d]: unknown op %q, expected %q or %q", path, i, op.Op, OpReplace, OpBody)
		}
	}

	p.raw = raw
	// Over the file as it was on disk, not over the parsed form: what a reviewer
	// will diff is the file, and formatting the parser discards is still part of
	// what the operator ran.
	p.hash = hashchain.Leaf(0, 0, raw)
	return &p, nil
}

// Hash identifies the patch, and goes in the child bundle's header.
func (p *Patch) Hash() hashchain.Hash { return p.hash }

// Raw returns the patch file as it was read.
func (p *Patch) Raw() []byte { return p.raw }

// Response is the part of a recorded reply a patch can change.
type Response struct {
	Status int
	Chunks [][]byte
}

// Apply produces the patched response.
//
// The body is patched as a whole and comes back as a single chunk. The recorded
// chunk boundaries described bytes that no longer exist, and redistributing a
// changed body across them would be a fiction -- an invented framing presented
// with the authority of a recorded one. Nothing downstream depends on it: the
// patched exchange is the point at which the run stops being a replay.
func (p *Patch) Apply(res Response) (Response, error) {
	var body []byte
	for _, c := range res.Chunks {
		body = append(body, c...)
	}

	for i, op := range p.Ops {
		switch op.Op {
		case OpBody:
			body = []byte(op.With)
		case OpReplace:
			if !strings.Contains(string(body), op.Find) {
				// A patch that quietly matches nothing is the worst outcome
				// available here: the fork runs, reports a clean suffix, and the
				// operator concludes the change was harmless when it was never
				// made.
				return Response{}, fmt.Errorf(
					"patch ops[%d]: the recorded response contains no %q, so this patch would change nothing", i, op.Find)
			}
			body = []byte(strings.ReplaceAll(string(body), op.Find, op.With))
		}
	}

	out := Response{Status: res.Status, Chunks: [][]byte{body}}
	if p.Status != 0 {
		out.Status = p.Status
	}
	return out, nil
}

// Describe renders the patch for the fork summary.
func (p *Patch) Describe() string {
	var b strings.Builder
	if p.Note != "" {
		b.WriteString(p.Note)
		b.WriteString("; ")
	}
	for i, op := range p.Ops {
		if i > 0 {
			b.WriteString(", ")
		}
		switch op.Op {
		case OpBody:
			fmt.Fprintf(&b, "replace the body with %d bytes", len(op.With))
		case OpReplace:
			fmt.Fprintf(&b, "%q -> %q", elide(op.Find), elide(op.With))
		}
	}
	if p.Status != 0 {
		fmt.Fprintf(&b, ", status %d", p.Status)
	}
	return b.String()
}

func elide(s string) string {
	const max = 48
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ErrNoPatch is returned when a fork needs a patch and has none.
var ErrNoPatch = errors.New("fork: no patch")
