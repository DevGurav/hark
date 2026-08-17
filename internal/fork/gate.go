package fork

import (
	"fmt"
	"strings"
	"sync"

	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/replay"
)

// Phase is how far a forked run has got.
type Phase uint8

const (
	// PhasePrefix is the part being re-executed against the recording. Every
	// action is compared with the parent's as it happens.
	PhasePrefix Phase = iota

	// PhasePatch is the single exchange at the branch point, served from the
	// recording with the patch applied.
	PhasePatch

	// PhaseLive is everything after: real dials, real credentials, real clock.
	PhaseLive
)

// Gate decides which of those three a forked run is in.
//
// It is driven by the child's own event stream rather than by a plan made in
// advance, because that is the only thing that can tell the difference between
// a fork and a run that quietly stopped matching its recording. The prefix is
// checked action by action, so a divergence is caught at the action that caused
// it rather than at the end -- and a fork from an unverified prefix proves
// nothing, so a divergence stops the run.
type Gate struct {
	at     uint64
	parent *replay.Digest
	patch  bool

	mu      sync.Mutex
	acc     replay.Accumulator
	phase   Phase
	patched bool
	split   *Divergence

	failed  sync.Once
	failure chan struct{}
}

// Divergence is the first action at which a fork stopped reproducing its
// parent.
type Divergence struct {
	Action   uint64
	Kind     logfmt.Kind
	Recorded string
	Forked   string
	Leading  []string
}

// NewGate prepares a fork of parent at event at.
//
// at is the event to branch at: everything before it is re-executed and
// verified, and it is the first event of the counterfactual.
func NewGate(parent *replay.Digest, at uint64, patched bool) (*Gate, error) {
	if parent == nil {
		return nil, fmt.Errorf("fork: no parent digest")
	}
	if at == 0 {
		// There would be no prefix to verify, so the run would be an ordinary
		// live run wearing a fork's output.
		return nil, fmt.Errorf("fork: -at 0 has no prefix to verify; a fork branches after at least one recorded event")
	}
	if at > uint64(len(parent.Steps)) {
		return nil, fmt.Errorf("fork: -at %d, but the recording has %d events (0..%d)",
			at, len(parent.Steps), len(parent.Steps)-1)
	}
	return &Gate{at: at, parent: parent, patch: patched, failure: make(chan struct{})}, nil
}

// Observe folds one event of the forked run in.
//
// Called for every event the child records, in order, by whatever holds the
// log's ordering lock. Below the fork point it compares; at the fork point it
// opens the gate; above it does nothing at all.
func (g *Gate) Observe(kind logfmt.Kind, payload []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.phase != PhasePrefix || g.split != nil {
		return
	}

	step, ok := g.acc.Add(kind, payload)
	if !ok {
		return
	}

	i := g.acc.Actions() - 1
	if i < uint64(len(g.parent.Steps)) && step.Hash != g.parent.Steps[i].Hash {
		g.diverge(i, step)
		return
	}

	if g.acc.Actions() == g.at {
		g.phase = PhasePatch
		if !g.patch {
			// Nothing to change at the branch point: this is the plain
			// counterfactual, "re-run from here and see what happens".
			g.phase = PhaseLive
		}
	}
}

func (g *Gate) diverge(i uint64, step replay.Step) {
	d := &Divergence{Action: i, Kind: step.Kind, Forked: step.Summary}
	if i < uint64(len(g.parent.Steps)) {
		d.Recorded = g.parent.Steps[i].Summary
		d.Kind = g.parent.Steps[i].Kind
	}
	from := int(i) - 3
	if from < 0 {
		from = 0
	}
	for j := from; j < int(i); j++ {
		d.Leading = append(d.Leading, g.parent.Steps[j].Summary)
	}

	g.split = d
	g.failed.Do(func() { close(g.failure) })
}

// Phase reports where the run is.
func (g *Gate) Phase() Phase {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.phase
}

// Live reports whether the run has left its recorded prefix behind. True from
// the branch point onward, including the patched exchange -- a clock read
// between the two belongs to the counterfactual, not to the recording.
func (g *Gate) Live() bool { return g.Phase() != PhasePrefix }

// TakePatch claims the branch point for one exchange. It answers true exactly
// once per fork, so the patch cannot be applied to two responses.
func (g *Gate) TakePatch() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.phase != PhasePatch {
		return false
	}
	g.phase = PhaseLive
	g.patched = true
	return true
}

// Patched reports whether the patch was applied to anything.
func (g *Gate) Patched() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.patched
}

// Actions reports how many actions of the prefix have been reproduced.
func (g *Gate) Actions() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.acc.Actions()
}

// Failed is closed when the fork diverges from its parent. A caller waits on it
// to stop the agent, because a fork that carries on past a divergence is
// producing a run whose prefix proves nothing.
func (g *Gate) Failed() <-chan struct{} { return g.failure }

// Divergence returns the first divergence, or nil.
func (g *Gate) Divergence() *Divergence {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.split
}

// PrefixRoot is the parent's digest over the verified prefix. Meaningful only
// once the gate has opened.
func (g *Gate) PrefixRoot() hashchain.Hash {
	if g.at == 0 || g.at > uint64(len(g.parent.Steps)) {
		return hashchain.Zero
	}
	return g.parent.Steps[g.at-1].Hash
}

// Describe renders a divergence for the operator.
func (d *Divergence) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "FORK-DIVERGED at action %d\n", d.Action)
	b.WriteString("  the prefix stopped reproducing the recording, so nothing was forked\n")
	fmt.Fprintf(&b, "  recorded: %s (%s)\n", d.Recorded, d.Kind)
	fmt.Fprintf(&b, "  forked:   %s\n", d.Forked)
	if len(d.Leading) > 0 {
		b.WriteString("  leading up to it:\n")
		for i, s := range d.Leading {
			fmt.Fprintf(&b, "    %d  %s\n", d.Action-uint64(len(d.Leading)-i), s)
		}
	}
	return b.String()
}
