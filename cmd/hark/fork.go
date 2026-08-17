package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/DevGurav/hark/internal/broker"
	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/fork"
	"github.com/DevGurav/hark/internal/launcher"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/mediator"
	"github.com/DevGurav/hark/internal/policy"
	"github.com/DevGurav/hark/internal/rekor"
	"github.com/DevGurav/hark/internal/replay"
	"github.com/DevGurav/hark/internal/runid"
	"github.com/DevGurav/hark/internal/shim"
	"github.com/DevGurav/hark/internal/signer"
)

// hark fork answers a counterfactual with a run.
//
// It re-executes the agent against the recording up to -at, checking every
// action against what was recorded, changes one response there, and lets the
// run go live from that point on. The output says what it proved and no more:
//
//	provably identical prefix, live suffix
//
// Never bit-exact. The suffix is a fresh run against a live upstream, and the
// parent's root has nothing to say about it.

func cmdFork(args []string) error {
	fs := flag.NewFlagSet("fork", flag.ExitOnError)
	at := fs.Uint64("at", 0, "branch at this event (required)")
	patchPath := fs.String("patch", "", "JSON patch to apply to the response at the branch point")
	out := fs.String("o", "", "write the forked run here (default: <runid>-fork.hark)")
	keyPath := fs.String("key", "", "sign the sealed root with this key")
	anchor := fs.Bool("anchor", false, "anchor the sealed root in a transparency log (needs -key)")
	rekorURL := fs.String("rekor", rekor.PublicLog, "transparency log to anchor in")
	workDir := fs.String("workdir", "", "override the recorded working directory")
	var up upstreams
	fs.Var(&up, "upstream", "dial HOST=ADDR instead of HOST:443 (defaults to the recording's)")
	upstreamCA := fs.String("upstream-ca", "", "the only root a redirected upstream may present")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hark fork -at N [-patch FILE] [-o BUNDLE] [-key FILE] <bundle>")
	}
	parentPath := fs.Arg(0)

	// The parent is verified before anything else happens. A fork from a bundle
	// that does not verify proves nothing at all, and finding that out after
	// spending a live run on it would be the wrong order.
	parentResult, err := bundle.Verify(parentPath)
	if err != nil {
		return err
	}
	switch parentResult.Status {
	case bundle.StatusBroken:
		return fmt.Errorf("hark fork: the parent bundle does not verify (%s); a fork from it would prove nothing",
			parentResult.Problem)
	case bundle.StatusTruncated:
		if parentResult.LeafCount < *at {
			return fmt.Errorf("hark fork: the parent was killed after %d events, before -at %d",
				parentResult.LeafCount, *at)
		}
		fmt.Fprintf(os.Stderr, "hark fork: the parent is truncated (%s); its prefix through event %d still verifies\n",
			parentResult.Problem, parentResult.LeafCount-1)
	}

	var patch *fork.Patch
	if *patchPath != "" {
		if patch, err = fork.LoadPatch(*patchPath); err != nil {
			return err
		}
		if patch.At != 0 && patch.At != *at {
			// The patch file says which event it was written for. Applying it
			// somewhere else is a silent wrong answer, and this is the only place
			// the mistake is visible.
			return fmt.Errorf("hark fork: -at %d, but %s was written for event %d", *at, *patchPath, patch.At)
		}
	}

	parentDigest, err := replay.Compute(parentPath)
	if err != nil {
		return err
	}
	gate, err := fork.NewGate(parentDigest, *at, patch != nil)
	if err != nil {
		return err
	}
	if patch != nil {
		// -at may name the position one past the last event, which is a legal
		// fork point -- the whole run is replayed and the fork goes live at the
		// end -- but there is no recorded response there for a patch to change.
		if *at == uint64(len(parentDigest.Steps)) {
			return fmt.Errorf("hark fork: -at %d is the end of the recording; "+
				"a patch changes a recorded response, and there is none there", *at)
		}
		if kind := parentDigest.Steps[*at].Kind; kind != logfmt.KindLLMRequest {
			return fmt.Errorf("hark fork: event %d is a %s; a patch changes a recorded response, "+
				"so -at must name an LlmRequest -- `hark inspect %s` lists them", *at, kind, parentPath)
		}
	}

	plan, err := loadPlanUpTo(parentPath, *at)
	if err != nil {
		return err
	}
	source, err := replay.Load(parentPath)
	if err != nil {
		return err
	}

	pol, err := policy.Parse(plan.policyRaw, "recorded policy")
	if err != nil {
		return fmt.Errorf("hark fork: the recorded policy no longer parses: %w", err)
	}

	// The suffix is live, so it needs the real credentials -- unlike a replay,
	// which deliberately runs without them. Resolved before the run starts, so a
	// missing key fails here rather than at the first live call.
	values, err := broker.ResolveFromEnv(pol.Secrets)
	if err != nil {
		return fmt.Errorf("%w\n  a fork goes live after its branch point, so it needs the real values", err)
	}

	// Redirections default to the recording's. If the parent reached a stub, the
	// fork's live suffix has to reach the same stub or it is not the same world.
	if len(up.list()) == 0 {
		if err := up.setAll(plan.upstreams); err != nil {
			return fmt.Errorf("hark fork: the recording's upstream redirection is unreadable: %w", err)
		}
	}
	dialUpstream, err := up.dialer(*upstreamCA)
	if err != nil {
		return err
	}

	id, err := runid.New()
	if err != nil {
		return err
	}
	forkPath := *out
	if forkPath == "" {
		forkPath = "run-" + id + "-fork.hark"
	}

	var key *signer.Key
	if *keyPath != "" {
		if key, err = signer.LoadKey(*keyPath); err != nil {
			return err
		}
	}
	if *anchor && key == nil {
		return errors.New("hark fork: -anchor commits a signed tree head, so it needs -key")
	}

	br, err := broker.New(id, values, pol)
	if err != nil {
		return err
	}

	runDir, err := os.MkdirTemp("", "hark-fork-"+id+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(runDir)

	policyHash := policy.Hash(plan.policyRaw)
	header := bundle.Header{
		RunID:      id,
		CreatedAt:  time.Now().UnixNano(),
		Recorder:   Version,
		PolicyHash: policyHash[:],
		ParentRoot: parentResult.Root[:],
		ForkPoint:  *at,
	}
	if patch != nil {
		h := patch.Hash()
		header.PatchHash = h[:]
	}
	w, err := bundle.Create(forkPath, header)
	if err != nil {
		return err
	}
	rec := &forkRecorder{recorder: recorder{w: w, start: time.Now(), br: br}, gate: gate}

	sealed := false
	defer func() {
		if !sealed {
			_ = w.Abort()
		}
	}()

	rec.append(logfmt.KindRunStart, logfmt.RunStart{
		RunID: id, StartedAt: time.Now().UnixNano(), Recorder: Version,
		WorkingDir: plan.workDir, ProviderSet: pol.AllowHosts, Argv: plan.argv,
		Upstreams: up.list(),
	})
	rec.append(logfmt.KindPolicyLoaded, plan.policyEvent)

	shimServer, err := shim.New(runDir, shim.ModeFork, rec, plan.shimValues)
	if err != nil {
		return err
	}
	shimServer.Live = gate.Live
	go func() { _ = shimServer.Serve() }()
	defer shimServer.Close()

	placeholders := br.Placeholders()
	rec.append(logfmt.KindEnvSnapshot, logfmt.EnvSnapshot{Vars: placeholders})

	caPath := filepath.Join(runDir, "ca.pem")
	shimDir, err := shimSourceDir()
	if err != nil {
		return err
	}
	agentEnv := append(buildEnv(placeholders, caPath), shimServer.Env(shimDir)...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		med      *mediator.Mediator
		medDone  = make(chan struct{})
		medReady = make(chan struct{})
		medOnce  sync.Once
	)

	wd := plan.workDir
	if *workDir != "" {
		wd = *workDir
	}

	playback := &forkPlayback{src: source, gate: gate, patch: patch}

	spec := launcher.Spec{
		Argv:       plan.argv,
		Env:        agentEnv,
		WorkDir:    wd,
		ReadPaths:  append(append([]string{}, pol.ReadPaths...), runDir, shimDir),
		WritePaths: pol.WritePaths,
		ResolvConf: filepath.Join(runDir, "resolv.conf"),

		BeforeRelease: func(n launcher.Network) error {
			m, err := mediator.New(mediator.Config{
				Policy: pol, Broker: br, Recorder: rec,
				Playback: playback, DialUpstream: dialUpstream,
				BindIP: n.MediatorIP, DNSPort: 53, TLSPort: 443,
				RunID: id, Started: medReady,
			})
			if err != nil {
				return err
			}
			med = m

			if err := os.WriteFile(caPath, m.CACertPEM(), 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(runDir, "resolv.conf"),
				[]byte("nameserver "+n.MediatorIP+"\noptions timeout:2 attempts:1\n"), 0o644); err != nil {
				return err
			}

			medOnce.Do(func() {
				go func() { defer close(medDone); _ = m.Serve(ctx) }()
			})
			select {
			case <-medReady:
				return nil
			case <-time.After(15 * time.Second):
				return errors.New("mediator did not start listening")
			}
		},
	}

	h, err := launcher.Launch(spec)
	if err != nil {
		return err
	}
	defer h.Close()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		select {
		case <-sigs:
			_ = h.Kill()
		case <-gate.Failed():
			// The prefix stopped reproducing the recording. Everything after this
			// point would be a live run wearing a fork's header, so it is stopped
			// rather than allowed to finish.
			_ = h.Kill()
		case <-ctx.Done():
		}
	}()

	code, waitErr := h.Wait()
	cancel()
	if med != nil {
		med.Close()
		<-medDone
	}

	reason := "exit"
	if waitErr != nil {
		reason = "error: " + waitErr.Error()
	}
	if d := gate.Divergence(); d != nil {
		reason = "fork-diverged"
	}
	rec.append(logfmt.KindRunEnd, logfmt.RunEnd{
		EndedAt: time.Now().UnixNano(), ExitCode: code, Reason: reason,
	})

	signedAt := time.Now().UnixNano()
	entry, index := anchorSeal(key, *anchor, *rekorURL, id, w, signedAt)

	foot, err := w.Seal(key, signedAt, entry, index)
	if err != nil {
		return err
	}
	sealed = true

	fmt.Println()
	if d := gate.Divergence(); d != nil {
		fmt.Print(d.Describe())
		fmt.Printf("  the partial run is at %s\n", forkPath)
		os.Exit(1)
	}

	switch {
	case gate.Phase() == fork.PhasePrefix:
		fmt.Printf("FORK-INCOMPLETE  the run ended after %d of the %d actions before the branch point\n",
			gate.Actions(), *at)
		fmt.Printf("  nothing was forked; the partial run is at %s\n", forkPath)
		os.Exit(1)
	case patch != nil && !gate.Patched():
		// The branch point was reached but no request followed it, so the patch
		// never applied. Reporting success here would describe a counterfactual
		// that was never run.
		fmt.Println("FORK-UNPATCHED  the branch point was reached, but no request followed it")
		fmt.Println("  the patch never applied, so this run is not the counterfactual it claims")
		fmt.Printf("  the run is at %s\n", forkPath)
		os.Exit(1)
	}

	fmt.Println("FORKED  provably identical prefix, live suffix")
	fmt.Printf("  parent       %s\n", parentPath)
	fmt.Printf("  parent root  %x\n", parentResult.Root)
	fmt.Printf("  branch at    event %d, after %d verified actions\n", *at, gate.Actions())
	fmt.Printf("  prefix       %x\n", gate.PrefixRoot())
	if patch != nil {
		fmt.Printf("  patch        %s\n", patch.Describe())
		fmt.Printf("  patch hash   %x\n", patch.Hash())
	}
	fmt.Printf("  child        %s\n", forkPath)
	fmt.Printf("  child root   %x\n", foot.Root)
	fmt.Printf("  events       %d\n", foot.LeafCount)

	if code != 0 {
		return exitError{code}
	}
	return nil
}

// forkRecorder is the run's recorder with the gate watching every event.
//
// The gate has to see events in the order they were appended, which is what the
// embedded recorder's lock already guarantees; observing inside it keeps the
// comparison in step with the log rather than racing it.
type forkRecorder struct {
	recorder
	gate *fork.Gate
}

func (r *forkRecorder) Append(kind logfmt.Kind, payload any) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	seq, err := r.w.Append(kind, uint64(time.Since(r.start).Nanoseconds()), payload)
	if err != nil {
		return seq, err
	}
	// Re-encoded rather than threaded out of the writer. Canonical CBOR is
	// deterministic, so this is the same bytes the leaf hash covered, and the
	// cost is nothing next to the network round trips that produce these events.
	if raw, err := logfmt.Marshal(payload); err == nil {
		r.gate.Observe(kind, raw)
	}
	return seq, nil
}

func (r *forkRecorder) append(kind logfmt.Kind, payload any) {
	_, _ = r.Append(kind, payload)
}

// forkPlayback serves the recording below the branch point, the patched
// response at it, and tells the mediator to go live above it.
type forkPlayback struct {
	src   *replay.Source
	gate  *fork.Gate
	patch *fork.Patch
}

func (p *forkPlayback) Lookup(canonical []byte) (*mediator.PlaybackResponse, error) {
	if p.gate.Phase() == fork.PhaseLive {
		return nil, mediator.ErrLive
	}

	res, err := p.src.Lookup(canonical)
	if err != nil {
		return nil, err
	}
	out := &mediator.PlaybackResponse{
		Status: res.Status, Headers: res.Headers, Chunks: res.Chunks, Error: res.Error,
	}

	// TakePatch answers true exactly once, so a patch cannot reach two
	// responses even if two exchanges arrive at the branch point together.
	if p.patch != nil && p.gate.TakePatch() {
		patched, err := p.patch.Apply(fork.Response{Status: res.Status, Chunks: res.Chunks})
		if err != nil {
			return nil, err
		}
		out.Status, out.Chunks = patched.Status, patched.Chunks
	}
	return out, nil
}
