package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/DevGurav/hark/internal/broker"
	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/launcher"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/mediator"
	"github.com/DevGurav/hark/internal/policy"
	"github.com/DevGurav/hark/internal/replay"
	"github.com/DevGurav/hark/internal/runid"
	"github.com/DevGurav/hark/internal/shim"
)

// hark replay re-runs a recorded agent against its recording.
//
// The recorded bundle supplies everything: the command, the policy, the
// responses, and the clock and RNG values. Nothing is dialled, so the replay
// costs nothing, has no side effects outside the workspace, and does not care
// whether the endpoints are still up.
//
// What it establishes, and the limit of it, is in ADR terms: given the same
// recorded external inputs, the agent produced the same sequence of
// externally-visible actions. It does not establish that a model would say the
// same thing twice -- nothing can.

func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	out := fs.String("o", "", "write the replayed run here (default: <runid>-replay.hark)")
	workDir := fs.String("workdir", "", "override the recorded working directory")
	keep := fs.Bool("keep", false, "keep the replayed bundle even when it matches")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hark replay [-o BUNDLE] [-workdir DIR] <bundle>")
	}
	recordedPath := fs.Arg(0)

	// Reduce the recording to its comparable actions before running anything. If
	// the bundle is unreadable there is no point starting an agent.
	recordedDigest, err := replay.Compute(recordedPath)
	if err != nil {
		return err
	}

	plan, err := loadPlan(recordedPath)
	if err != nil {
		return err
	}

	source, err := replay.Load(recordedPath)
	if err != nil {
		return err
	}

	id, err := runid.New()
	if err != nil {
		return err
	}
	replayPath := *out
	if replayPath == "" {
		replayPath = "run-" + id + "-replay.hark"
	}

	pol, err := policy.Parse(plan.policyRaw, "recorded policy")
	if err != nil {
		return fmt.Errorf("hark replay: the recorded policy no longer parses: %w", err)
	}

	// Placeholders are rebuilt rather than reused. Their values never mattered --
	// canonicalisation normalises them precisely because they embed a run id --
	// and a replay must not need the real credentials to run.
	values := make(map[string]string, len(pol.Secrets))
	for logical := range pol.Secrets {
		values[logical] = "replay-has-no-credentials"
	}
	br, err := broker.New(id, values, pol)
	if err != nil {
		return err
	}

	runDir, err := os.MkdirTemp("", "hark-replay-"+id+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(runDir)

	w, err := bundle.Create(replayPath, bundle.Header{
		RunID:     id,
		CreatedAt: time.Now().UnixNano(),
		Recorder:  Version,
	})
	if err != nil {
		return err
	}
	rec := &recorder{w: w, start: time.Now(), br: br}

	sealed := false
	defer func() {
		if !sealed {
			_ = w.Abort()
		}
	}()

	rec.append(logfmt.KindRunStart, logfmt.RunStart{
		RunID: id, StartedAt: time.Now().UnixNano(), Recorder: Version,
		WorkingDir: plan.workDir, ProviderSet: pol.AllowHosts, Argv: plan.argv,
		// Carried through rather than rebuilt. A replay dials nothing, so the
		// redirections cannot apply to it -- but they are part of the run's
		// starting conditions, and dropping them here would report a divergence
		// on every replay of a run that used one.
		Upstreams: plan.upstreams,
	})
	// Re-emit the recorded event verbatim rather than rebuilding one. A
	// reconstruction differs in fields that describe where the policy came from
	// rather than what it permitted -- Source above all -- and the digest would
	// report that as a divergence when nothing about the run had changed.
	rec.append(logfmt.KindPolicyLoaded, plan.policyEvent)

	shimServer, err := shim.New(runDir, shim.ModeReplay, rec, plan.shimValues)
	if err != nil {
		return err
	}
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
				Playback: &playbackSource{src: source},
				BindIP:   n.MediatorIP, DNSPort: 53, TLSPort: 443,
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
	rec.append(logfmt.KindRunEnd, logfmt.RunEnd{
		EndedAt: time.Now().UnixNano(), ExitCode: code, Reason: reason,
	})

	if _, err := w.Seal(nil, time.Now().UnixNano(), "", 0); err != nil {
		return err
	}
	sealed = true

	replayedDigest, err := replay.Compute(replayPath)
	if err != nil {
		return err
	}
	comparison := replay.Compare(recordedDigest, replayedDigest)

	fmt.Println()
	fmt.Println(comparison.Describe())
	if left := source.Unconsumed(); left > 0 {
		fmt.Printf("  %d recorded response(s) were never asked for\n", left)
	}
	for src, n := range shimServer.Remaining() {
		fmt.Printf("  %d recorded %s value(s) unused\n", n, src)
	}
	fmt.Printf("  replayed bundle: %s\n", replayPath)

	if comparison.Equal && !*keep {
		// A matching replay's bundle is redundant with the original by
		// definition; -keep is there for anyone who wants to inspect it.
		if err := os.Remove(replayPath); err == nil {
			fmt.Printf("  (removed; pass -keep to retain it)\n")
		}
	}

	if !comparison.Equal {
		return exitError{1}
	}
	return nil
}

// plan is what a recording says about how to re-run it.
type plan struct {
	argv        []string
	workDir     string
	upstreams   []string
	policyRaw   []byte
	policyEvent logfmt.PolicyLoaded
	shimValues  shim.Values
}

// loadPlan reads the recording for everything needed to reproduce the run.
func loadPlan(path string) (*plan, error) { return loadPlanUpTo(path, math.MaxUint64) }

// loadPlanUpTo is loadPlan with the clock and RNG history stopped at a sequence
// number.
//
// A fork wants only the values recorded before its branch point: the ones after
// it belong to the run that was, and serving them to the counterfactual would
// mean a run whose randomness came from a future it is no longer heading for.
// The framing events -- argv, the policy -- are read from the whole file
// regardless, since they describe the run rather than its history.
func loadPlanUpTo(path string, upTo uint64) (*plan, error) {
	r, err := bundle.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	p := &plan{shimValues: shim.Values{}}
	for {
		f, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if f.Seq >= upTo && (f.Kind == logfmt.KindClockRead || f.Kind == logfmt.KindRandomRead) {
			continue
		}

		switch f.Kind {
		case logfmt.KindRunStart:
			var v logfmt.RunStart
			if logfmt.Unmarshal(f.Payload, &v) == nil {
				p.argv, p.workDir, p.upstreams = v.Argv, v.WorkingDir, v.Upstreams
			}
		case logfmt.KindPolicyLoaded:
			var v logfmt.PolicyLoaded
			if logfmt.Unmarshal(f.Payload, &v) == nil {
				p.policyRaw, p.policyEvent = v.Raw, v
			}
		case logfmt.KindClockRead:
			var v logfmt.ClockRead
			if logfmt.Unmarshal(f.Payload, &v) == nil {
				p.shimValues[v.Source] = append(p.shimValues[v.Source], clockJSON(v))
			}
		case logfmt.KindRandomRead:
			var v logfmt.RandomRead
			if logfmt.Unmarshal(f.Payload, &v) == nil {
				p.shimValues[v.Source] = append(p.shimValues[v.Source], json.RawMessage(v.Data))
			}
		}
	}

	if len(p.argv) == 0 {
		return nil, errors.New("hark replay: the recording does not name a command; it predates argv being recorded")
	}
	if len(p.policyRaw) == 0 {
		return nil, errors.New("hark replay: the recording carries no policy")
	}
	return p, nil
}

// clockJSON turns a recorded clock reading back into the JSON the shim expects.
//
// The log stores nanoseconds for readability; the shim speaks the units the
// Python call returns. The conversion is lossy for float seconds, which is why
// the digest excludes clock values from comparison rather than pretending
// otherwise.
func clockJSON(v logfmt.ClockRead) json.RawMessage {
	if v.Source == "time.time_ns" || v.Source == "time.monotonic_ns" {
		return json.RawMessage(fmt.Sprintf("%d", v.Value))
	}
	return json.RawMessage(fmt.Sprintf("%.9f", float64(v.Value)/1e9))
}

// playbackSource adapts replay.Source to the mediator's Playback interface.
type playbackSource struct{ src *replay.Source }

func (p *playbackSource) Lookup(canonical []byte) (*mediator.PlaybackResponse, error) {
	res, err := p.src.Lookup(canonical)
	if err != nil {
		return nil, err
	}
	return &mediator.PlaybackResponse{
		Status: res.Status, Headers: res.Headers, Chunks: res.Chunks, Error: res.Error,
	}, nil
}

// shimSourceDir locates the Python shim next to the binary or in the source
// tree.
func shimSourceDir() (string, error) {
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "shim")
		if _, err := os.Stat(filepath.Join(candidate, "sitecustomize.py")); err == nil {
			return candidate, nil
		}
	}
	for _, candidate := range []string{"shim", filepath.Join("..", "shim")} {
		if _, err := os.Stat(filepath.Join(candidate, "sitecustomize.py")); err == nil {
			return filepath.Abs(candidate)
		}
	}
	return "", errors.New("hark replay: cannot find shim/sitecustomize.py next to the binary or in the working directory")
}
