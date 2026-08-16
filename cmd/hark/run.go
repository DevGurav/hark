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
	"github.com/DevGurav/hark/internal/launcher"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/mediator"
	"github.com/DevGurav/hark/internal/policy"
	"github.com/DevGurav/hark/internal/runid"
	"github.com/DevGurav/hark/internal/signer"
)

// hark run ties everything together: policy, broker, bundle, mediator, launcher.
//
// The ordering is the interesting part, and most of it exists to make one
// guarantee true -- that nothing the agent does can happen before it can be
// recorded:
//
//	load policy and resolve credentials   fail here, not halfway through a run
//	open the bundle                       the log exists before anything is logged
//	record the run's starting conditions
//	launch, which builds the boundary
//	  ...and calls back to start the mediator on it
//	release the agent
//	wait, record the outcome, seal

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	policyPath := fs.String("policy", "", "policy file (required)")
	out := fs.String("o", "", "bundle to write (default: <runid>.hark)")
	keyPath := fs.String("key", "", "sign the sealed root with this key")
	workDir := fs.String("workdir", "", "working directory for the agent")
	var writePaths stringList
	fs.Var(&writePaths, "write", "grant the agent write access to this path (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" {
		return errors.New("usage: hark run -policy FILE [-o BUNDLE] [-key FILE] [-write DIR] -- COMMAND...")
	}
	if fs.NArg() == 0 {
		return errors.New("hark run: no command given")
	}

	pol, rawPolicy, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}

	// Resolve credentials before anything else observable happens. A missing key
	// should stop the run here rather than at the first model call, halfway
	// through a recorded session.
	values, err := broker.ResolveFromEnv(pol.Secrets)
	if err != nil {
		return err
	}

	id, err := runid.New()
	if err != nil {
		return err
	}
	bundlePath := *out
	if bundlePath == "" {
		bundlePath = "run-" + id + ".hark"
	}

	var key *signer.Key
	if *keyPath != "" {
		if key, err = signer.LoadKey(*keyPath); err != nil {
			return err
		}
	}

	br, err := broker.New(id, values, pol)
	if err != nil {
		return err
	}

	// A per-run directory for the things the agent must be able to read: the
	// run's CA, and a resolv.conf pointing at the mediator. Removed on exit --
	// the CA is worthless afterwards and leaving it lying around is untidy at
	// best.
	runDir, err := os.MkdirTemp("", "hark-"+id+"-")
	if err != nil {
		return fmt.Errorf("hark run: creating the run directory: %w", err)
	}
	defer os.RemoveAll(runDir)

	policyHash := policy.Hash(rawPolicy)
	w, err := bundle.Create(bundlePath, bundle.Header{
		RunID:      id,
		CreatedAt:  time.Now().UnixNano(),
		Recorder:   Version,
		PolicyHash: policyHash[:],
	})
	if err != nil {
		return err
	}

	rec := &recorder{w: w, start: time.Now(), br: br}

	sealed := false
	defer func() {
		// A run that did not reach RunEnd is aborted rather than sealed, leaving
		// a verifiable prefix rather than a footer that claims completeness.
		if !sealed {
			_ = w.Abort()
		}
	}()

	rec.append(logfmt.KindRunStart, logfmt.RunStart{
		RunID:       id,
		StartedAt:   time.Now().UnixNano(),
		Recorder:    Version,
		WorkingDir:  *workDir,
		ProviderSet: pol.AllowHosts,
	})
	rec.append(logfmt.KindPolicyLoaded, logfmt.PolicyLoaded{
		Source:     *policyPath,
		AllowHosts: pol.AllowHosts,
		ReadPaths:  pol.ReadPaths,
		WritePaths: pol.WritePaths,
		Raw:        rawPolicy,
	})

	placeholders := br.Placeholders()
	caPath := filepath.Join(runDir, "ca.pem")
	agentEnv := buildEnv(placeholders, caPath)
	rec.append(logfmt.KindEnvSnapshot, logfmt.EnvSnapshot{Vars: placeholders})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		med      *mediator.Mediator
		medDone  = make(chan struct{})
		medErr   error
		medOnce  sync.Once
		medReady = make(chan struct{})
	)

	spec := launcher.Spec{
		Argv:       fs.Args(),
		Env:        agentEnv,
		WorkDir:    *workDir,
		ReadPaths:  append(append([]string{}, pol.ReadPaths...), runDir),
		WritePaths: append(append([]string{}, pol.WritePaths...), writePaths...),
		ResolvConf: filepath.Join(runDir, "resolv.conf"),

		// The boundary exists by the time this runs, so the mediator can bind the
		// address that was just assigned. The agent is still blocked.
		BeforeRelease: func(n launcher.Network) error {
			m, err := mediator.New(mediator.Config{
				Policy: pol, Broker: br, Recorder: rec,
				BindIP: n.MediatorIP, DNSPort: 53, TLSPort: 443,
				RunID: id, Started: medReady,
			})
			if err != nil {
				return err
			}
			med = m

			if err := os.WriteFile(caPath, m.CACertPEM(), 0o644); err != nil {
				return fmt.Errorf("writing the run CA: %w", err)
			}
			if err := os.WriteFile(filepath.Join(runDir, "resolv.conf"),
				[]byte("nameserver "+n.MediatorIP+"\noptions timeout:2 attempts:1\n"), 0o644); err != nil {
				return fmt.Errorf("writing resolv.conf: %w", err)
			}

			medOnce.Do(func() {
				go func() { defer close(medDone); medErr = m.Serve(ctx) }()
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

	// SIGINT must still produce a usable artifact. The bundle is aborted rather
	// than sealed, so it carries a verifiable prefix and says the run did not
	// finish.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		select {
		case <-sigs:
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
	rec.append(logfmt.KindRunEnd, logfmt.RunEnd{
		EndedAt: time.Now().UnixNano(), ExitCode: code, Reason: reason,
	})

	foot, err := w.Seal(key, time.Now().UnixNano(), "", 0)
	if err != nil {
		return err
	}
	sealed = true

	fmt.Fprintf(os.Stderr, "\nhark: wrote %s\n", bundlePath)
	fmt.Fprintf(os.Stderr, "  events %d\n", foot.LeafCount)
	fmt.Fprintf(os.Stderr, "  root   %x\n", foot.Root)
	if medErr != nil {
		fmt.Fprintf(os.Stderr, "  mediator: %v\n", medErr)
	}

	// The agent's exit code is the command's result, so it becomes ours.
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

// buildEnv assembles the agent's environment: the host's, plus placeholder
// credentials, plus the trust-store variables pointing at this run's CA.
//
// Three variables rather than one because there is no single convention --
// OpenSSL, Python's requests, and Node each read a different name.
func buildEnv(placeholders map[string]string, caPath string) []string {
	env := os.Environ()
	for k, v := range placeholders {
		env = append(env, k+"="+v)
	}
	for _, k := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"} {
		env = append(env, k+"="+caPath)
	}
	return env
}

// recorder adapts the bundle writer to the mediator's Recorder interface.
//
// The lock matters: the mediator records from a goroutine per connection while
// the main flow records the run's framing events. The bundle writer maintains a
// hash chain, so two concurrent appends would corrupt it.
type recorder struct {
	mu    sync.Mutex
	w     *bundle.Writer
	start time.Time
	br    *broker.Broker
}

func (r *recorder) Append(kind logfmt.Kind, payload any) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.w.Append(kind, uint64(time.Since(r.start).Nanoseconds()), payload)
}

func (r *recorder) Sync() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.w.Sync()
}

func (r *recorder) append(kind logfmt.Kind, payload any) {
	_, _ = r.Append(kind, payload)
}

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string     { return fmt.Sprint(*s) }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }
