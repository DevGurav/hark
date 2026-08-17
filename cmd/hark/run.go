package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DevGurav/hark/internal/broker"
	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/launcher"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/mediator"
	"github.com/DevGurav/hark/internal/policy"
	"github.com/DevGurav/hark/internal/rekor"
	"github.com/DevGurav/hark/internal/runid"
	"github.com/DevGurav/hark/internal/shim"
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
	anchor := fs.Bool("anchor", false, "anchor the sealed root in a transparency log (needs -key)")
	rekorURL := fs.String("rekor", rekor.PublicLog, "transparency log to anchor in")
	workDir := fs.String("workdir", "", "working directory for the agent")
	var writePaths stringList
	fs.Var(&writePaths, "write", "grant the agent write access to this path (repeatable)")
	var up upstreams
	fs.Var(&up, "upstream", "dial HOST=ADDR instead of HOST:443 (repeatable; recorded in the bundle)")
	upstreamCA := fs.String("upstream-ca", "", "the only root a redirected upstream may present")
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

	dialUpstream, err := up.dialer(*upstreamCA)
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
	if *anchor && key == nil {
		// There would be nothing to anchor: what a transparency log holds is a
		// signed tree head, and an unsigned root is not one.
		return errors.New("hark run: -anchor commits a signed tree head, so it needs -key")
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
		Argv:        fs.Args(),
		Upstreams:   up.list(),
	})
	rec.append(logfmt.KindPolicyLoaded, logfmt.PolicyLoaded{
		Source:     *policyPath,
		AllowHosts: pol.AllowHosts,
		ReadPaths:  pol.ReadPaths,
		WritePaths: pol.WritePaths,
		Raw:        rawPolicy,
	})

	// The shim captures the clock and RNG reads that never cross the network
	// boundary. Without it a recording cannot replay, so it starts before the
	// agent does.
	shimServer, err := shim.New(runDir, shim.ModeRecord, rec, nil)
	if err != nil {
		return err
	}
	go func() { _ = shimServer.Serve() }()
	defer shimServer.Close()

	shimDir, err := shimSourceDir()
	if err != nil {
		return err
	}

	placeholders := br.Placeholders()
	caPath := filepath.Join(runDir, "ca.pem")
	agentEnv := append(buildEnv(placeholders, caPath), shimServer.Env(shimDir)...)
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
		ReadPaths:  append(append([]string{}, pol.ReadPaths...), runDir, shimDir),
		WritePaths: append(append([]string{}, pol.WritePaths...), writePaths...),
		ResolvConf: filepath.Join(runDir, "resolv.conf"),

		// The boundary exists by the time this runs, so the mediator can bind the
		// address that was just assigned. The agent is still blocked.
		BeforeRelease: func(n launcher.Network) error {
			m, err := mediator.New(mediator.Config{
				Policy: pol, Broker: br, Recorder: rec,
				BindIP: n.MediatorIP, DNSPort: 53, TLSPort: 443,
				RunID: id, Started: medReady, DialUpstream: dialUpstream,
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

	if ref := rec.Leaked(); ref != "" {
		// Left unsealed on purpose: the bundle has a hole where an event was
		// refused, and a footer would claim a completeness it does not have.
		return fmt.Errorf("hark run: the real value of %q reached the recorder, so %s was not sealed",
			ref, bundlePath)
	}

	signedAt := time.Now().UnixNano()
	entry, index := anchorSeal(key, *anchor, *rekorURL, id, w, signedAt)

	foot, err := w.Seal(key, signedAt, entry, index)
	if err != nil {
		return err
	}
	sealed = true

	fmt.Fprintf(os.Stderr, "\nhark: wrote %s\n", bundlePath)
	fmt.Fprintf(os.Stderr, "  events %d\n", foot.LeafCount)
	fmt.Fprintf(os.Stderr, "  root   %x\n", foot.Root)
	if entry != "" {
		fmt.Fprintf(os.Stderr, "  anchor %s (index %d)\n", entry, index)
	}
	if medErr != nil {
		fmt.Fprintf(os.Stderr, "  mediator: %v\n", medErr)
	}

	// The agent's exit code is the command's result, so it becomes ours --
	// returned rather than exited, so the deferred cleanup still runs.
	if code != 0 {
		return exitError{code}
	}
	return nil
}

// anchorSeal submits the tree head about to be sealed, and returns the entry
// reference to store in the footer.
//
// The signature is produced here and again inside Seal. Ed25519 is
// deterministic and the inputs are identical, so both are the same signature --
// which is what lets the anchor be obtained before the footer that has to carry
// it.
//
// Every failure path is non-fatal and says what happened. Rekor being down must
// never mean a run cannot be recorded: the bundle is already complete and
// internally verifiable by this point, and the anchor is the part that adds
// non-equivocation on top.
func anchorSeal(key *signer.Key, want bool, logURL, runID string, w *bundle.Writer, signedAt int64) (string, int64) {
	if !want || key == nil {
		return "", 0
	}

	sth := key.Sign(runID, w.LeafCount(), w.Root(), signedAt)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	entry, err := rekor.New(logURL).Anchor(ctx, sth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hark: not anchored: %v\n", err)
		fmt.Fprintln(os.Stderr, "  the bundle is sealed and verifiable; it simply carries no public commitment")
		return "", 0
	}
	return entry.UUID, entry.LogIndex
}

// buildEnv assembles the agent's environment: the supervisor's, with the
// placeholder credentials and this run's CA *replacing* anything of the same
// name rather than being appended after it.
//
// Replacing is the whole point, and getting it wrong is not a subtle bug.
// Appending looks equivalent because most tools take the last value of a
// duplicated variable -- but CPython's convertenviron keeps the *first*, so an
// operator running `API_KEY=... hark run` handed the agent the real credential,
// which then travelled into the bundle. The demo caught it on its first
// complete run.
//
// The same hazard applies to the trust-store variables: an inherited
// SSL_CERT_FILE would win over this run's CA and the agent would fail its
// handshake against a mediator it had no reason to trust.
//
// Three CA variables rather than one because there is no single convention --
// OpenSSL, Python's requests, and Node each read a different name.
func buildEnv(placeholders map[string]string, caPath string) []string {
	ours := make(map[string]string, len(placeholders)+4)
	for k, v := range placeholders {
		ours[k] = v
	}
	for _, k := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"} {
		ours[k] = caPath
	}

	env := make([]string, 0, len(os.Environ())+len(ours))
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if ok {
			if _, replaced := ours[name]; replaced {
				continue
			}
		}
		env = append(env, kv)
	}

	// Sorted, so two runs of the same agent differ in the values of these
	// variables and not in their order.
	names := make([]string, 0, len(ours))
	for k := range ours {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		env = append(env, k+"="+ours[k])
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

	// leaked names the secret an event was found to carry, if one ever was.
	leaked string
}

func (r *recorder) Append(kind logfmt.Kind, payload any) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.appendLocked(kind, payload)
}

// appendLocked writes one event, with the ordering lock already held. Separate
// so a fork's recorder can observe the same event without taking the lock twice
// or skipping the check below.
func (r *recorder) appendLocked(kind logfmt.Kind, payload any) (uint64, error) {
	// The last line of defence, and it should never fire.
	//
	// Substitution already happens on copies, so a real credential has no path
	// into the log -- which is exactly why this is worth checking. A bundle is
	// meant to be handed to a reviewer and anchored in a public log, and a
	// silent leak into one is not a failure anyone notices in time. It fired for
	// real once, on the demo's first complete run, when the agent turned out to
	// be holding the operator's own credential.
	//
	// The event is dropped rather than written, and the run is failed at the
	// end. Refusing to seal beats sealing something that cannot be shared.
	if r.br != nil {
		if body, err := logfmt.Marshal(payload); err == nil {
			if ref, found := r.br.ContainsSecret(body); found {
				if r.leaked == "" {
					r.leaked = ref
					fmt.Fprintf(os.Stderr,
						"\nhark: refusing to log a %s event: it carries the real value of %q\n"+
							"  this is a bug in hark, not in the agent. The run will not be sealed.\n",
						kind, ref)
				}
				return 0, fmt.Errorf("recorder: %s event carries the real value of %q", kind, ref)
			}
		}
	}

	return r.w.Append(kind, uint64(time.Since(r.start).Nanoseconds()), payload)
}

// Leaked reports the secret a payload was found to carry, or "".
func (r *recorder) Leaked() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.leaked
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
