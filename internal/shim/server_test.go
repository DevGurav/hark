package shim

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevGurav/hark/internal/logfmt"
)

// capture is a Recorder that keeps events in memory.
type capture struct {
	mu     sync.Mutex
	events []any
}

func (c *capture) Append(kind logfmt.Kind, payload any) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, payload)
	return uint64(len(c.events) - 1), nil
}

func (c *capture) all() []any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]any(nil), c.events...)
}

func start(t *testing.T, mode Mode, rec Recorder, recorded Values) *Server {
	t.Helper()

	// Socket paths are capped near 108 bytes, and t.TempDir() on some systems is
	// long enough to matter.
	dir, err := os.MkdirTemp("", "hark-shim-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	s, err := New(dir, mode, rec, recorded)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { s.Close() })

	// Wait for the socket rather than sleeping.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(s.Path()); err == nil {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the shim socket never appeared")
	return nil
}

// python reports a working interpreter, or skips.
//
// LookPath is not enough on Windows, where the Microsoft Store ships an "app
// execution alias" -- a real file named python.exe that exists, resolves, and
// then prints an advertisement instead of running anything. The interpreter has
// to be probed.
func python(t *testing.T) string {
	t.Helper()
	// hark is Linux-only, and so is the shim: it speaks AF_UNIX, which Python
	// does not expose on Windows. Skipping keeps the rest of the suite runnable
	// on a development machine.
	if runtime.GOOS != "linux" {
		t.Skip("the shim needs a Linux interpreter with AF_UNIX")
	}
	for _, name := range []string{"python3", "python"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		out, err := exec.Command(p, "-c", "print('hark-probe')").CombinedOutput()
		if err == nil && strings.Contains(string(out), "hark-probe") {
			return p
		}
	}
	t.Skip("no working python interpreter available")
	return ""
}

// runAgent executes a snippet with the shim installed.
func runAgent(t *testing.T, s *Server, code string) (string, error) {
	t.Helper()

	py := python(t)
	shimDir, err := filepath.Abs(filepath.Join("..", "..", "shim"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(shimDir, "sitecustomize.py")); err != nil {
		t.Fatalf("shim not found at %s: %v", shimDir, err)
	}

	cmd := exec.Command(py, "-c", code)
	cmd.Env = append(os.Environ(), s.Env(shimDir)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// The end-to-end property: a snippet reading the clock and drawing randomness
// produces identical output when replayed.
func TestRecordThenReplayReproducesOutput(t *testing.T) {
	const code = `
import time, random, os, uuid
print("t=%r" % time.time())
print("m=%r" % time.monotonic())
print("r=%r" % random.random())
print("i=%d" % random.randint(1, 1000000))
print("u=%s" % uuid.uuid4())
print("x=%s" % os.urandom(8).hex())
`

	rec := &capture{}
	recServer := start(t, ModeRecord, rec, nil)

	first, err := runAgent(t, recServer, code)
	if err != nil {
		t.Fatalf("recording run failed: %v\n%s", err, first)
	}
	if !strings.Contains(first, "t=") {
		t.Fatalf("unexpected output: %s", first)
	}

	// Everything the agent read is now queued on the server; hand it to a
	// replaying one.
	replayServer := start(t, ModeReplay, nil, recServer.snapshot())

	second, err := runAgent(t, replayServer, code)
	if err != nil {
		t.Fatalf("replay run failed: %v\n%s", err, second)
	}

	if first != second {
		t.Fatalf("replay diverged.\n--- recorded ---\n%s\n--- replayed ---\n%s", first, second)
	}
}

// randint and choice are bound methods of a hidden Random instance, so patching
// random.random alone leaves them drawing from the unpatched generator.
func TestModuleLevelHelpersArePatched(t *testing.T) {
	const code = `
import random
print(random.randint(1, 10**9))
print(random.choice(list(range(1000))))
`
	rec := &capture{}
	recServer := start(t, ModeRecord, rec, nil)

	first, err := runAgent(t, recServer, code)
	if err != nil {
		t.Fatalf("recording failed: %v\n%s", err, first)
	}

	replayServer := start(t, ModeReplay, nil, recServer.snapshot())
	second, err := runAgent(t, replayServer, code)
	if err != nil {
		t.Fatalf("replay failed: %v\n%s", err, second)
	}
	if first != second {
		t.Fatalf("module-level helpers were not captured.\nrecorded: %s\nreplayed: %s", first, second)
	}
}

func TestClockAndRandomAreRecordedAsEvents(t *testing.T) {
	rec := &capture{}
	s := start(t, ModeRecord, rec, nil)

	if out, err := runAgent(t, s, "import time, random\ntime.time()\nrandom.random()\n"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}

	var clocks, randoms int
	for _, e := range rec.all() {
		switch v := e.(type) {
		case logfmt.ClockRead:
			clocks++
			if v.Source == "" {
				t.Fatal("a clock read was recorded with no source")
			}
		case logfmt.RandomRead:
			randoms++
		}
	}
	if clocks == 0 || randoms == 0 {
		t.Fatalf("expected both kinds recorded, got %d clock and %d random", clocks, randoms)
	}
}

// A replay that asks for more randomness than was recorded has taken a
// different path. Inventing a value would let it report success over a run that
// did something else.
func TestReplayRefusesWhenTheRecordingRunsOut(t *testing.T) {
	s := start(t, ModeReplay, nil, Values{
		"random.random": {json.RawMessage("0.5")},
	})

	out, err := runAgent(t, s, "import random\nprint(random.random())\nprint(random.random())\n")
	if err == nil {
		t.Fatalf("a divergent replay succeeded:\n%s", out)
	}
	if !strings.Contains(out, "diverged") {
		t.Fatalf("the failure should say the run diverged:\n%s", out)
	}
	if !strings.Contains(out, "0.5") {
		t.Fatalf("the first draw should still have been served:\n%s", out)
	}
}

// The shim must not silently continue when it cannot reach the supervisor. A
// recording that looks complete and can never replay is the failure nobody
// notices until they need it.
func TestShimFailsLoudlyWithoutASupervisor(t *testing.T) {
	py := python(t)
	shimDir, _ := filepath.Abs(filepath.Join("..", "..", "shim"))

	cmd := exec.Command(py, "-c", "import time; print(time.time())")
	cmd.Env = append(os.Environ(),
		"HARK_SHIM_SOCKET="+filepath.Join(t.TempDir(), "nonexistent.sock"),
		"HARK_SHIM_MODE=record",
		"PYTHONPATH="+shimDir,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the agent ran without a supervisor:\n%s", out)
	}
	if !strings.Contains(string(out), "cannot reach the supervisor") {
		t.Fatalf("unhelpful failure:\n%s", out)
	}
}

// Without the environment set the shim must do nothing at all, so an unrelated
// Python process on the same machine is unaffected.
func TestShimIsInertWithoutConfiguration(t *testing.T) {
	py := python(t)
	shimDir, _ := filepath.Abs(filepath.Join("..", "..", "shim"))

	cmd := exec.Command(py, "-c", "import time; print('ran', time.time() > 0)")
	cmd.Env = append(os.Environ(), "PYTHONPATH="+shimDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("an unconfigured shim broke the interpreter: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ran True") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestEnvPinsHashSeed(t *testing.T) {
	s := start(t, ModeRecord, &capture{}, nil)
	var found bool
	for _, kv := range s.Env("/somewhere") {
		if kv == "PYTHONHASHSEED=0" {
			found = true
		}
	}
	if !found {
		// Set iteration order varies per process without it, and dict ordering
		// leaks into prompt construction more often than people expect.
		t.Fatal("PYTHONHASHSEED is not pinned")
	}
}

func TestNewRejectsBadMode(t *testing.T) {
	if _, err := New(t.TempDir(), "sideways", &capture{}, nil); err == nil {
		t.Fatal("accepted an unknown mode")
	}
	if _, err := New(t.TempDir(), ModeRecord, nil, nil); err == nil {
		t.Fatal("accepted recording with no recorder")
	}
}
