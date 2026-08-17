package shim

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

// A forked run consumes the recording up to its fork point and draws for real
// after it. The switch is the supervisor's to make -- it is the side that knows
// how far the verified prefix got -- but the value has to be produced in the
// agent's own process, so the reply says "live" and expects one back.
//
// Driven over the socket rather than through an interpreter, so it runs
// everywhere. The Python half is exercised by TestForkAgentDrawsLiveValues.
func TestForkServesTheRecordingUntilTheGateOpens(t *testing.T) {
	rec := &capture{}
	var live atomic.Bool

	s := start(t, ModeFork, rec, Values{
		"random.random": {json.RawMessage("0.25"), json.RawMessage("0.75")},
	})
	s.Live = live.Load

	c := dialShim(t, s)

	if got := c.call(t, request{Op: "get", Src: "random.random"}); string(got.Val) != "0.25" {
		t.Fatalf("below the fork point the recording is the authority, got %s", got.Val)
	}

	live.Store(true)

	got := c.call(t, request{Op: "get", Src: "random.random"})
	if !got.Live {
		t.Fatalf("past the fork point the agent must draw for real, got %s", got.Val)
	}
	if len(got.Val) != 0 {
		t.Fatalf("a live reply must not also carry a value: %s", got.Val)
	}
	if reply := c.call(t, request{Op: "rec", Src: "random.random", Val: json.RawMessage("0.9")}); !reply.OK {
		t.Fatalf("the live value was refused: %s", reply.Err)
	}

	// Two values reached the agent and both are in the log -- the one served from
	// the recording and the one it drew itself. A fork's suffix is a recording in
	// its own right, and its prefix has to replay again.
	if got := len(rec.all()); got != 2 {
		t.Fatalf("recorded %d events, expected 2", got)
	}

	// The unconsumed recorded value belongs to the run that was, not to the one
	// being explored, so it stays in the queue rather than being served later.
	if got := s.Remaining()["random.random"]; got != 1 {
		t.Fatalf("%d recorded values left, expected 1", got)
	}
}

// shimClient speaks the newline-delimited JSON protocol directly.
type shimClient struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialShim(t *testing.T, s *Server) *shimClient {
	t.Helper()
	conn, err := net.Dial("unix", s.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &shimClient{conn: conn, r: bufio.NewReader(conn)}
}

func (c *shimClient) call(t *testing.T, req request) reply {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.conn.Write(append(body, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var rep reply
	if err := json.Unmarshal(line, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

// The Python half of the same handover: the recorded value comes back below the
// fork point, and a real one is drawn and logged above it.
func TestForkAgentDrawsLiveValues(t *testing.T) {
	rec := &capture{}

	s := start(t, ModeFork, rec, Values{
		"random.random": {json.RawMessage("0.125")},
	})
	// The gate opens after the first draw. In a real fork it opens on the event
	// count reaching the fork point; here counting the reads is equivalent and
	// keeps the test to one moving part.
	reads := 0
	s.Live = func() bool { reads++; return reads > 1 }

	out, err := runAgent(t, s, `
import random
print("a=%r" % random.random())
print("b=%r" % random.random())
`)
	// runAgent skips on a machine without a usable interpreter, so anything
	// reaching here ran the code.
	if err != nil {
		t.Fatalf("forked agent failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, "a=0.125") {
		t.Fatalf("the prefix draw did not come from the recording:\n%s", out)
	}
	if strings.Count(out, "0.125") != 1 {
		t.Fatalf("the recording was served past the fork point:\n%s", out)
	}
	if got := len(rec.all()); got != 2 {
		t.Fatalf("recorded %d draws, expected 2 -- the live one must be logged too", got)
	}
}

// Some patched functions are implemented in terms of others: uuid.uuid4 calls
// os.urandom underneath.
//
// Without a re-entrancy guard, recording captures both the inner draw and the
// outer result while replay serves only the outer one from its own queue, so the
// queues drift apart and a later os.urandom is answered with bytes recorded for
// the uuid. The replay then reports success while the agent sees a value it
// never saw -- which is the exact failure this project exists to prevent.
//
// This regressed once, caught the first time the shim was run against a real
// interpreter rather than reasoned about.
func TestNestedCaptureDoesNotDesynchronise(t *testing.T) {
	const code = `
import os, uuid
print("u=%s" % uuid.uuid4())
print("x=%s" % os.urandom(8).hex())
print("u2=%s" % uuid.uuid4())
print("x2=%s" % os.urandom(4).hex())
`
	rec := &capture{}
	recServer := start(t, ModeRecord, rec, nil)

	first, err := runAgent(t, recServer, code)
	if err != nil {
		t.Fatalf("recording failed: %v\n%s", err, first)
	}

	// One value per outermost call, not one per underlying draw.
	snap := recServer.snapshot()
	if got := len(snap["uuid.uuid4"]); got != 2 {
		t.Fatalf("recorded %d uuid values, expected 2", got)
	}
	if got := len(snap["os.urandom"]); got != 2 {
		t.Fatalf("recorded %d urandom values, expected 2 -- uuid4's internal draw leaked in", got)
	}

	replayServer := start(t, ModeReplay, nil, snap)
	second, err := runAgent(t, replayServer, code)
	if err != nil {
		t.Fatalf("replay failed: %v\n%s", err, second)
	}
	if first != second {
		t.Fatalf("nested capture desynchronised.\n--- recorded ---\n%s\n--- replayed ---\n%s", first, second)
	}
}
