//go:build linux

package launcher

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Landlock enforcement cannot be tested in-process: restrict_self is
// irreversible for the calling thread, so the first test would restrict the test
// binary and every later test would run inside that domain.
//
// So the tests re-execute this binary as a helper, apply a ruleset there, and
// attempt one filesystem operation. The exit code carries the answer. That also
// makes the test measure the thing that matters -- whether the kernel actually
// refused -- rather than whether a syscall returned zero.

const (
	exitOperationAllowed = 0
	exitOperationDenied  = 1
	exitApplyFailed      = 3
)

func TestMain(m *testing.M) {
	// Launch re-executes /proc/self/exe, which under `go test` is this binary.
	// Handling the sentinel here is what lets the launcher be tested at all.
	if IsInit(os.Args) {
		if err := Init(); err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			os.Exit(126)
		}
		os.Exit(127)
	}

	switch os.Getenv("HARK_HELPER") {
	case "landlock":
		landlockHelper()
		return
	case "seccomp":
		seccompHelper()
		return
	case "caps":
		capsHelper()
		return
	}
	os.Exit(m.Run())
}

func landlockHelper() {
	// Required: the domain is installed on this thread and execve or the
	// subsequent syscalls must happen on it too.
	runtime.LockOSThread()

	var rules []FSRule
	for _, p := range filepath.SplitList(os.Getenv("HARK_RO")) {
		if p != "" {
			rules = append(rules, FSRule{Path: p})
		}
	}
	for _, p := range filepath.SplitList(os.Getenv("HARK_RW")) {
		if p != "" {
			rules = append(rules, FSRule{Path: p, Write: true})
		}
	}

	if err := ApplyFilesystem(rules); err != nil {
		fmt.Fprintln(os.Stderr, "apply:", err)
		os.Exit(exitApplyFailed)
	}

	target := os.Getenv("HARK_TARGET")
	var err error
	switch os.Getenv("HARK_OP") {
	case "read":
		_, err = os.ReadFile(target)
	case "write":
		err = os.WriteFile(target, []byte("written"), 0o600)
	case "create":
		err = os.WriteFile(filepath.Join(target, "new.txt"), []byte("x"), 0o600)
	default:
		fmt.Fprintln(os.Stderr, "unknown op")
		os.Exit(4)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "operation:", err)
		os.Exit(exitOperationDenied)
	}
	os.Exit(exitOperationAllowed)
}

// runLandlock executes the helper and returns its exit code.
func runLandlock(t *testing.T, ro, rw []string, op, target string) int {
	t.Helper()

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"HARK_HELPER=landlock",
		"HARK_RO="+strings.Join(ro, string(filepath.ListSeparator)),
		"HARK_RW="+strings.Join(rw, string(filepath.ListSeparator)),
		"HARK_OP="+op,
		"HARK_TARGET="+target,
	)
	out, err := cmd.CombinedOutput()

	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ExitCode() == exitApplyFailed {
			t.Fatalf("applying the ruleset failed: %s", out)
		}
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatalf("running helper: %v: %s", err, out)
	}
	return exitOperationAllowed
}

func TestABIIsSupported(t *testing.T) {
	abi, err := ABI()
	if err != nil {
		t.Skipf("Landlock unavailable here: %v", err)
	}
	t.Logf("Landlock ABI version %d", abi)
	if abi < MinABI {
		t.Fatalf("kernel ABI %d is below the required minimum %d", abi, MinABI)
	}
}

func requireLandlock(t *testing.T) {
	t.Helper()
	if _, err := ABI(); err != nil {
		t.Skipf("Landlock unavailable here: %v", err)
	}
}

// The property the whole containment story rests on: a path that was not
// granted is unreadable, no matter that the process owns it.
func TestUngrantedPathIsUnreadable(t *testing.T) {
	requireLandlock(t)

	allowed := t.TempDir()
	secret := filepath.Join(t.TempDir(), "bundle.hark")
	if err := os.WriteFile(secret, []byte("the audit log"), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := runLandlock(t, []string{allowed}, nil, "read", secret); code != exitOperationDenied {
		t.Fatalf("read a file outside every granted path (exit %d)", code)
	}
}

func TestGrantedPathIsReadable(t *testing.T) {
	requireLandlock(t)

	dir := t.TempDir()
	f := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := runLandlock(t, []string{dir}, nil, "read", f); code != exitOperationAllowed {
		t.Fatalf("could not read a file inside a granted path (exit %d)", code)
	}
}

// Read-only must genuinely mean read-only. Granting the workspace read access
// and having writes silently succeed would be the quiet kind of failure.
func TestReadOnlyPathRejectsWrites(t *testing.T) {
	requireLandlock(t)

	dir := t.TempDir()
	f := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := runLandlock(t, []string{dir}, nil, "write", f); code != exitOperationDenied {
		t.Fatalf("wrote to a read-only path (exit %d)", code)
	}
}

func TestWritablePathAcceptsWrites(t *testing.T) {
	requireLandlock(t)

	dir := t.TempDir()
	if code := runLandlock(t, nil, []string{dir}, "create", dir); code != exitOperationAllowed {
		t.Fatalf("could not create a file in a writable path (exit %d)", code)
	}
}

// The arrangement a real run uses: read-only source, writable scratch, and an
// audit log the agent was never told about.
func TestRealisticLayout(t *testing.T) {
	requireLandlock(t)

	app := t.TempDir()
	work := t.TempDir()
	logDir := t.TempDir()

	src := filepath.Join(app, "agent.py")
	if err := os.WriteFile(src, []byte("print('hi')"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(logDir, "run.hark")
	if err := os.WriteFile(bundle, []byte("HARK\x01"), 0o600); err != nil {
		t.Fatal(err)
	}

	ro, rw := []string{app}, []string{work}

	if code := runLandlock(t, ro, rw, "read", src); code != exitOperationAllowed {
		t.Fatalf("agent could not read its own source (exit %d)", code)
	}
	if code := runLandlock(t, ro, rw, "create", work); code != exitOperationAllowed {
		t.Fatalf("agent could not write to its workspace (exit %d)", code)
	}
	if code := runLandlock(t, ro, rw, "write", src); code != exitOperationDenied {
		t.Fatalf("agent modified its own read-only source (exit %d)", code)
	}
	if code := runLandlock(t, ro, rw, "read", bundle); code != exitOperationDenied {
		t.Fatalf("agent read the audit log it is being recorded into (exit %d)", code)
	}
	if code := runLandlock(t, ro, rw, "write", bundle); code != exitOperationDenied {
		t.Fatalf("agent wrote to the audit log it is being recorded into (exit %d)", code)
	}
}

// An empty ruleset denies everything rather than allowing everything. Getting
// this backwards would make a misconfigured policy maximally permissive.
func TestEmptyRulesetDeniesEverything(t *testing.T) {
	requireLandlock(t)

	f := filepath.Join(t.TempDir(), "x.txt")
	if err := os.WriteFile(f, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := runLandlock(t, nil, nil, "read", f); code != exitOperationDenied {
		t.Fatalf("an empty ruleset allowed a read (exit %d)", code)
	}
}

func TestApplyRejectsMissingPath(t *testing.T) {
	requireLandlock(t)

	err := ApplyFilesystem([]FSRule{{Path: "/definitely/not/here"}})
	if err == nil {
		t.Fatal("accepted a rule naming a path that does not exist")
	}
	if !strings.Contains(err.Error(), "not/here") {
		t.Fatalf("error should name the offending path, got: %v", err)
	}
}
