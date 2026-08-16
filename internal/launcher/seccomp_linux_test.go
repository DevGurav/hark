//go:build linux

package launcher

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// Like Landlock, a seccomp filter cannot be undone, so enforcement is measured
// in a helper subprocess rather than in the test binary.

const (
	exitSyscallAllowed = 0
	exitSyscallDenied  = 1
	exitSetupFailed    = 3
	exitCapsHeld       = 5
	exitCapsClear      = 6
)

func seccompHelper() {
	runtime.LockOSThread()

	if err := ApplySeccomp(); err != nil {
		fmt.Fprintln(os.Stderr, "apply:", err)
		os.Exit(exitSetupFailed)
	}

	var err error
	switch os.Getenv("HARK_SYSCALL") {
	case "unshare":
		err = unix.Unshare(unix.CLONE_NEWNS)
	case "ptrace":
		_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_TRACEME), 0, 0, 0, 0, 0)
		if errno != 0 {
			err = errno
		}
	case "setns":
		_, _, errno := unix.Syscall(unix.SYS_SETNS, 0, 0, 0)
		if errno != 0 {
			err = errno
		}
	case "getpid":
		// A syscall with no business being blocked. If this fails, the filter is
		// denying far more than it was asked to.
		if unix.Getpid() <= 0 {
			err = errors.New("getpid returned nonsense")
		}
	case "openfile":
		// Ordinary work must keep working: a filter that breaks file IO would
		// stop every agent regardless of what it was trying to do.
		f, e := os.CreateTemp("", "hark-seccomp-*")
		if e != nil {
			err = e
		} else {
			_, err = f.WriteString("ok")
			f.Close()
			os.Remove(f.Name())
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown syscall selector")
		os.Exit(4)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "syscall:", err)
		os.Exit(exitSyscallDenied)
	}
	os.Exit(exitSyscallAllowed)
}

func capsHelper() {
	runtime.LockOSThread()

	if err := DropCapabilities(); err != nil {
		fmt.Fprintln(os.Stderr, "drop:", err)
		os.Exit(exitSetupFailed)
	}
	held, err := HasCapabilities()
	if err != nil {
		fmt.Fprintln(os.Stderr, "check:", err)
		os.Exit(exitSetupFailed)
	}
	if held {
		os.Exit(exitCapsHeld)
	}
	os.Exit(exitCapsClear)
}

func runHelper(t *testing.T, mode string, env ...string) (int, string) {
	t.Helper()

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), append([]string{"HARK_HELPER=" + mode}, env...)...)
	out, err := cmd.CombinedOutput()

	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("running helper: %v: %s", err, out)
	}
	return 0, string(out)
}

// The syscalls worth blocking are blocked.
func TestSeccompDeniesDangerousSyscalls(t *testing.T) {
	for _, sc := range []string{"unshare", "ptrace", "setns"} {
		t.Run(sc, func(t *testing.T) {
			code, out := runHelper(t, "seccomp", "HARK_SYSCALL="+sc)
			if code == exitSetupFailed {
				t.Fatalf("installing the filter failed: %s", out)
			}
			if code != exitSyscallDenied {
				t.Fatalf("%s was permitted (exit %d)\n%s", sc, code, out)
			}
		})
	}
}

// And nothing else is. A filter that blocks ordinary work would stop every
// agent, which is a far more likely failure than one that blocks too little.
func TestSeccompAllowsOrdinaryWork(t *testing.T) {
	for _, sc := range []string{"getpid", "openfile"} {
		t.Run(sc, func(t *testing.T) {
			code, out := runHelper(t, "seccomp", "HARK_SYSCALL="+sc)
			if code != exitSyscallAllowed {
				t.Fatalf("%s was denied (exit %d)\n%s", sc, code, out)
			}
		})
	}
}

func TestCapabilitiesAreDropped(t *testing.T) {
	code, out := runHelper(t, "caps")
	switch code {
	case exitCapsClear:
		// Expected.
	case exitCapsHeld:
		t.Fatalf("capabilities survived the drop\n%s", out)
	case exitSetupFailed:
		t.Fatalf("dropping capabilities failed: %s", out)
	default:
		t.Fatalf("unexpected exit %d\n%s", code, out)
	}
}

// The filter's shape, checked without installing it: architecture validation
// first, one comparison per denied syscall, then allow, then deny.
func TestFilterLayout(t *testing.T) {
	denied := deniedSyscalls()
	prog, err := buildFilter(denied)
	if err != nil {
		t.Fatal(err)
	}

	const preamble = 4 // load arch, compare, kill, load nr
	want := preamble + len(denied) + 2
	if len(prog) != want {
		t.Fatalf("filter has %d instructions, expected %d", len(prog), want)
	}

	if prog[0].code != bpfLD|bpfW|bpfABS || prog[0].k != offsetArch {
		t.Fatal("filter does not begin by loading the architecture")
	}
	if prog[2].k != retKillProcess {
		t.Fatal("an architecture mismatch is not fatal")
	}
	if prog[3].k != offsetNR {
		t.Fatal("the syscall number is not loaded before the comparisons")
	}

	// Every comparison must land exactly on the deny instruction.
	denyIndex := len(prog) - 1
	for i := range denied {
		pos := preamble + i
		target := pos + 1 + int(prog[pos].jt)
		if target != denyIndex {
			t.Fatalf("comparison %d jumps to instruction %d, deny is at %d", i, target, denyIndex)
		}
	}

	if prog[denyIndex-1].k != retAllow {
		t.Fatal("the fall-through action is not allow")
	}
	if prog[denyIndex].k != retErrno|uint32(unix.EPERM) {
		t.Fatal("the deny action is not EPERM")
	}
}

// Pinning the architecture is what stops a 32-bit syscall on x86_64 being used
// to reach a different call under a number the filter thinks it knows.
func TestFilterPinsArchitecture(t *testing.T) {
	arch, err := auditArch()
	if err != nil {
		t.Skip(err)
	}
	prog, err := buildFilter([]int{unix.SYS_PTRACE})
	if err != nil {
		t.Fatal(err)
	}
	if prog[1].k != arch {
		t.Fatalf("filter compares against 0x%X, expected 0x%X", prog[1].k, arch)
	}
}

func TestFilterRejectsOversizedDenylist(t *testing.T) {
	huge := make([]int, 300)
	if _, err := buildFilter(huge); err == nil {
		t.Fatal("accepted a denylist too long for single-byte jump offsets")
	}
}
