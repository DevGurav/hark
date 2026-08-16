//go:build linux

package launcher

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Seccomp syscall filtering.
//
// The namespace already means the agent has nowhere to send a packet, and
// Landlock already means it has nothing to read. Seccomp closes a third door:
// syscalls that manipulate the sandbox itself, or reach into other processes.
//
// This is defence in depth rather than the primary control. Most of what is
// denied here also requires a capability the child will not hold. The exceptions
// are the ones worth having: ptrace and process_vm_readv work between processes
// of the same user with no capability at all, so an agent could otherwise read
// the memory of anything else that user is running.
//
// The filter is hand-assembled classic BPF. libseccomp would mean cgo and a
// system library on every build host, for a filter this size.

// Classic BPF opcodes, from linux/bpf_common.h.
const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfK   = 0x00
	bpfRET = 0x06
)

// seccomp_data field offsets, from linux/seccomp.h.
const (
	offsetNR   = 0
	offsetArch = 4
)

// Filter return actions.
const (
	retKillProcess = 0x80000000
	retErrno       = 0x00050000
	retAllow       = 0x7fff0000
)

type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// sockFprog mirrors struct sock_fprog. Go inserts the same padding between the
// length and the pointer that C does on a 64-bit target, so the layouts match.
type sockFprog struct {
	length uint16
	filter *sockFilter
}

// deniedSyscalls have no legitimate place in an agent and meaningful value to an
// attacker. Named rather than numbered because syscall numbers differ per
// architecture; unix.SYS_* resolves them for the target being built.
func deniedSyscalls() []int {
	return []int{
		// Reading or controlling other processes. These need no capability
		// between processes of the same user, which makes them the most valuable
		// entries here.
		unix.SYS_PTRACE,
		unix.SYS_PROCESS_VM_READV,
		unix.SYS_PROCESS_VM_WRITEV,

		// Rearranging the sandbox.
		unix.SYS_MOUNT,
		unix.SYS_UMOUNT2,
		unix.SYS_PIVOT_ROOT,
		unix.SYS_CHROOT,
		unix.SYS_SETNS,
		unix.SYS_UNSHARE,

		// open_by_handle_at resolves a file handle without a path, which has
		// been the basis of more than one container escape.
		unix.SYS_OPEN_BY_HANDLE_AT,

		// Kernel manipulation.
		unix.SYS_INIT_MODULE,
		unix.SYS_FINIT_MODULE,
		unix.SYS_DELETE_MODULE,
		unix.SYS_KEXEC_LOAD,
		unix.SYS_BPF,
		unix.SYS_PERF_EVENT_OPEN,

		// Kernel keyring: a credential store the agent has no business in.
		unix.SYS_ADD_KEY,
		unix.SYS_REQUEST_KEY,
		unix.SYS_KEYCTL,

		// Host-level operations.
		unix.SYS_REBOOT,
		unix.SYS_SWAPON,
		unix.SYS_SWAPOFF,
	}
}

// auditArch returns the AUDIT_ARCH_* value for the architecture this binary was
// built for.
//
// Checking it is not decoration. On x86_64 a process can issue 32-bit syscalls,
// where the numbers mean entirely different things — so a filter that matched
// numbers without pinning the architecture could be bypassed by making the same
// call through the other ABI.
func auditArch() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return 0xC000003E, nil // AUDIT_ARCH_X86_64
	case "arm64":
		return 0xC00000B7, nil // AUDIT_ARCH_AARCH64
	default:
		return 0, fmt.Errorf("seccomp: no audit arch known for GOARCH %q", runtime.GOARCH)
	}
}

// buildFilter assembles the program.
//
//	if arch != expected      -> kill
//	if nr in denied          -> EPERM
//	otherwise                -> allow
func buildFilter(denied []int) ([]sockFilter, error) {
	arch, err := auditArch()
	if err != nil {
		return nil, err
	}

	prog := []sockFilter{
		// Load the architecture and refuse anything unexpected outright. A
		// mismatch here is not a mistake, so it is killed rather than refused.
		{code: bpfLD | bpfW | bpfABS, k: offsetArch},
		{code: bpfJMP | bpfJEQ | bpfK, jt: 1, jf: 0, k: arch},
		{code: bpfRET | bpfK, k: retKillProcess},

		// Load the syscall number for the comparisons that follow.
		{code: bpfLD | bpfW | bpfABS, k: offsetNR},
	}

	// Each comparison jumps forward to the deny instruction. After check i of n
	// there are (n-1-i) checks left plus the allow instruction, so the deny sits
	// n-i instructions ahead of the next one.
	n := len(denied)
	for i, nr := range denied {
		prog = append(prog, sockFilter{
			code: bpfJMP | bpfJEQ | bpfK,
			jt:   uint8(n - i),
			jf:   0,
			k:    uint32(nr),
		})
	}

	prog = append(prog,
		sockFilter{code: bpfRET | bpfK, k: retAllow},
		// EPERM rather than kill. A denied syscall becomes an ordinary error the
		// runtime can report, instead of a process that vanishes and leaves
		// whoever is debugging it with nothing. The call is refused either way.
		sockFilter{code: bpfRET | bpfK, k: retErrno | uint32(unix.EPERM)},
	)

	if n > 250 {
		// Jump offsets are a single byte, so a longer denylist would need the
		// program restructured. Far from the limit today; worth failing loudly
		// rather than emitting a filter with wrapped offsets.
		return nil, fmt.Errorf("seccomp: %d denied syscalls exceeds what single-byte jumps can address", n)
	}
	return prog, nil
}

// ApplySeccomp installs the filter on the calling thread.
//
// Like Landlock, this applies per-thread and is inherited across execve, so it
// must run with runtime.LockOSThread held and be followed by exec on that same
// thread.
func ApplySeccomp() error {
	prog, err := buildFilter(deniedSyscalls())
	if err != nil {
		return err
	}

	// The kernel refuses a filter from an unprivileged caller unless NO_NEW_PRIVS
	// is set. ApplyFilesystem also sets it, and setting it twice is harmless --
	// doing it here as well removes an ordering dependency between the two, which
	// is the kind of coupling that breaks quietly when someone reorders the init
	// sequence later.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("seccomp: setting NO_NEW_PRIVS: %w", err)
	}

	fprog := sockFprog{
		length: uint16(len(prog)),
		filter: &prog[0],
	}

	_, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER), 0,
		uintptr(unsafe.Pointer(&fprog)))
	// Keep the program alive until the kernel has copied it in; without this the
	// collector would be free to move or reclaim it mid-call.
	runtime.KeepAlive(prog)
	runtime.KeepAlive(fprog)

	if errno != 0 {
		return fmt.Errorf("seccomp: installing filter: %w", errno)
	}
	return nil
}
