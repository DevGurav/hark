//go:build linux

package launcher

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock filesystem scoping.
//
// Landlock is what stops the agent reading files outside its workspace, and --
// the property that matters most -- reaching the bundle it is being recorded
// into. The kernel enforces it, so a compromised agent cannot lift it.
//
// # Why ABI negotiation is not optional
//
// Access rights were added over successive kernel releases. A ruleset asking for
// a right the running kernel does not know is rejected outright with EINVAL, so
// the requested set has to be masked down to what this kernel actually supports.
//
// The failure mode to avoid is the tempting one: catch the error, carry on
// unrestricted, log a warning. That produces a process that looks contained and
// is not, which is worse than refusing to start. Apply returns an error and the
// caller aborts the run.

// Filesystem access rights, from linux/landlock.h. These are ABI values and
// never change.
const (
	fsExecute    = 1 << 0
	fsWriteFile  = 1 << 1
	fsReadFile   = 1 << 2
	fsReadDir    = 1 << 3
	fsRemoveDir  = 1 << 4
	fsRemoveFile = 1 << 5
	fsMakeChar   = 1 << 6
	fsMakeDir    = 1 << 7
	fsMakeReg    = 1 << 8
	fsMakeSock   = 1 << 9
	fsMakeFifo   = 1 << 10
	fsMakeBlock  = 1 << 11
	fsMakeSym    = 1 << 12
	fsRefer      = 1 << 13 // ABI 2
	fsTruncate   = 1 << 14 // ABI 3
	fsIoctlDev   = 1 << 15 // ABI 5

	ruleTypePathBeneath = 1

	// createRulesetVersion asks landlock_create_ruleset to report the ABI
	// version instead of creating anything.
	createRulesetVersion = 1 << 0

	// MinABI is the lowest ABI hark will run under.
	//
	// ABI 1 lacks LANDLOCK_ACCESS_FS_REFER, and without it the kernel denies
	// every rename or link across directories rather than letting policy decide.
	// That breaks ordinary agent behaviour -- writing a temp file and renaming it
	// into place is how most software writes a file at all -- so the floor is 2.
	MinABI = 2
)

// rightsForABI returns the full set of filesystem rights this kernel understands.
func rightsForABI(abi int) uint64 {
	r := uint64(fsExecute | fsWriteFile | fsReadFile | fsReadDir |
		fsRemoveDir | fsRemoveFile | fsMakeChar | fsMakeDir | fsMakeReg |
		fsMakeSock | fsMakeFifo | fsMakeBlock | fsMakeSym)
	if abi >= 2 {
		r |= fsRefer
	}
	if abi >= 3 {
		r |= fsTruncate
	}
	if abi >= 5 {
		r |= fsIoctlDev
	}
	return r
}

// ABI reports the Landlock ABI version the running kernel supports.
//
// It returns ErrLandlockUnavailable when Landlock is absent -- which on a
// container host usually means the LSM is simply not in the active list, and is
// the single most common reason hark refuses to start somewhere new.
func ABI() (int, error) {
	r, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, createRulesetVersion)
	if errno != 0 {
		if errno == unix.ENOSYS || errno == unix.EOPNOTSUPP {
			return 0, fmt.Errorf("%w: %v", ErrLandlockUnavailable, errno)
		}
		return 0, fmt.Errorf("landlock: querying ABI version: %w", errno)
	}
	return int(r), nil
}

// ErrLandlockUnavailable means the kernel has no Landlock support, or it is not
// in the active LSM list. Check /sys/kernel/security/lsm.
var ErrLandlockUnavailable = errors.New("landlock: unavailable on this kernel")

// rulesetAttr mirrors struct landlock_ruleset_attr, truncated to its first
// field.
//
// The struct grew in later ABIs (handled_access_net at 4, scoped at 6), and the
// kernel validates the size argument against what it knows. Passing only the
// filesystem field with size 8 is accepted by every ABI from 1 upward. hark
// governs the network with a namespace rather than Landlock -- see ADR-0003,
// which explains why Landlock cannot express host-based policy anyway -- so the
// later fields are genuinely unused rather than merely skipped.
type rulesetAttr struct {
	handledAccessFS uint64
}

// pathBeneathAttr mirrors struct landlock_path_beneath_attr, which is declared
// __attribute__((packed)) and is therefore 12 bytes, not 16. Getting this wrong
// yields EINVAL with nothing to indicate why.
type pathBeneathAttr struct {
	allowedAccess uint64
	parentFD      int32
}

// FSRule grants access beneath one path.
type FSRule struct {
	Path  string
	Write bool
}

// ApplyFilesystem builds a ruleset from the given paths and enforces it on the
// calling thread.
//
// # Threading
//
// landlock_restrict_self restricts the *calling thread*, not the process. Go
// moves goroutines between threads freely, so this must be called with
// runtime.LockOSThread already held and must be followed by execve on that same
// thread. In hark that is guaranteed by structure rather than by convention: it
// only ever runs inside the re-executed init child, immediately before
// syscall.Exec replaces the process.
//
// The restriction survives execve and is inherited by every descendant, which is
// what makes it useful here -- an agent that spawns children cannot escape by
// doing so.
func ApplyFilesystem(rules []FSRule) error {
	abi, err := ABI()
	if err != nil {
		return err
	}
	if abi < MinABI {
		return fmt.Errorf("landlock: kernel reports ABI %d, hark requires at least %d", abi, MinABI)
	}

	handled := rightsForABI(abi)

	attr := rulesetAttr{handledAccessFS: handled}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("landlock: creating ruleset: %w", errno)
	}
	rulesetFD := int(fd)
	defer unix.Close(rulesetFD)

	readRights := uint64(fsExecute|fsReadFile|fsReadDir) & handled
	writeRights := handled // everything this kernel supports, beneath the path

	for _, rule := range rules {
		allowed := readRights
		if rule.Write {
			allowed = writeRights
		}
		if err := addPathRule(rulesetFD, rule.Path, allowed); err != nil {
			return err
		}
	}

	// NO_NEW_PRIVS is mandatory before restrict_self for an unprivileged caller,
	// and is wanted regardless: it stops a setuid binary in the workspace from
	// becoming an escape route.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("landlock: setting NO_NEW_PRIVS: %w", err)
	}

	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), 0, 0); errno != 0 {
		return fmt.Errorf("landlock: enforcing ruleset: %w", errno)
	}
	return nil
}

func addPathRule(rulesetFD int, path string, allowed uint64) error {
	// O_PATH gets a handle for naming purposes only: it neither reads the file
	// nor requires permission to. That matters because a rule may name a
	// directory the supervisor has no business opening for real.
	pathFD, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("landlock: opening %q for a rule: %w", path, err)
	}
	defer unix.Close(pathFD)

	attr := pathBeneathAttr{
		allowedAccess: allowed,
		parentFD:      int32(pathFD),
	}
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFD), ruleTypePathBeneath,
		uintptr(unsafe.Pointer(&attr)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("landlock: adding a rule for %q: %w", path, errno)
	}
	return nil
}
