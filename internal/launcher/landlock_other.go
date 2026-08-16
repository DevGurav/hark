//go:build !linux

package launcher

import (
	"errors"
	"os"
)

// Stubs for non-Linux hosts.
//
// hark runs only on Linux. These exist so `go build ./...` and the pure-logic
// tests still work on a development machine that is not, which is most of the
// codebase -- the bundle format, hashing, policy, SNI parsing and the broker all
// have no kernel dependency.
//
// They return errors rather than succeeding silently. A no-op containment layer
// that reports success is the exact failure this project exists to prevent.

// MinABI is the lowest Landlock ABI hark will run under.
const MinABI = 2

// ErrLandlockUnavailable means Landlock cannot be used here.
var ErrLandlockUnavailable = errors.New("landlock: unavailable: hark requires Linux")

// FSRule grants access beneath one path.
type FSRule struct {
	Path  string
	Write bool
}

// ErrUnsupported means this containment primitive needs Linux.
var ErrUnsupported = errors.New("launcher: containment requires Linux")

// ABI reports the Landlock ABI version. Always unavailable off Linux.
func ABI() (int, error) { return 0, ErrLandlockUnavailable }

// ApplyFilesystem always fails off Linux.
func ApplyFilesystem([]FSRule) error { return ErrLandlockUnavailable }

// ApplySeccomp always fails off Linux.
func ApplySeccomp() error { return ErrUnsupported }

// DropCapabilities always fails off Linux.
func DropCapabilities() error { return ErrUnsupported }

// HasCapabilities always fails off Linux.
func HasCapabilities() (bool, error) { return false, ErrUnsupported }

// InitArg is the sentinel marking the re-executed child.
const InitArg = "__hark-init"

// SystemReadPaths would be granted read-only on Linux.
var SystemReadPaths []string

// Spec describes one contained run.
type Spec struct {
	Argv          []string
	Env           []string
	WorkDir       string
	ReadPaths     []string
	WritePaths    []string
	Stdin         *os.File
	Stdout        *os.File
	Stderr        *os.File
	ResolvConf    string
	BeforeRelease func(n Network) error
}

// Network describes one boundary.
type Network struct {
	HostIF     string
	PeerIF     string
	HostCIDR   string
	PeerCIDR   string
	MediatorIP string
}

// Handle refers to a running agent.
type Handle struct {
	Pid     int
	Network Network
}

// Launch always fails off Linux.
func Launch(Spec) (*Handle, error) { return nil, ErrUnsupported }

// Wait always fails off Linux.
func (h *Handle) Wait() (int, error) { return -1, ErrUnsupported }

// Kill always fails off Linux.
func (h *Handle) Kill() error { return ErrUnsupported }

// Close always fails off Linux.
func (h *Handle) Close() error { return ErrUnsupported }

// Init always fails off Linux.
func Init() error { return ErrUnsupported }

// IsInit reports whether this process is the re-executed child.
func IsInit(args []string) bool {
	return len(args) > 1 && args[1] == InitArg
}
