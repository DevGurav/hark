//go:build linux

package launcher

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// Launching the agent inside its containment.
//
// # Why the binary re-executes itself
//
// Landlock and seccomp both restrict the *calling thread*, not the process, and
// both are inherited across execve. Go moves goroutines between OS threads
// whenever it likes, so there is no way to apply them from an ordinary goroutine
// and be sure the thread that eventually calls execve is the restricted one.
//
// Go also offers no safe hook between fork and exec: the child of a fork in a Go
// program may only call async-signal-safe operations, which rules out almost
// everything the setup needs.
//
// So the supervisor re-executes its own binary with a sentinel argument. That
// child is a fresh process whose main goroutine holds a locked thread, applies
// every restriction on it, and calls execve on that same thread. runc solves the
// same problem the same way, for the same reason.
//
// # Sequence
//
//	parent                              init child
//	------                              ----------
//	clone(CLONE_NEWNET) ─────────────►  start, lock thread
//	write spec to fd 3 ──────────────►  read spec
//	create veth, move peer into ns
//	configure both ends
//	write "go" to fd 3 ──────────────►  unblock
//	                                    chdir, resolve binary
//	                                    Landlock, seccomp, drop caps
//	                                    execve(agent)
//
// The child blocks until the network exists. Without that barrier the agent
// could start running -- and making network calls -- before the boundary it is
// supposed to be inside had been built.

// InitArg is the sentinel that marks the re-executed child.
const InitArg = "__hark-init"

// SystemReadPaths are granted read-only in every run.
//
// An interpreter cannot start without them: Python alone needs its standard
// library, the dynamic loader, and the CA bundle. Granting them is not a
// weakening of the policy so much as an admission of what "run a program" means.
// The bundle is never among them, and nothing here is writable.
//
// /proc is the one with a real cost: it lets the agent enumerate other processes
// on the host. It is granted because runtimes genuinely need it and because
// seccomp already denies the syscalls that would turn that visibility into
// access -- ptrace and process_vm_readv. Recorded as a known limitation in
// docs/security.md rather than left for a reader to notice.
var SystemReadPaths = []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc"}

// Spec describes one contained run.
type Spec struct {
	Argv       []string
	Env        []string
	WorkDir    string
	ReadPaths  []string
	WritePaths []string

	// Stdin, Stdout and Stderr are passed through to the agent. Nil means
	// inherit the supervisor's.
	Stdin  *os.File
	Stdout *os.File
	Stderr *os.File
}

// childSpec is what actually crosses the pipe. It excludes the file handles,
// which are passed as descriptors rather than serialised.
type childSpec struct {
	Argv       []string `json:"argv"`
	Env        []string `json:"env"`
	WorkDir    string   `json:"work_dir"`
	ReadPaths  []string `json:"read_paths"`
	WritePaths []string `json:"write_paths"`
}

// Handle refers to a running agent.
type Handle struct {
	Pid     int
	Network Network

	cmd  *exec.Cmd
	torn bool
}

// Launch starts the agent inside a new network namespace with the filesystem,
// syscall and capability restrictions applied.
//
// The returned Handle must be closed to remove the veth pair and firewall rules,
// whether or not the agent exited cleanly.
func Launch(s Spec) (*Handle, error) {
	if len(s.Argv) == 0 {
		return nil, errors.New("launcher: empty argv")
	}
	if err := requireRoot(); err != nil {
		return nil, err
	}
	if err := checkTooling(); err != nil {
		return nil, err
	}
	if _, err := ABI(); err != nil {
		// Refuse rather than run uncontained. A missing LSM is the single most
		// common reason this fails on a new machine, so the error says where to
		// look.
		return nil, fmt.Errorf("launcher: %w (check /sys/kernel/security/lsm)", err)
	}

	// Clear anything a previously killed supervisor left behind. Rules outlive
	// the interfaces they name, so without this they accumulate across crashes.
	pruneStaleRules()

	net, err := NewNetwork()
	if err != nil {
		return nil, err
	}

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("launcher: creating the control pipe: %w", err)
	}
	defer readPipe.Close()
	defer writePipe.Close()

	cmd := exec.Command("/proc/self/exe", InitArg)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.Stdin, s.Stdout, s.Stderr
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	// The control pipe becomes fd 3 in the child.
	cmd.ExtraFiles = []*os.File{readPipe}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET,
		// The agent dies with the supervisor. A contained process outliving the
		// thing recording it would be both unrecorded and unsupervised.
		Pdeathsig: syscall.SIGKILL,
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("launcher: starting the init child: %w", err)
	}
	h := &Handle{Pid: cmd.Process.Pid, Network: net, cmd: cmd}

	abort := func(cause error) (*Handle, error) {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = net.teardown()
		return nil, cause
	}

	cs := childSpec{
		Argv:       s.Argv,
		Env:        s.Env,
		WorkDir:    s.WorkDir,
		ReadPaths:  append(existingSystemPaths(), s.ReadPaths...),
		WritePaths: s.WritePaths,
	}
	if err := writeSpec(writePipe, cs); err != nil {
		return abort(err)
	}

	if err := net.setup(h.Pid); err != nil {
		return abort(err)
	}

	// Release the child only once the boundary exists.
	if _, err := writePipe.Write([]byte{1}); err != nil {
		return abort(fmt.Errorf("launcher: releasing the init child: %w", err))
	}
	return h, nil
}

// Wait blocks until the agent exits and returns its exit code.
func (h *Handle) Wait() (int, error) {
	err := h.cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// Kill terminates the agent immediately.
func (h *Handle) Kill() error {
	if h.cmd.Process == nil {
		return nil
	}
	return h.cmd.Process.Kill()
}

// Close removes the network boundary. Safe to call more than once.
//
// Usually a no-op on the success path: a veth pair is reaped by the kernel when
// its namespace goes away, and deleting either end takes both. It does real work
// when a run is aborted part-way through setup, and it always removes the
// firewall rules, which outlive the namespace.
func (h *Handle) Close() error {
	if h.torn {
		return nil
	}
	h.torn = true
	return h.Network.teardown()
}

// Init is the re-executed child. It never returns on success, because execve
// replaces the process.
//
// Every step here runs on one locked thread, and the order is fixed: the
// restrictions have to be in place before the agent's code exists in this
// process at all.
func Init() error {
	runtime.LockOSThread()

	pipe := os.NewFile(3, "hark-control")
	if pipe == nil {
		return errors.New("launcher: no control pipe on fd 3")
	}
	defer pipe.Close()

	spec, err := readSpec(pipe)
	if err != nil {
		return err
	}

	// Block until the parent has built the namespace. Reading a single byte is
	// the barrier; an EOF here means the parent gave up, so the child must too
	// rather than run an agent with no containment around it.
	var ready [1]byte
	if _, err := io.ReadFull(pipe, ready[:]); err != nil {
		return fmt.Errorf("launcher: waiting for the boundary to be built: %w", err)
	}

	if spec.WorkDir != "" {
		if err := os.Chdir(spec.WorkDir); err != nil {
			return fmt.Errorf("launcher: entering %q: %w", spec.WorkDir, err)
		}
	}

	// Resolve the binary before restricting anything. PATH lookup afterwards
	// would depend on the granted read paths, and a failure at that point would
	// be reported as a missing program rather than a policy that is too narrow.
	binary, err := exec.LookPath(spec.Argv[0])
	if err != nil {
		return fmt.Errorf("launcher: locating %q: %w", spec.Argv[0], err)
	}

	// Capabilities go first, for two reasons.
	//
	// Shedding privilege at the earliest possible point is the right default:
	// every line after this runs unprivileged, so a mistake in one of them has
	// less to work with.
	//
	// The concrete reason is ordering. DropCapabilities reads
	// /proc/sys/kernel/cap_last_cap, and once Landlock is enforced /proc is no
	// longer readable unless it was granted. Doing this after the ruleset meant
	// the drop failed and the agent kept root's capabilities -- caught by the
	// integration test rather than by reading the code, which is exactly what
	// that test is for.
	//
	// Neither of the steps that follow needs a capability: Landlock is designed
	// for unprivileged callers, and seccomp only requires NO_NEW_PRIVS.
	if err := DropCapabilities(); err != nil {
		return err
	}

	rules := make([]FSRule, 0, len(spec.ReadPaths)+len(spec.WritePaths))
	for _, p := range spec.ReadPaths {
		rules = append(rules, FSRule{Path: p})
	}
	for _, p := range spec.WritePaths {
		rules = append(rules, FSRule{Path: p, Write: true})
	}
	if err := ApplyFilesystem(rules); err != nil {
		return err
	}
	if err := ApplySeccomp(); err != nil {
		return err
	}

	env := spec.Env
	if env == nil {
		env = os.Environ()
	}
	return syscall.Exec(binary, spec.Argv, env)
}

// IsInit reports whether this process is the re-executed child.
func IsInit(args []string) bool {
	return len(args) > 1 && args[1] == InitArg
}

// existingSystemPaths filters SystemReadPaths to those actually present.
// Landlock rejects a rule naming a path that does not exist, and /lib64 is
// absent on arm64.
func existingSystemPaths() []string {
	out := make([]string, 0, len(SystemReadPaths))
	for _, p := range SystemReadPaths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func writeSpec(w io.Writer, cs childSpec) error {
	body, err := json.Marshal(cs)
	if err != nil {
		return fmt.Errorf("launcher: encoding the child spec: %w", err)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(body)))
	if _, err := w.Write(length[:]); err != nil {
		return fmt.Errorf("launcher: sending the child spec: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("launcher: sending the child spec: %w", err)
	}
	return nil
}

func readSpec(r io.Reader) (*childSpec, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, fmt.Errorf("launcher: reading the child spec: %w", err)
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("launcher: implausible child spec length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("launcher: reading the child spec: %w", err)
	}
	var cs childSpec
	if err := json.Unmarshal(body, &cs); err != nil {
		return nil, fmt.Errorf("launcher: decoding the child spec: %w", err)
	}
	if len(cs.Argv) == 0 {
		return nil, errors.New("launcher: child spec has empty argv")
	}
	return &cs, nil
}
