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
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
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

	// ResolvConf is a file on the host bind-mounted over /etc/resolv.conf inside
	// the agent's mount namespace, pointing its resolver at the mediator.
	//
	// The documented trick for this is /etc/netns/<name>/resolv.conf, which
	// `ip netns exec` bind-mounts for you -- but that only works for a *named*
	// namespace. The agent's is anonymous, created by clone(CLONE_NEWNET), so
	// the mount has to be done directly. Empty means leave the host's resolver
	// alone.
	ResolvConf string

	// BeforeRelease runs after the boundary is built and before the agent is
	// released, with the addresses that were assigned.
	//
	// This exists because of an ordering knot: the mediator has to listen on the
	// veth address, which does not exist until the interface is configured, and
	// the agent must not run before the mediator is listening. The barrier the
	// child already blocks on is the natural place to resolve it. An error here
	// aborts the run and the agent never starts.
	BeforeRelease func(n Network) error
}

// childSpec is what actually crosses the pipe. It excludes the file handles,
// which are passed as descriptors rather than serialised.
type childSpec struct {
	Argv       []string `json:"argv"`
	Env        []string `json:"env"`
	WorkDir    string   `json:"work_dir"`
	ReadPaths  []string `json:"read_paths"`
	WritePaths []string `json:"write_paths"`
	ResolvConf string   `json:"resolv_conf"`
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
	if err := checkReachable(append(append([]string{}, s.ReadPaths...), s.WritePaths...)); err != nil {
		return nil, err
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

	// Assign only when the file is actually present.
	//
	// Spec's fields are *os.File and Cmd's are io.Writer. Assigning a nil
	// *os.File to an interface produces a non-nil interface holding a nil
	// pointer, so a later `cmd.Stdout == nil` check is false and exec writes
	// through a nil file -- which fails silently and sends the agent's output
	// nowhere. The agent still runs and its exit code still propagates, so the
	// symptom is a program that appears to produce nothing.
	if s.Stdin != nil {
		cmd.Stdin = s.Stdin
	}
	if s.Stdout != nil {
		cmd.Stdout = s.Stdout
	} else {
		cmd.Stdout = os.Stdout
	}
	if s.Stderr != nil {
		cmd.Stderr = s.Stderr
	} else {
		cmd.Stderr = os.Stderr
	}
	// The control pipe becomes fd 3 in the child.
	cmd.ExtraFiles = []*os.File{readPipe}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// CLONE_NEWNS as well as CLONE_NEWNET, so the child can point its
		// resolver at the mediator without touching the host's /etc/resolv.conf.
		Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
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
		ResolvConf: s.ResolvConf,
	}
	if err := writeSpec(writePipe, cs); err != nil {
		return abort(err)
	}

	if err := net.setup(h.Pid); err != nil {
		return abort(err)
	}

	if s.BeforeRelease != nil {
		if err := s.BeforeRelease(net); err != nil {
			return abort(fmt.Errorf("launcher: preparing the boundary: %w", err))
		}
	}

	// Release the child only once the boundary exists and everything listening
	// on it is ready.
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

	// Mounts happen before capabilities are dropped, because mount(2) needs
	// CAP_SYS_ADMIN, and before seccomp, which denies it outright.
	if err := applyMounts(spec.ResolvConf); err != nil {
		return err
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
	rules := make([]FSRule, 0, len(spec.ReadPaths)+len(spec.WritePaths)+1)
	for _, p := range spec.ReadPaths {
		rules = append(rules, FSRule{Path: p})
	}
	// The bind-mounted resolv.conf needs its own rule, granted on the mounted
	// path rather than on either side of the mount.
	//
	// A Landlock rule covers a hierarchy, and a bind mount is its own mount
	// point: the file is not beneath the rule on /etc, and it is no longer
	// reached through the rule on the source directory either. Granting /etc and
	// the source both looks sufficient and is not -- the agent gets EACCES on
	// /etc/resolv.conf, every lookup fails, and the symptom is a run where
	// nothing reaches the mediator at all.
	if spec.ResolvConf != "" {
		rules = append(rules, FSRule{Path: "/etc/resolv.conf"})
	}
	for _, p := range spec.WritePaths {
		rules = append(rules, FSRule{Path: p, Write: true})
	}

	// Opened before the drop, enforced after it. Reaching a path needs search
	// permission on every parent directory, and an unprivileged uid 0 does not
	// have it in another user's home -- so the handles are taken while this
	// process still holds CAP_DAC_OVERRIDE, and the ruleset is built from them.
	opened, err := OpenRules(rules)
	if err != nil {
		return err
	}
	defer CloseRules(opened)

	if err := DropCapabilities(); err != nil {
		return err
	}

	if err := ApplyFilesystem(opened); err != nil {
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

// checkReachable refuses a run whose granted paths the agent could not reach
// anyway.
//
// The agent runs as uid 0 with every capability dropped, which means it is
// subject to ordinary file permissions -- CAP_DAC_OVERRIDE is what normally
// exempts root from them, and it is gone by design. A clone in a mode-0750 home
// directory is therefore unreadable to it, however generous the policy is.
//
// Landlock only ever removes access; it cannot grant past DAC. So a policy that
// names such a path is not wrong so much as unachievable, and saying which
// directory blocks it beats letting the agent fail later with an import error.
func checkReachable(paths []string) error {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			// A path that does not exist is a different problem, reported where
			// it is discovered rather than guessed at here.
			continue
		}
		if blocker, err := firstUnsearchable(path); err != nil {
			return err
		} else if blocker != "" {
			return fmt.Errorf(
				"launcher: the agent could not reach %s: %s is not searchable by an unprivileged process, "+
					"and the agent runs with every capability dropped. Move what the agent needs somewhere "+
					"world-traversable, or loosen that directory", path, blocker)
		}
	}
	return nil
}

// firstUnsearchable walks the ancestors of path and returns the first directory
// a capability-less uid 0 could not traverse, or "" when the whole chain is
// reachable.
func firstUnsearchable(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("launcher: resolving %q: %w", path, err)
	}

	var ancestors []string
	for p := abs; ; p = filepath.Dir(p) {
		ancestors = append([]string{p}, ancestors...)
		if p == "/" || filepath.Dir(p) == p {
			break
		}
	}

	for _, p := range ancestors {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			return "", nil // reported elsewhere
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		// The agent is uid 0, gid 0. Owner bits apply when root owns the
		// directory, group bits when root's group does, other bits otherwise --
		// the ordinary DAC precedence, with no capability to fall back on.
		var searchable bool
		switch {
		case st.Uid == 0:
			searchable = st.Mode&unix.S_IXUSR != 0
		case st.Gid == 0:
			searchable = st.Mode&unix.S_IXGRP != 0
		default:
			searchable = st.Mode&unix.S_IXOTH != 0
		}
		if !searchable {
			return fmt.Sprintf("%s (mode %04o, owner uid %d)", p, st.Mode&0o7777, st.Uid), nil
		}
	}
	return "", nil
}

// applyMounts points the agent's resolver at the mediator.
//
// The child has its own mount namespace, but a namespace alone is not
// isolation: mounts propagate back to the parent by default, so a bind mount
// here would replace the *host's* /etc/resolv.conf. Marking the tree private
// first is what confines it, and forgetting that line is the difference between
// a contained change and breaking DNS for the whole machine.
func applyMounts(resolvConf string) error {
	if resolvConf == "" {
		return nil
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("launcher: making the mount tree private: %w", err)
	}
	if err := unix.Mount(resolvConf, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("launcher: pointing /etc/resolv.conf at the mediator: %w", err)
	}
	return nil
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
