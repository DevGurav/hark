//go:build linux

package launcher

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Network setup for the agent's namespace.
//
// A veth pair straddles the boundary: one end stays with the supervisor and the
// mediator listens on it, the other is moved into the agent's namespace. The
// agent's routing table ends up with a link route and a default route, both
// pointing at the mediator, and nothing else. There is no second path out, which
// is what makes the containment claim hold regardless of what the agent's code
// does about proxy settings.
//
// Configuration goes through `ip` and `nsenter` rather than raw netlink. That is
// a deliberate v0.1 choice: these are the exact commands the design was verified
// with in W0, so what runs matches what was proven, and anyone reading the code
// can reproduce it by hand. Netlink removes two process dependencies and is a
// contained swap behind this file when it is worth doing.

// Network describes one boundary.
type Network struct {
	HostIF     string // supervisor side
	PeerIF     string // agent side
	HostCIDR   string // e.g. 10.200.1.1/24
	PeerCIDR   string // e.g. 10.200.1.2/24
	MediatorIP string // e.g. 10.200.1.1
}

// NewNetwork builds a Network with unique interface names.
//
// Interface names are capped at 15 characters by the kernel, and two concurrent
// runs must not collide, so the suffix is random rather than derived from a pid.
func NewNetwork() (Network, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Network{}, fmt.Errorf("network: generating interface suffix: %w", err)
	}
	id := hex.EncodeToString(b[:])
	return Network{
		HostIF:     "hk" + id + "h",
		PeerIF:     "hk" + id + "n",
		HostCIDR:   "10.200.1.1/24",
		PeerCIDR:   "10.200.1.2/24",
		MediatorIP: "10.200.1.1",
	}, nil
}

// setup creates the veth pair and configures both ends. pid identifies the
// child whose network namespace the peer is moved into.
func (n Network) setup(pid int) error {
	target := strconv.Itoa(pid)

	steps := [][]string{
		{"ip", "link", "add", n.HostIF, "type", "veth", "peer", "name", n.PeerIF},
		{"ip", "link", "set", n.PeerIF, "netns", target},
		{"ip", "addr", "add", n.HostCIDR, "dev", n.HostIF},
		{"ip", "link", "set", n.HostIF, "up"},

		{"nsenter", "-t", target, "-n", "ip", "addr", "add", n.PeerCIDR, "dev", n.PeerIF},
		{"nsenter", "-t", target, "-n", "ip", "link", "set", n.PeerIF, "up"},
		{"nsenter", "-t", target, "-n", "ip", "link", "set", "lo", "up"},

		// The default route points at the mediator. Combined with the forwarding
		// blocks below, that means every packet the agent sends reaches the
		// mediator or nothing at all -- which is what lets an attempt be recorded
		// and refused rather than silently dropped by the routing table. See
		// ADR-0006.
		{"nsenter", "-t", target, "-n", "ip", "route", "add", "default", "via", n.MediatorIP},
	}

	for _, step := range steps {
		if err := run(step); err != nil {
			// Leave nothing half-built behind; the caller aborts the run anyway.
			_ = n.teardown()
			return err
		}
	}

	if err := n.blockForwarding(); err != nil {
		_ = n.teardown()
		return err
	}
	return nil
}

// blockForwarding stops the host routing the agent's packets onward.
//
// Without this the containment depends on the host's global ip_forward setting,
// which hark does not own and any unrelated tool might flip. Explicit DROP rules
// on this interface make the boundary hold regardless -- the agent's default
// route reaches the mediator and terminates there.
func (n Network) blockForwarding() error {
	for _, args := range [][]string{
		{"iptables", "-I", "FORWARD", "-i", n.HostIF, "-j", "DROP"},
		{"iptables", "-I", "FORWARD", "-o", n.HostIF, "-j", "DROP"},
	} {
		if err := run(args); err != nil {
			return err
		}
	}
	return nil
}

// teardown removes everything setup created. Deleting the host end of a veth
// pair takes the peer with it, and the peer disappears with the namespace in any
// case, so the link delete is the only cleanup that matters.
//
// Every step is best-effort: teardown runs on the failure path too, where some
// of it will not exist.
func (n Network) teardown() error {
	_ = run([]string{"iptables", "-D", "FORWARD", "-i", n.HostIF, "-j", "DROP"})
	_ = run([]string{"iptables", "-D", "FORWARD", "-o", n.HostIF, "-j", "DROP"})

	if err := run([]string{"ip", "link", "del", n.HostIF}); err != nil {
		if strings.Contains(err.Error(), "Cannot find device") {
			return nil
		}
		return err
	}
	return nil
}

// pruneStaleRules removes forwarding rules left by runs that never tore down.
//
// A veth pair is reaped with its namespace, but iptables rules are not: a
// supervisor killed with SIGKILL leaves both DROP rules behind, naming an
// interface that no longer exists. They are inert -- nothing matches a device
// that is gone -- but they accumulate for as long as the host stays up, and a
// FORWARD chain thousands of rules deep is somebody's confusing afternoon later.
//
// Called before each run, so hark cleans up after its own past failures without
// anyone needing to know it should.
//
// Only rules naming a missing hk-prefixed interface are touched. Anything else
// in the chain belongs to somebody else.
func pruneStaleRules() {
	out, err := exec.Command("iptables", "-S", "FORWARD").Output()
	if err != nil {
		return // Not fatal: pruning is hygiene, not correctness.
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "-A" {
			continue
		}
		var iface string
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "-i" || fields[i] == "-o" {
				iface = fields[i+1]
			}
		}
		if !strings.HasPrefix(iface, "hk") {
			continue
		}
		if err := exec.Command("ip", "link", "show", iface).Run(); err == nil {
			continue // Interface still exists, so the rule is live.
		}
		args := append([]string{"-D"}, fields[1:]...)
		_ = exec.Command("iptables", args...).Run()
	}
}

// run executes one configuration command, folding stderr into the error so a
// failure says what the kernel actually objected to rather than just reporting
// a non-zero exit.
func run(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("network: %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// checkTooling verifies the external commands exist before a run starts, so a
// missing package is reported up front instead of halfway through building the
// boundary.
func checkTooling() error {
	for _, bin := range []string{"ip", "nsenter", "iptables"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("network: %s not found in PATH: install iproute2, util-linux and iptables", bin)
		}
	}
	return nil
}

// requireRoot reports whether the supervisor can create namespaces at all.
//
// Checked explicitly because the failure otherwise surfaces as a confusing
// EPERM from clone() several steps later.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("launcher: creating a network namespace requires root (run under sudo)")
	}
	return nil
}
