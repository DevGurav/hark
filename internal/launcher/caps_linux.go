//go:build linux

package launcher

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Capability dropping.
//
// The supervisor needs CAP_NET_ADMIN to create the namespace and move a veth
// into it. Without an explicit drop, the agent it launches would inherit that,
// and an agent holding CAP_NET_ADMIN can reconfigure the very namespace meant to
// contain it -- add a route, bring up an interface, and walk out.
//
// So the child sheds everything before exec.

// DropCapabilities removes every capability from the calling thread and from
// the bounding set, so nothing can be regained across execve.
//
// # Order
//
// The sequence is not interchangeable. Dropping the bounding set requires
// CAP_SETPCAP, so it has to happen while capabilities are still held. Clearing
// the permitted set first would leave the bounding set populated with no way
// left to empty it, and a populated bounding set is what allows a setuid binary
// to hand capabilities back on exec.
//
//  1. clear the ambient set   -- otherwise it survives exec into the child
//  2. drop the bounding set   -- needs CAP_SETPCAP, so it goes before step 3
//  3. clear permitted, effective and inheritable
func DropCapabilities() error {
	// PR_CAP_AMBIENT_CLEAR_ALL. Ambient capabilities are the ones deliberately
	// designed to survive execve, so they have to go explicitly.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		// EINVAL means the kernel predates ambient capabilities, in which case
		// there is nothing to clear. Any other error is real.
		if err != unix.EINVAL {
			return fmt.Errorf("caps: clearing the ambient set: %w", err)
		}
	}

	last, err := lastCap()
	if err != nil {
		return err
	}
	for cap := 0; cap <= last; cap++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
			// EPERM means we never held CAP_SETPCAP, which is the ordinary case
			// when the supervisor already runs unprivileged. There is nothing to
			// drop, and failing here would refuse a run that is already safe.
			if err == unix.EPERM {
				break
			}
			return fmt.Errorf("caps: dropping bounding capability %d: %w", cap, err)
		}
	}

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data [2]unix.CapUserData // all zero: nothing permitted, effective or inheritable
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("caps: clearing capability sets: %w", err)
	}
	return nil
}

// HasCapabilities reports whether the calling thread holds any capability. Used
// by tests, and by the launcher to assert the child really is stripped before it
// hands control to the agent.
func HasCapabilities() (bool, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false, fmt.Errorf("caps: reading capability sets: %w", err)
	}
	for _, d := range data {
		if d.Effective != 0 || d.Permitted != 0 || d.Inheritable != 0 {
			return true, nil
		}
	}
	return false, nil
}

// lastCap reads the highest capability number this kernel knows.
//
// Read rather than hardcoded: the list grows between releases, and a constant
// compiled in today would silently stop dropping the newest capabilities on a
// newer kernel — leaving exactly the ones least likely to be audited.
func lastCap() (int, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, fmt.Errorf("caps: reading cap_last_cap: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, fmt.Errorf("caps: parsing cap_last_cap: %w", err)
	}
	if n < 0 || n > 255 {
		return 0, fmt.Errorf("caps: implausible cap_last_cap %d", n)
	}
	return n, nil
}
