//go:build linux

package launcher

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Integration tests for the whole containment. These need root, because
// creating a network namespace does, and they skip rather than fail without it
// so the rest of the suite still runs unprivileged.

func requireRoot_(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a network namespace; run with sudo")
	}
	if _, err := ABI(); err != nil {
		t.Skipf("Landlock unavailable here: %v", err)
	}
	if err := checkTooling(); err != nil {
		t.Skipf("%v", err)
	}
}

// launch runs argv under containment and returns its exit code and combined
// output.
func launch(t *testing.T, s Spec) (int, string) {
	t.Helper()

	out, err := os.CreateTemp(t.TempDir(), "out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	s.Stdout, s.Stderr = out, out
	if s.WritePaths == nil {
		s.WritePaths = []string{t.TempDir()}
	}

	h, err := Launch(s)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })

	code, err := h.Wait()
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	body, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, string(body)
}

func TestLaunchRunsProgram(t *testing.T) {
	requireRoot_(t)

	code, out := launch(t, Spec{Argv: []string{"echo", "contained"}})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "contained") {
		t.Fatalf("did not see the program's output: %q", out)
	}
}

func TestLaunchPropagatesExitCode(t *testing.T) {
	requireRoot_(t)

	code, out := launch(t, Spec{Argv: []string{"sh", "-c", "exit 42"}})
	if code != 42 {
		t.Fatalf("exit %d, expected 42: %s", code, out)
	}
}

// The containment claim: there is no route out, whatever the agent does about
// proxy settings.
func TestNoRouteToTheInternet(t *testing.T) {
	requireRoot_(t)

	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}

	code, out := launch(t, Spec{
		Argv: []string{"sh", "-c",
			"unset HTTPS_PROXY https_proxy ALL_PROXY; curl -s --max-time 5 https://example.com"},
	})
	if code == 0 {
		t.Fatalf("the agent reached the internet: %s", out)
	}
}

// The routing table must contain the mediator and nothing else. This is the
// check that would catch a future change quietly restoring a second path out.
func TestRoutingTablePointsOnlyAtTheMediator(t *testing.T) {
	requireRoot_(t)

	code, out := launch(t, Spec{Argv: []string{"ip", "route", "show"}})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "default via 10.200.1.1") {
		t.Fatalf("no default route to the mediator:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		if !strings.Contains(line, "10.200.1.") {
			t.Fatalf("unexpected route out of the namespace: %q", line)
		}
	}
}

// Landlock, seccomp and the capability drop all reach the agent, applied by the
// init child rather than by the tests directly.
func TestRestrictionsReachTheAgent(t *testing.T) {
	requireRoot_(t)

	secret := filepath.Join(t.TempDir(), "bundle.hark")
	if err := os.WriteFile(secret, []byte("the audit log"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("filesystem is scoped", func(t *testing.T) {
		code, out := launch(t, Spec{Argv: []string{"cat", secret}})
		if code == 0 {
			t.Fatalf("the agent read the audit log: %s", out)
		}
	})

	t.Run("granted paths still work", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "input.txt")
		if err := os.WriteFile(f, []byte("readable"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out := launch(t, Spec{Argv: []string{"cat", f}, ReadPaths: []string{dir}})
		if code != 0 || !strings.Contains(out, "readable") {
			t.Fatalf("the agent could not read a granted path (exit %d): %s", code, out)
		}
	})

	t.Run("workspace is writable", func(t *testing.T) {
		work := t.TempDir()
		code, out := launch(t, Spec{
			Argv:       []string{"sh", "-c", "echo written > " + filepath.Join(work, "out.txt")},
			WritePaths: []string{work},
		})
		if code != 0 {
			t.Fatalf("the agent could not write its workspace (exit %d): %s", code, out)
		}
		if _, err := os.Stat(filepath.Join(work, "out.txt")); err != nil {
			t.Fatalf("the write did not land: %v", err)
		}
	})

	t.Run("capabilities are gone", func(t *testing.T) {
		// CapEff must be all zeros even though the supervisor ran as root.
		code, out := launch(t, Spec{Argv: []string{"sh", "-c", "grep ^CapEff /proc/self/status"}})
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "0000000000000000") {
			t.Fatalf("the agent inherited capabilities: %s", out)
		}
	})

	t.Run("seccomp is active", func(t *testing.T) {
		// Seccomp: 2 means a filter is installed.
		code, out := launch(t, Spec{Argv: []string{"sh", "-c", "grep ^Seccomp: /proc/self/status"}})
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "Seccomp:\t2") {
			t.Fatalf("no seccomp filter on the agent: %s", out)
		}
	})
}

// A run must not leave interfaces or firewall rules behind.
//
// The agent sleeps rather than exiting immediately, because a veth pair is
// reaped by the kernel when its namespace goes away -- deleting either end takes
// both. A fast-exiting child therefore removes the host interface before the
// assertion can see it, which is a race in the test rather than a bug in the
// code. It also means teardown is usually a no-op on the success path and only
// does real work when a run is aborted mid-setup.
func TestTeardownRemovesTheBoundary(t *testing.T) {
	requireRoot_(t)

	out, err := os.CreateTemp(t.TempDir(), "out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	h, err := Launch(Spec{Argv: []string{"sleep", "10"}, Stdout: out, Stderr: out})
	if err != nil {
		t.Fatal(err)
	}
	host := h.Network.HostIF

	if err := exec.Command("ip", "link", "show", host).Run(); err != nil {
		t.Fatalf("the host interface was never created: %v", err)
	}
	rules, err := exec.Command("iptables", "-S", "FORWARD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rules), host) {
		t.Fatalf("forwarding was never blocked for %s:\n%s", host, rules)
	}

	if err := h.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	if err := exec.Command("ip", "link", "show", host).Run(); err == nil {
		t.Fatal("the host interface survived teardown")
	}
	after, err := exec.Command("iptables", "-S", "FORWARD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), host) {
		t.Fatalf("firewall rules survived teardown:\n%s", after)
	}

	// Close is idempotent, because it runs on the failure path too.
	if err := h.Close(); err != nil {
		t.Fatalf("second Close returned an error: %v", err)
	}
}

func TestLaunchRejectsEmptyArgv(t *testing.T) {
	if _, err := Launch(Spec{}); err == nil {
		t.Fatal("accepted an empty argv")
	}
}

// A supervisor killed before teardown leaves forwarding rules naming an
// interface that no longer exists. They are inert but they accumulate, so the
// next run clears them.
func TestStaleRulesArePruned(t *testing.T) {
	requireRoot_(t)

	const ghost = "hkdeadbeefh"
	for _, args := range [][]string{
		{"iptables", "-I", "FORWARD", "-i", ghost, "-j", "DROP"},
		{"iptables", "-I", "FORWARD", "-o", ghost, "-j", "DROP"},
	} {
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			t.Fatalf("seeding a stale rule: %v", err)
		}
	}

	pruneStaleRules()

	out, err := exec.Command("iptables", "-S", "FORWARD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), ghost) {
		t.Fatalf("stale rules survived pruning:\n%s", out)
	}
}

// Pruning must not touch rules that belong to a live run, or to anyone else.
func TestPruneLeavesLiveAndForeignRulesAlone(t *testing.T) {
	requireRoot_(t)

	const foreign = "-i docker0 -j ACCEPT"
	if err := exec.Command("iptables", "-I", "FORWARD", "-i", "lo", "-j", "ACCEPT").Run(); err != nil {
		t.Skipf("could not seed a foreign rule: %v", err)
	}
	t.Cleanup(func() {
		_ = exec.Command("iptables", "-D", "FORWARD", "-i", "lo", "-j", "ACCEPT").Run()
	})
	_ = foreign

	out, err := os.CreateTemp(t.TempDir(), "out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	h, err := Launch(Spec{Argv: []string{"sleep", "10"}, Stdout: out, Stderr: out})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Kill(); _, _ = h.Wait(); _ = h.Close() }()

	pruneStaleRules()

	rules, err := exec.Command("iptables", "-S", "FORWARD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rules), h.Network.HostIF) {
		t.Fatalf("pruning removed a live run's rules:\n%s", rules)
	}
	if !strings.Contains(string(rules), "-i lo -j ACCEPT") {
		t.Fatalf("pruning removed an unrelated rule:\n%s", rules)
	}
}

// Each run gets its own interface names, so two runs cannot collide.
func TestNetworkNamesAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		n, err := NewNetwork()
		if err != nil {
			t.Fatal(err)
		}
		if len(n.HostIF) > 15 || len(n.PeerIF) > 15 {
			t.Fatalf("interface name exceeds the 15-character kernel limit: %q", n.HostIF)
		}
		if seen[n.HostIF] {
			t.Fatal("interface name collision")
		}
		seen[n.HostIF] = true
	}
}
