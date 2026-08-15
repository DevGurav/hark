# W2 — launcher, mediator, secrets broker

**Goal.** A fake agent, driven by `curl`, runs inside a contained namespace and produces a real
`.hark` bundle containing a real egress denial.

No model calls yet. No replay yet. The deliverable is that containment works, the boundary is
recorded, and the bundle verifies.

This is the highest-variance week. Every trap below has cost someone a day.

## Prerequisites

- W0 complete. Specifically the namespace transcript — without it this week becomes discovery.
- Working on the Linux box, not WSL2.

## Verified mechanics

*Populate this section during W0 with the exact commands that worked on the target kernel. Leaving
it empty and improvising is how W2 overruns.*

```text
(paste the working netns + veth + CA transcript here in W0)
```

## Deliverables

| File | Responsibility |
| --- | --- |
| `internal/policy/policy.go` | Parse and validate the TOML policy. An allowlist, not a DSL. |
| `internal/launcher/launcher.go` | Create the namespace and veth, apply Landlock and seccomp, drop capabilities, exec the child. |
| `internal/launcher/landlock_linux.go` | Filesystem scoping. Build-tagged; Linux only. |
| `internal/launcher/seccomp_linux.go` | Syscall filter plus `NO_NEW_PRIVS`. |
| `internal/broker/broker.go` | Placeholder generation and credential injection at the boundary. |
| `internal/mediator/mediator.go` | TLS termination, HTTP recording, egress policy evaluation. |
| `internal/mediator/ca.go` | Per-run CA generation and leaf signing. |
| `cmd/hark/run.go` | Wire it together behind `hark run`. |

Build tags matter: everything kernel-specific goes in `*_linux.go` with a `//go:build linux` guard
and a stub that returns a clear error elsewhere, so `go build ./...` keeps working on Windows for the
pure-logic packages.

## Interfaces

Implement against these so the pieces fit without a redesign mid-week.

```go
// internal/policy
type Policy struct {
    AllowHosts []string          // exact hostnames; no wildcards in v0.1
    ReadPaths  []string
    WritePaths []string
    Secrets    map[string]string // logical name -> env var to populate
}

func Load(path string) (*Policy, []byte, error) // returns the policy and its raw bytes for hashing
func (p *Policy) AllowsHost(host string) (rule string, ok bool)

// internal/launcher
type Spec struct {
    Argv       []string
    Env        []string
    WorkDir    string
    ReadPaths  []string
    WritePaths []string
    MediatorAddr string // the only reachable address
}

type Handle struct{ Pid int }

func Launch(ctx context.Context, s Spec) (*Handle, error)
func (h *Handle) Wait() (exitCode int, err error)

// internal/broker
type Broker struct{}

func New(runID string, secrets map[string]string) *Broker
func (b *Broker) Placeholders() map[string]string      // what the agent's env gets
func (b *Broker) Inject(host string, header http.Header, body []byte) ([]byte, bool)

// internal/mediator
type Recorder interface {
    Append(kind logfmt.Kind, payload any) (uint64, error)
    Sync() error
}

type Mediator struct{}

func New(p *policy.Policy, b *broker.Broker, r Recorder) (*Mediator, error)
func (m *Mediator) Addr() string
func (m *Mediator) CACertPEM() []byte
func (m *Mediator) Serve(ctx context.Context) error
```

The `Recorder` interface exists so the mediator does not import `bundle` directly. It keeps the
mediator testable without a file on disk, and it is the seam W3's playback mode swaps out.

## Tasks

### 1. Policy loader

- [ ] TOML with `allow_hosts`, `read_paths`, `write_paths`, `[secrets]`.
- [ ] Reject wildcards with a clear error. v0.1 is exact-match only; a half-implemented wildcard
      matcher is a security bug waiting to happen.
- [ ] Return the raw bytes alongside the parsed policy, so `PolicyHash` covers what was actually on
      disk rather than a re-serialisation of it.

**Acceptance.** Unit tests: a valid policy parses, a wildcard is rejected, an unknown key is
rejected, and the same file always produces the same hash.

### 2. Launcher

- [ ] Create a network namespace and veth pair. Address the host end and the namespace end; bring up
      `lo`. **Set no default route.**
- [ ] Apply Landlock: read-only on `ReadPaths`, read-write on `WritePaths`, nothing else. The bundle
      path must not be reachable.
- [ ] `NO_NEW_PRIVS`, drop all capabilities, apply a seccomp filter.
- [ ] Exec the child with the broker's placeholder environment.

**Acceptance.**

```sh
sudo ./hark run --policy testdata/deny-all.toml -- curl -s https://example.com   # must fail
sudo ./hark run --policy testdata/demo.toml -- sh -c 'unset HTTPS_PROXY; curl -s https://example.com'
```

The second is the important one: the agent stripped the proxy variable and still cannot escape,
because the namespace and not the environment is the control.

### 3. CA and TLS termination

- [ ] Generate a fresh CA per run. Never persist it, never reuse one across runs.
- [ ] Write the CA into the agent's trust store inside the namespace, and set `SSL_CERT_FILE`,
      `REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`.
- [ ] Sign leaf certificates on demand from the SNI.

**Acceptance.** `curl https://example.com` inside the namespace succeeds and the mediator sees
plaintext.

### 4. Egress policy and recording

- [ ] On CONNECT or on the TLS handshake, write `EgressAttempt` **before** evaluating policy.
- [ ] Evaluate, then write `EgressDecision` with the rule that decided it.
- [ ] `Sync()` immediately after a denial. The denial is the evidence the bundle exists to carry; a
      crash straight afterwards must not erase it.
- [ ] On allow, record `LLMRequest`, then `LLMResponseChunk` per chunk, then `LLMResponseEnd`.

**Acceptance.** `hark verify` on the produced bundle reports `VERIFIED`, and `hark inspect` shows the
attempt/decision pair with the denial.

### 5. Secrets broker

- [ ] Populate the agent's environment with `hark-placeholder-<runid>` per configured secret.
- [ ] On egress to an allowlisted host, substitute the real value in headers and body.
- [ ] Record `SecretInjected` by reference: logical name, placeholder, host, and optionally a hash of
      the real value. **Never the value.**

**Acceptance.** A test asserts the real secret appears nowhere in the bundle bytes. Write this test
first — it is the one whose failure would be worst.

### 6. `hark run`

- [ ] Wire policy → broker → mediator → launcher → bundle.
- [ ] Write `RunStart`, `PolicyLoaded`, `EnvSnapshot`, `FsManifest` at start; `RunEnd` at exit.
- [ ] Seal on clean exit; `Abort` on signal, leaving a verifiable prefix.

**Acceptance.** `hark run` then `hark verify` then `hark inspect`, end to end, with a denial in the
middle. Then `kill -9` the run and confirm `hark verify` reports `TRUNCATED` with a sensible prefix.

## Traps

**Landlock cannot express host-based network policy.** Its network rules are port-based — ABI v4 for
TCP, v10 for UDP. It cannot say "allow api.google.com, deny evil.example". That is exactly why the
design routes through a mediating proxy. Use Landlock for the filesystem, where it is the right tool.
See ADR-0003.

**seccomp cannot filter `connect()` by address.** Filters cannot dereference pointer arguments, so
`sockaddr` contents are unreachable, and reading them from userspace afterwards is a TOCTOU race. The
correct construction is `SECCOMP_USER_NOTIF` with `pidfd_getfd`. Not needed here — the namespace makes
the question moot — but know why, because it gets asked.

**Landlock ABI versions differ across kernels.** Query the supported ABI and degrade explicitly rather
than assuming. A silent no-op is the worst outcome: it looks contained and is not. If the required ABI
is unavailable, refuse to run.

**Go's threading versus namespaces.** `setns` applies per-thread, and the Go runtime moves goroutines
between threads. Do the namespace work in a locked thread (`runtime.LockOSThread`) or, more simply,
do it in the child between `fork` and `exec` — which in Go means re-executing the binary with a
sentinel argument and doing the setup there before `syscall.Exec`. Decide this early; retrofitting is
painful.

**Cert-pinning clients will refuse the CA.** Document it, do not fight it. The in-process shim in W3
is the workaround.

**Recording the response body while streaming it.** Do not buffer the whole response and forward it
afterwards — that breaks streaming agents and destroys the chunk boundaries W3 depends on. Use
`io.TeeReader`, record chunks as they pass, and forward immediately.

## Definition of done

- [ ] `go build ./...` on both Linux and Windows (stubs cover the non-Linux path).
- [ ] `go vet ./...` clean, `gofmt -l .` empty.
- [ ] `go test ./... -count=1` and `-race` green.
- [ ] The two launcher acceptance commands behave as specified.
- [ ] A bundle from a real run verifies, and its inspect output shows the denial.
- [ ] A test asserts no real secret appears in bundle bytes.
- [ ] `docs/build-log.md` entry; `docs/architecture.md` "not yet built" list trimmed;
      `docs/security.md` control table statuses moved from W2 to done; roadmap ticked; CHANGELOG
      updated.
- [ ] Any new decision captured as an ADR — the launcher's fork/exec approach probably deserves one.

## Expected commits

```text
feat(policy): load and validate the TOML allowlist
feat(launcher): contain the agent in a network namespace
feat(launcher): scope the filesystem with Landlock and seccomp
feat(mediator): terminate TLS with a per-run CA
feat(mediator): evaluate egress policy and record both sides of the decision
feat(broker): keep real credentials out of the agent's address space
feat(cli): add hark run
docs: record the W2 containment work
```
