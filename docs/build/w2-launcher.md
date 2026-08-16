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

Confirmed working on kernel 6.6.143 during W0. These are the exact commands to translate into
`internal/launcher`, not a sketch to improvise from.

```sh
ip netns add harkns
ip link add veth-h type veth peer name veth-n
ip link set veth-n netns harkns
ip addr add 10.200.1.1/24 dev veth-h
ip link set veth-h up
ip netns exec harkns ip addr add 10.200.1.2/24 dev veth-n
ip netns exec harkns ip link set veth-n up
ip netns exec harkns ip link set lo up
```

The resulting routing table inside the namespace is one line, and that single line is the entire
containment story:

```text
10.200.1.0/24 dev veth-n proto kernel scope link src 10.200.1.2
```

A link route to the mediator and nothing else. No default route, so there is nowhere else to send a
packet.

Three properties were verified rather than assumed:

| Check | Result |
| --- | --- |
| `curl https://example.com` inside the namespace | blocked — no route |
| Same, with `HTTPS_PROXY` and `https_proxy` unset | still blocked — the namespace is the control, not the environment |
| `ping 10.200.1.1` (the mediator end) | reachable |

The second row is the one that gets asked about in review. An agent that strips its proxy variables,
spawns a child, or writes raw sockets still has no route, because the control is the routing table
and not a convention the process is trusted to honour.

### TLS interception, verified

A per-run CA, `mitmdump` bound to the mediator end, and a client inside the namespace:

```sh
curl --proxy http://10.200.1.1:8080 --cacert <ca>.pem https://example.com
# HTTP 200  ssl_verify_result=0
```

`ssl_verify_result=0` is the part that matters: the client validated the certificate against the
run's own CA, so interception is transparent to it. The mediator saw full plaintext:

```text
10.200.1.2:52634: GET https://example.com/ HTTP/2.0
      << HTTP/2.0 200 OK 559b
10.200.1.2:52644: GET https://api.github.com/zen HTTP/2.0
      << HTTP/2.0 200 OK 39b
```

### Mediated DNS and SNI, verified

An explicit proxy only works for a cooperating client, and a non-cooperating one must still be
*recorded*, not silently dropped. See
[ADR-0006](../decisions/0006-mediated-dns-and-sni-host-identification.md).

Per-namespace resolver, using the kernel's own mechanism — `ip netns exec` bind-mounts
`/etc/netns/<name>/` over `/etc/`:

```sh
mkdir -p /etc/netns/harkns
echo "nameserver 10.200.1.1" > /etc/netns/harkns/resolv.conf
```

The mediator answers every A query with its own address and reads the intended host from the TLS
ClientHello. Result, with `HTTPS_PROXY`, `https_proxy` and `ALL_PROXY` all unset:

```text
DNS      QUERY evil.example type 1
         QUERY generativelanguage.googleapis.com type 1
MEDIATOR CONNECTION FROM ('10.200.1.2', 42490) -> intended host: evil.example
         CONNECTION FROM ('10.200.1.2', 42496) -> intended host: generativelanguage.googleapis.com
```

An agent that ignores every proxy convention still names its destination twice, in full, at the
mediator. That is what makes "every attempt is on the record" true rather than aspirational.

Two notes for the implementation. The mediator binds 53 and 443, so it needs privileged ports — the
supervisor already requires `CAP_NET_ADMIN` for the namespace, so this adds nothing new. And
`SO_ORIGINAL_DST` is deliberately unused: DNAT conntrack state performed inside the namespace is not
visible to a process outside it, so SNI is not merely simpler here, it is the only thing that works.

### Environment caveats found in W0

**Landlock is unavailable in a container.** The W0 prototype ran in a hosted shell whose active LSM
list was `capability,lockdown,yama,loadpin,safesetid,apparmor,bpf` — no `landlock`. Namespaces,
veth and seccomp all work there; filesystem scoping does not. Everything in this phase except task 2's
Landlock step can therefore be developed in such an environment, but the Landlock path must be
verified on a real VM before W2 is called done.

This is a reason to get the capability detection right rather than a reason to wait: query the
Landlock ABI at startup and **refuse to run** when the required version is missing. A silent no-op
looks contained and is not.

**seccomp is not pre-applied.** `/proc/self/status` reported `Seccomp: 0` and `Seccomp_filters: 0`,
so no inherited filter constrains the launcher and it is free to install its own.

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
| `internal/mediator/dns.go` | Namespace resolver: answers every A query with the mediator address. |
| `internal/mediator/sni.go` | Recover the intended host from the TLS ClientHello. |
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

- [x] TOML with `allow_hosts`, `read_paths`, `write_paths`, `[secrets]`.
- [x] Reject wildcards with a clear error. v0.1 is exact-match only; a half-implemented wildcard
      matcher is a security bug waiting to happen.
- [x] Return the raw bytes alongside the parsed policy, so `PolicyHash` covers what was actually on
      disk rather than a re-serialisation of it.
- [x] Reject unknown keys, malformed hosts, relative paths and duplicate entries.

**Acceptance.** Unit tests: a valid policy parses, a wildcard is rejected, an unknown key is
rejected, and the same file always produces the same hash. **Done** — `internal/policy`.

Note for the launcher: policy paths are Linux namespace paths and must be cleaned with `path.Clean`,
never `filepath.Clean`, which rewrites `/app` to `\app` when the parsing happens on Windows.

### 2. Launcher

- [ ] Create a network namespace and veth pair. Address the host end and the namespace end; bring up
      `lo`. **Set no default route.**
- [x] Apply Landlock: read-only on `ReadPaths`, read-write on `WritePaths`, nothing else. The bundle
      path must not be reachable — `internal/launcher/landlock_linux.go`. ABI probed at startup and
      the run refuses below ABI 2; rights masked to what the kernel supports; `NO_NEW_PRIVS` set
      before `restrict_self`.
- [x] Drop all capabilities — `internal/launcher/caps_linux.go`. Ambient set, then bounding set, then
      permitted/effective/inheritable, in that order: dropping the bounding set needs `CAP_SETPCAP`,
      so clearing permitted first would strand it populated with no way left to empty it.
- [x] Apply a seccomp filter — `internal/launcher/seccomp_linux.go`. Hand-assembled classic BPF,
      architecture pinned, `EPERM` rather than kill so a denial is a debuggable error.
- [ ] Exec the child with the broker's placeholder environment.

Two constraints the Landlock work imposes on the launcher, both verified against the kernel:

`landlock_restrict_self` restricts the **calling thread**, not the process. Go moves goroutines
between threads freely, so it must run under `runtime.LockOSThread` with `execve` following on that
same thread. That is the concrete reason the launcher re-executes itself rather than doing the setup
in a goroutine, and it is what the init child exists for.

An empty ruleset **denies everything** rather than allowing everything, so a policy that grants no
paths fails closed. Worth knowing before someone "simplifies" the empty case.

**Acceptance.**

```sh
sudo ./hark run --policy testdata/deny-all.toml -- curl -s https://example.com   # must fail
sudo ./hark run --policy testdata/demo.toml -- sh -c 'unset HTTPS_PROXY; curl -s https://example.com'
```

The second is the important one: the agent stripped the proxy variable and still cannot escape,
because the namespace and not the environment is the control.

### 3. CA and TLS termination

- [x] Generate a fresh CA per run. Never persist it, never reuse one across runs —
      `internal/mediator/ca.go`. ECDSA P-256, 24h validity, path length constrained to zero, the
      private key has no accessor.
- [x] Sign leaf certificates on demand from the SNI, cached per host. A literal-IP dial lands in the
      IP SAN rather than the DNS SAN, or verification fails.
- [ ] Write the CA into the agent's trust store inside the namespace, and set `SSL_CERT_FILE`,
      `REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`. *(needs the launcher)*

**Acceptance.** `curl https://example.com` inside the namespace succeeds and the mediator sees
plaintext.

### 3b. Mediated DNS and SNI

Per [ADR-0006](../decisions/0006-mediated-dns-and-sni-host-identification.md). This is what makes a
non-cooperating agent's attempts recordable instead of silently dropped.

- [ ] Write `/etc/netns/<ns>/resolv.conf` pointing at the mediator; clean it up on exit.
- [x] DNS message layer — `internal/mediator/dnsmsg.go`. Query parsing with bounded compression-
      pointer following, A responses pointing at the mediator, and NOERROR-with-no-answers for
      everything else so clients fall back to A. Names are lower-cased at parse time and validated
      before they can reach policy or the log.
- [ ] Bind it: UDP listener on the mediator address, port 53. *(needs the VM)*
- [ ] Record `DnsQuery` and `DnsDecision` (next free event kind numbers — never renumber existing
      ones; update `docs/protocol.md` in the same commit).
- [x] Parse SNI from the ClientHello on the 443 listener to recover the intended host —
      `internal/mediator/sni.go`. Bounds-checked throughout, fuzzed, and validates the recovered name
      before it reaches policy or the log.
- [ ] Handle the cases ADR-0006 lists as limitations: plain HTTP falls back to the `Host` header, a
      literal-IP dial is recorded as an attempt with an empty host rather than allowed by default.

**Acceptance.** With `HTTPS_PROXY`, `https_proxy` and `ALL_PROXY` all unset, a request to a
disallowed host produces both a `DnsQuery` and an `EgressAttempt` naming that host, and is denied.

### 4. Egress policy and recording

- [ ] On CONNECT or on the TLS handshake, write `EgressAttempt` **before** evaluating policy.
- [ ] Evaluate, then write `EgressDecision` with the rule that decided it.
- [ ] `Sync()` immediately after a denial. The denial is the evidence the bundle exists to carry; a
      crash straight afterwards must not erase it.
- [ ] On allow, record `LLMRequest`, then `LLMResponseChunk` per chunk, then `LLMResponseEnd`.

**Acceptance.** `hark verify` on the produced bundle reports `VERIFIED`, and `hark inspect` shows the
attempt/decision pair with the denial.

### 5. Secrets broker

- [x] Populate the agent's environment with `hark-placeholder-<runid>-<logical>` per configured
      secret — `internal/broker`. The logical name is part of the token because two secrets sharing a
      placeholder could not be told apart at substitution time.
- [x] On egress to an allowlisted host, substitute the real value in headers and body. Inputs are
      never mutated: `Inject` works on copies and returns them, so the caller records the originals
      (holding placeholders) and sends the copies. Structural, rather than a rule to remember.
- [x] Refuse to substitute for a host the policy denies — a second check behind the mediator's, so a
      regression in the first one still cannot put a credential on the wire.
- [x] `ContainsSecret` for the recorder to assert against anything about to be written.
- [ ] Record `SecretInjected` by reference: logical name, placeholder, host, and a hash of the real
      value. **Never the value.** *(needs the mediator wiring; `Injection` already carries exactly
      these fields and nothing else)*

**Acceptance.** A test asserts the real secret appears nowhere in the bundle bytes. Write this test
first — it is the one whose failure would be worst. **Done** —
`TestRealSecretNeverLeavesTheBoundary`.

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
