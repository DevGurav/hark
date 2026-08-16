# Build log

Newest first. Append-only.

---

## 2026-08-16 — the mediator listens

DNS responder, TLS termination, policy evaluation and the forwarding path. Written off-VM, because
none of it needs a kernel feature: bind address and ports became configuration, so the whole server
runs on loopback with high ports in tests and differs from a real run only in using the veth address
and 53/443.

**Where the total order comes from.** Recording happens under one lock in the mediator. That is the
only place concurrent boundary crossings are ordered, and it is what replay will follow. It
deliberately stops at the boundary: two threads racing on a dict inside the agent are not ordered by
anything here, and the replayer is meant to detect that rather than pretend otherwise.

**Denials are synced, and the attempt is written first.** A denial is the evidence the bundle exists
to carry, so a crash immediately afterwards must not be able to erase it. Writing the attempt before
the verdict means a crash between the two still leaves the attempt on the record.

**A connection with no SNI is denied, not allowed.** That is a literal-IP dial. Policy is expressed
in host names, so a connection carrying none cannot match it, and defaulting to permit would make
skipping DNS an escape hatch.

**The broker's guarantee, tested from both ends.** The recorded request holds the placeholder; only
the copy sent upstream holds the credential. That is structural rather than careful, because Inject
returns copies instead of mutating -- so the recorded request cannot accidentally be the injected
one. The test asserts the upstream received the real value *and* that neither the recorded request
nor the SecretInjected event contains it.

**ALPN pinned to http/1.1.** Letting the client negotiate h2 would mean unpacking framed
multiplexing before anything could be recorded per request, for throughput no agent notices beside
model latency.

**Occurrence ordinals now, matching later.** One run can send byte-identical requests and get
different answers -- a retry after a 429 is the ordinary case. The ordinal is recorded now so W3 has
it; headers stay out of the key for the moment, since they carry the injected credential and
canonicalising them properly is the two-day job that belongs with the replay work.

**A fixture bug worth noting.** The forwarding test first failed with an empty placeholder: the test
policy had no `[secrets]` mapping, and the broker takes environment-variable names from there. The
test now asserts the placeholder is non-empty before proceeding, so the same mistake fails with a
sentence rather than a confusing diff.

**Verified.** 109 tests, 156 with subtests, across 9 packages. Build, vet, gofmt clean; race clean.

**Next.** `hark run`: wire policy, broker, mediator, launcher and bundle together, write
`/etc/netns/<ns>/resolv.conf`, and run the whole thing on the VM against a real `curl`. That closes
W2.

---

## 2026-08-16 — the launcher: containment working end to end

The three restriction layers now actually reach an agent, via the re-executed init child that ties
them together. `ADR-0007` has the design; this is what building it taught.

**The integration test earned its place immediately.** Every unit test passed while the whole thing
was broken. `DropCapabilities` reads `/proc/sys/kernel/cap_last_cap`, and it ran *after* Landlock had
already made `/proc` unreadable — so the drop failed and the agent kept root's capabilities. Reading
the code, the order looked fine; the original comment even justified it, claiming the earlier steps
still needed `CAP_SYS_ADMIN`. They do not. Landlock is built for unprivileged callers and seccomp
needs only `NO_NEW_PRIVS`.

Fixed by dropping capabilities first, which is the better default anyway: everything after that line
runs unprivileged, so a mistake in it has less to work with.

**A second correction, this one to the design.** The original plan was a namespace with *no default
route*, on the theory that no route means no escape. True, and useless: the packet dies in the
routing table, the mediator never sees it, and nothing is recorded. The default route now points at
the mediator, with explicit `FORWARD` DROP rules so the host cannot route onward regardless of its
global `ip_forward` setting. Traffic reaches the mediator or it reaches nothing. This is ADR-0006
arriving in the code.

**A leak worth finding.** A veth pair is reaped with its namespace — deleting either end takes both —
so teardown is usually a no-op on the success path. The `iptables` rules are *not* reaped. A
supervisor killed before teardown leaves two rules naming an interface that no longer exists. They
are inert, but they accumulate for as long as the host is up. Every run now prunes stale
`hk`-prefixed rules before starting, so hark cleans up after its own past failures without anyone
needing to know it should. Tests cover both directions: stale rules go, live and unrelated ones stay.

That same fact caused a test failure that looked like a bug and was not: `TestTeardownRemovesTheBoundary`
checked for the host interface after launching `true`, which had already exited and taken the veth
with it. The agent sleeps now.

**Verified.** Full launcher suite green as root on kernel 6.17: the agent runs, exit codes propagate,
there is no route to the internet even with every proxy variable unset, the routing table contains
nothing but the mediator, the audit log is unreadable, granted paths work, `CapEff` is all zeros
despite a root supervisor, and `Seccomp: 2` confirms a filter is installed. Full suite green
unprivileged and under `-race`. Zero stray interfaces or rules afterwards.

**Next.** Bind the DNS responder and the TLS listener on the mediator address, record the boundary
crossings, and wire it together behind `hark run`.

---

## 2026-08-16 — seccomp, capabilities, and the DNS message layer

**Seccomp.** Hand-assembled classic BPF rather than libseccomp, which would drag cgo and a system
library onto every build host for a filter of about thirty instructions.

The architecture check earns its place. On x86_64 a process can issue 32-bit syscalls where the
numbers mean different things, so a filter matching numbers without pinning the ABI can be sidestepped
by calling through the other one. That case is killed rather than refused, because it cannot be an
accident.

Denials return EPERM rather than killing the process. The call is refused either way, but an error the
runtime can surface beats a process that vanishes and leaves whoever is debugging it with nothing.

Most of what the filter denies also needs a capability the child will not hold, so it is genuinely
defence in depth. The exceptions justify it on their own: `ptrace` and `process_vm_readv` work between
processes of the same user with no capability at all.

**Capabilities.** The order is fixed and not obvious. Dropping the bounding set needs `CAP_SETPCAP`, so
it must happen while capabilities are still held — clearing the permitted set first would strand the
bounding set populated with nothing left able to empty it, and a populated bounding set is exactly what
lets a setuid binary hand capabilities back across execve. Ambient goes first, since that is the set
designed to survive exec.

`cap_last_cap` comes from `/proc` rather than a constant. The list grows between releases, and a value
compiled in today would silently stop dropping the newest capabilities on a newer kernel — the ones
least likely to be audited.

**DNS message layer.** Written off-VM, since wire-format parsing needs no kernel.

The decision worth recording: non-A queries get NOERROR with an empty answer section, never NXDOMAIN.
NOERROR says the name exists but has no record of that type, so the client falls back to A and reaches
the mediator. NXDOMAIN would convince it the name does not exist at all and it would give up without
connecting — losing the connection *and* the SNI observation that ADR-0006 depends on.

Compression-pointer following is bounded at sixteen jumps, with a test that fails on non-termination
rather than trusting the bound. A name pointing at itself is the standard way to hang a resolver, and
hanging here would stall the run being recorded.

**Testing.** Both new pieces are checked against real implementations rather than fixtures. The
seccomp and capability work runs in helper subprocesses and measures whether the kernel actually
refused. The DNS layer is driven by Go's own `net.Resolver` over loopback UDP, which also exercises
the AAAA-fallback path for free — the resolver asks for AAAA, gets an empty NOERROR, retries with A.

**Verified.** 17 launcher tests green on the box; full suite green on both machines; DNS fuzzing 1.6M
executions clean.

**Next.** The netns/veth setup and the re-exec init child that ties Landlock, seccomp and the
capability drop together. Needs the VM.

---

## 2026-08-16 — Landlock, against the real kernel

First session working directly against the VM rather than writing code to be tested later. Edits
happen locally, sync to the box, build and test there — so the repo's git history and identity stay
on one machine while the syscalls get exercised on another.

**What landed.** `internal/launcher/landlock_linux.go`: ABI probe, rights masked to what the running
kernel supports, `NO_NEW_PRIVS`, `restrict_self`. A build-tagged stub covers non-Linux hosts so the
pure-logic packages still build on Windows — and the stub returns an error rather than succeeding
quietly, because a containment layer that reports success while doing nothing is the exact failure
this project exists to prevent.

**Two kernel facts worth writing down**, both now enforced by the code and its tests.

`landlock_restrict_self` restricts the *calling thread*, not the process. Go moves goroutines between
threads whenever it likes, so this cannot be called from an ordinary goroutine and trusted. It needs
`runtime.LockOSThread` with `execve` following on the same thread. That is the concrete justification
for the re-exec design the launcher will use — not a stylistic preference borrowed from runc.

An empty ruleset denies everything rather than allowing everything. A policy granting no paths
therefore fails closed, which is the right direction, but it is the sort of thing someone later
"simplifies" into an early return.

**Testing shape.** Landlock cannot be tested in-process, since the first test would restrict the test
binary and every later test would inherit that domain. So the tests re-execute the test binary as a
helper, apply a ruleset, attempt one filesystem operation, and read the answer from its exit code.
That measures whether the kernel actually refused rather than whether a syscall returned zero, which
is the whole difference between containment and the appearance of it.

`TestRealisticLayout` is the one to point at: the agent reads its own source, writes its workspace,
and can neither read nor write the bundle it is being recorded into.

**A dependency trap.** `go get golang.org/x/sys/unix` silently raised the module's Go directive to
1.25, which would have broken the VM's 1.23.5 toolchain and CI both. The bump came from the latest
x/sys and persisted after pinning an older one, because Go never lowers the directive on its own.
Set back to 1.23.0 by hand; the pinned x/sys builds fine there.

**Verified.** Landlock ABI 7 on kernel 6.17. Eight enforcement tests green on the box, full suite
green on both machines, vet and gofmt clean.

**Next.** Seccomp and capability drop, then the netns/veth setup and the re-exec init child that ties
them together.

## 2026-08-16 — W2 begins: policy loader and SNI parser

Started W2 with the parts that have no kernel dependency, so they could be written with the VM
stopped. Only netns, Landlock and seccomp actually need the box running, and leaving it up while
typing burns credit for nothing.

**Policy.** An allowlist, not a language. The interesting decisions are all about failing loudly:
wildcards rejected rather than half-implemented, unknown keys rejected rather than ignored, duplicate
and malformed hosts rejected. Each of those, done the lenient way, produces a policy that reads as a
restriction and behaves as an omission — which is the worst possible defect in this component.

`Load` returns the raw file bytes next to the parsed policy so `PolicyHash` covers what was actually
on disk. A re-serialisation would drop comments and formatting, and the artifact a reviewer diffs is
the file.

**A portability bug the tests caught.** `filepath.Clean("/app")` returns `\app` on Windows. Policy
paths describe locations inside a Linux namespace, so they must be cleaned with `path.Clean`
regardless of which OS parses them. Worth noting in the W2 spec because the launcher will face the
same trap.

**SNI.** The mediator learns the agent's intended destination from the ClientHello, and those bytes
come from the untrusted process. Everything goes through a bounds-checked cursor; a panic here would
take down the process holding the signing key and the audit log, on input the agent chooses.

Three outcomes stay distinct rather than collapsing into "error", because callers act differently on
each: still arriving (read more), not TLS (reject), valid but no SNI (record with an empty host —
what a literal-IP dial looks like).

The recovered name is validated before reaching policy or the log. Control characters could forge log
lines. Refusing beats sanitising, since a cleaned-up name might still match a rule it should not.

Tested against ClientHellos generated by Go's own TLS stack rather than hand-written fixtures, which
checks the parser against what clients actually send instead of against my reading of the RFC. Every
truncation prefix and every single-byte corruption of a real hello is exercised. Fuzzing ran ~2M
executions with no crash.

**Verified.** Full suite green, vet and gofmt clean.

Continued in the same session with the other two kernel-independent pieces.

**Broker.** The design decision worth recording is that `Inject` never mutates its inputs. It works
on copies and returns them, so the caller records the originals — which still hold placeholders — and
sends the copies. The alternative is a rule every call site has to remember, and forgetting once puts
a live credential into an artifact designed to be published. Structural beats documented here.

Two smaller things that would have been bugs. Placeholders carry both the run id and the logical
name: without the logical name, substitution cannot tell two secrets apart. And values are replaced
longest-first, because if one secret's value contains another's, replacing the shorter first mangles
the longer, which then fails to match and travels unsubstituted.

`Inject` also refuses to substitute for a denied host even though the mediator checks policy first.
Redundant by design — if that check regresses, the credential still does not travel.

**CA.** Fresh per run, memory only, P-256, 24-hour validity, path length constrained to zero, private
key with no accessor. A CA on disk can be stolen; one outliving its run can forge certificates long
after. Regenerating costs milliseconds against a standing risk.

Tested end to end through a real `tls.Listen` and a real client trusting only that CA. That is what
proves interception is transparent to the agent — asserting on certificate fields would not. The
converse matters too and is covered: a client with default roots must be rejected, and run B's CA
must not validate run A's leaf.

**Verified.** 88 tests, 118 with subtests, across 8 packages. Build, vet, gofmt clean.

**Next.** The off-VM work is done. One focused VM session remains for W2: the launcher (netns,
Landlock ABI detection, seccomp, capability drop), the DNS responder, egress recording, and wiring it
all behind `hark run`.

---

## 2026-08-16 — W0: the box, and a hole in the containment design

Provisioned the target machine and ran the prototype. It found a real defect in the design, which is
exactly what the phase was for.

**The box.** Ubuntu 24.04 on Azure, kernel 6.17, 2 vCPU / 3.8 GiB. `landlock` is in the active LSM
list at **ABI version 7**, so no kernel command-line surgery was needed and the full ruleset feature
set is available. No inherited seccomp filter, so the launcher is free to install its own. The repo
builds and its tests pass there, including under `-race`, which the Windows box cannot run for want
of cgo.

Before that box existed I ran the same probe in a hosted shell, which reported
`capability,lockdown,yama,loadpin,safesetid,apparmor,bpf` — no `landlock`. Namespaces, veth and
seccomp all worked there; only filesystem scoping did not. Worth recording because it is the
signature of every container-based environment, and it is now in `docs/troubleshooting.md`.

**Containment, proven rather than assumed.** A network namespace with a veth pair and a single link
route. A process inside it cannot reach the network. A process that unsets `HTTPS_PROXY`,
`https_proxy` and `ALL_PROXY` also cannot reach the network, because the routing table is the control
and the environment variable is only a convenience. TLS interception with a per-run CA works and is
transparent to the client — `curl` reported `ssl_verify_result=0` while the mediator logged the full
plaintext request and response.

**The defect.** The original design was netns with no default route plus `HTTPS_PROXY`. Cooperating
agents go through the mediator; non-cooperating ones have no route and fail. Safe, but *silent*: the
packet dies at the routing layer, the mediator never sees it, and nothing is recorded. The project
claims every attempt to cross the boundary is on the record, and that claim was breaking in precisely
the case that matters most — the agent that is misbehaving.

The prototype surfaced it concretely. With no resolver in the namespace, a non-cooperating `curl`
failed at DNS before any TCP connection existed, so the DNAT rule I had added never even fired. And
handing the namespace an ordinary resolver would have fixed that while opening a textbook
exfiltration channel, since DNS tunneling needs nothing more than the ability to resolve
attacker-chosen names.

**The fix**, now ADR-0006: the mediator serves DNS for the namespace and answers every A query with
its own address, then recovers the intended host from the TLS ClientHello's SNI. Verified end to end
— an agent with every proxy variable unset named `evil.example` twice, once in the DNS query and once
in the SNI, both at the mediator. Per-namespace resolver configuration needs no container runtime:
`ip netns exec` already bind-mounts `/etc/netns/<name>/` over `/etc/`.

A detail worth keeping: `SO_ORIGINAL_DST` is not merely unnecessary here, it cannot work. Conntrack
state for a DNAT performed inside the namespace is not visible to a process outside it. SNI sidesteps
the problem instead of fighting it.

**Verified.** Landlock ABI 7 confirmed by direct syscall probe. Three containment proofs. TLS
interception against two hosts. Mediated DNS and SNI recovery against an allowlisted host and a
disallowed one. Full test suite green on the target box under `-race`.

**Next.** The related-work table is the one W0 item still open — every row needs checking against the
actual project before the repo goes public. Then W2, which gained two tasks and two event kinds from
today's finding.

## 2026-08-16 — W1: bundle format, Merkle Mountain Range, verifier

Built the entire cryptographic and format layer, deliberately before touching anything kernel-related.

**Why this order.** W2 and W3 — the launcher and the replayer — are the two highest-variance weeks,
and they are consecutive. Starting there risks a fortnight with nothing to show. The bundle format
has no kernel dependencies, runs identically on Windows and Linux, and is the piece hardest to fake
later: a verifier that catches tampering is either real or it is not. So it went first.

**What landed.**

- `internal/hashchain` — three domain-separated BLAKE3 constructions. The prefix bytes are the
  second-preimage defence RFC 6962 uses for Certificate Transparency, and the tests assert the
  separation directly rather than assuming it.
- `internal/mmr` — flat post-order node array, `TrailingZeros(n)` merges per append, peaks bagged
  right-to-left. Inclusion proofs carry no direction bits: direction is derived from the leaf index
  during verification, so a forger cannot choose them.
- `internal/logfmt` — 16 event kinds with frozen numeric values, canonical CBOR payloads with
  integer keys, and a frame codec that stores the leaf hash alongside the payload.
- `internal/signer` — Ed25519 signed tree heads over a length-prefixed, domain-separated input.
- `internal/bundle` — writer, reader and verifier.
- `internal/runid` — ULIDs, chosen over UUIDv4 so a directory of bundles lists chronologically.
- CLI: `verify`, `inspect`, `prove`, `synth`, `keygen`.

**Two design points worth recording.**

Storing the leaf hash in each frame rather than recomputing it on read looked redundant at first. It
is what lets the verifier distinguish an edited payload from a reordered log: if the stored leaf
disagrees with the recomputed one, those bytes changed; if the leaf agrees but the chain link does
not, the frame is intact but was moved. Two different failures, two different remedies, and a
verifier for an audit tool should say which.

Keeping both a hash chain and an MMR seemed like belt and braces until the crashed-run case came up.
An MMR root only exists once sealed, so a `SIGKILL`ed run would have had no verifiable structure at
all. The chain gives streaming integrity over whatever was written. `hark verify` now reports
`TRUNCATED` with the surviving prefix and exit code 3 — a killed run is a real state, not a failure.

**Bugs found while building.**

`climb` collected sibling hashes top-down while `Verify` derived direction bits bottom-up. Every
proof for a mountain taller than one level would have failed. Caught by writing the exhaustive
round-trip test before trusting the implementation — sampling a few leaf counts would very likely
have missed it, since single-leaf mountains verify fine either way.

First pass at the verifier reported zero events and a zero root when it hit a fault, discarding the
prefix that had verified. Fixed to report how much of the run survived. Related: the fault message
was printed as `seq 9: seq 9: ...` because both `Validate` and the CLI prefixed it. `Validate` no
longer includes the sequence number — the caller has it.

Also: `hark verify -key` printed `VERIFIED` above a line saying the pinned key did not match. Now
`REJECTED`. For a tool whose entire pitch is precise reporting, a headline that contradicts the
detail below it is the worst possible defect.

**Verified.** 47 tests (52 with subtests) across 6 packages, `go vet` clean. End-to-end by hand:
keygen → synth → verify → inspect → prove → prove -check, plus the three negative paths (corrupted
payload, truncated run, pinned-key mismatch) each producing the right output and exit code.

**Next.** W0 groundwork, which W1 jumped ahead of: provision the Linux box, prototype netns + veth +
MITM in throwaway shell before writing any Go for it, and verify the related-work table against the
actual repositories rather than against summaries. Then W2, the launcher.
