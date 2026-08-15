# 0001 — Go for the runtime

Status: accepted
Date: 2026-08-16

## Context

`hark` is a supervisor process that creates network namespaces, applies Landlock and seccomp
policies, terminates TLS, and maintains an append-only hashed log. It ships as a single binary that
wraps an arbitrary child process. The language choice has to serve three things at once: direct
access to Linux security syscalls, a credible story for the determinism claim the project is built
on, and delivery inside an eight-week window.

Three candidates were real: Java, Go, Rust.

## Decision

Go, with no second language for the enforcement layer.

## Consequences

- Direct access to what the design needs: `vishvananda/netns`, `landlock-lsm/go-landlock`,
  `libseccomp-golang`, and `net/http` plus `crypto/tls` for the mediating proxy.
- A single static binary with no runtime to install, which matters for a tool whose job is to be the
  outermost process in someone else's container.
- `cilium/ebpf` is the most mature eBPF binding in any language, which keeps the W3 upgrade path open
  without a rewrite.
- Go's garbage collector introduces timing nondeterminism in the supervisor. This is tolerable
  because determinism here is a property of *recorded event ordering*, not of wall-clock timing: the
  mediator imposes a total order on boundary crossings and replay follows that order. The GC can
  move when events happen without moving what order they happened in. It would not be tolerable if
  `hark` claimed timing fidelity, which it does not.

## Alternatives considered

**Java.** Rejected on the merits, despite being the language I have the most systems experience in
after writing a Netty-based Redis-compatible server. There is no credible JVM path to Landlock,
seccomp or netns without JNI shims around every call. Worse, a JIT that deoptimises and a GC that
pauses are exactly the wrong foundation under a project whose thesis is determinism — the irony
would have to be defended in every conversation about it. Range matters more than reuse here.

**Rust.** The strongest technical fit and the one I expect to regret not taking. `landlock`,
`seccompiler`, `aya` and `rustls` are all first-class, there is no GC, and startup is immediate.
Rejected on schedule risk rather than on merit: the mediator is a TLS-intercepting async proxy, and
`hyper` + `rustls` + `tokio` lifetimes is precisely the region of Rust where progress is least
predictable. With placements running concurrently, an unfinished Rust implementation is worth far
less than a finished Go one, and the asymmetry is severe enough to decide it.

Revisit at v0.3: porting the launcher alone to Rust is a bounded piece of work once the format and
the protocol have stopped moving.
