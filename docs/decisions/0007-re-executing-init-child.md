# 0007 — The launcher re-executes its own binary

Status: accepted
Date: 2026-08-16

## Context

Three containment layers have to be in place before the agent's code runs: a network namespace, a
Landlock ruleset, and a seccomp filter, with every capability dropped. Landlock and seccomp are both
inherited across `execve`, which is what makes them useful — but both restrict the **calling thread**,
not the process.

Go moves goroutines between OS threads whenever it likes. There is no way to apply a per-thread
restriction from an ordinary goroutine and be confident the thread that eventually calls `execve` is
the restricted one.

Go also offers no safe hook between `fork` and `exec`. A forked child of a Go program may only call
async-signal-safe operations before exec, which rules out nearly everything the setup needs: opening
paths for Landlock rules, reading `/proc`, allocating.

## Decision

The supervisor re-executes its own binary with a sentinel first argument, `__hark-init`. That child
process locks its thread, applies every restriction on it, and calls `execve` on the same thread.

`runc` solves the same problem the same way, for the same reason.

```text
parent                              init child
------                              ----------
clone(CLONE_NEWNET) ─────────────►  start, lock thread
write spec to fd 3 ──────────────►  read spec
create veth, move peer into ns
configure both ends
write "go" to fd 3 ──────────────►  unblock
                                    chdir, resolve the binary
                                    drop capabilities
                                    Landlock, seccomp
                                    execve(agent)
```

## Consequences

- The per-thread constraint is satisfied structurally rather than by convention. Nothing in the child
  spawns a goroutine, so there is no thread for the restrictions to be applied to except the one that
  execs.
- The child blocks on a pipe read until the boundary exists. Without that barrier the agent could
  start — and make network calls — before the namespace it is supposed to be inside was built.
- The spec crosses as length-prefixed JSON on fd 3. An EOF instead of the release byte means the
  parent gave up, and the child exits rather than running an agent with no containment around it.
- `main` has to branch on the sentinel before anything else. The child is a different process role,
  not a subcommand, and must not touch flags or any global state.
- The binary must be able to re-execute itself, so `/proc/self/exe` has to be readable. That is true
  everywhere hark runs.

## Ordering, learned the hard way

Capabilities are dropped **first**, then Landlock, then seccomp. The first attempt had capabilities
last, on the reasoning that the earlier steps might still need privilege. They do not — Landlock is
designed for unprivileged callers and seccomp needs only `NO_NEW_PRIVS` — and the order was actively
wrong: `DropCapabilities` reads `/proc/sys/kernel/cap_last_cap`, which Landlock had already made
unreadable. The drop failed and the agent kept root's capabilities.

The unit tests all passed. The integration test caught it, which is the argument for having one.

Dropping privilege at the earliest possible point is the better default anyway.

## Alternatives considered

**`runtime.LockOSThread` in the parent, then `syscall.Exec`.** Would work for a process that only
ever launches one agent and then becomes it, but the supervisor has to outlive the agent — it holds
the mediator, the log and the signing key.

**A separate helper binary.** Avoids the sentinel-argument branch in `main`, at the cost of a second
artifact that has to be found at runtime, kept in step with the supervisor, and shipped alongside it.
Re-executing `/proc/self/exe` is always the matching build.

**cgo, doing the setup in a C constructor before the Go runtime starts.** This is what some container
runtimes do. It works, and it drags cgo into every build of a project that otherwise has no need of
it. Not worth it for a sequence that fits in one function.

**Applying the restrictions after exec, from inside the agent.** Requires the agent to cooperate,
which the threat model assumes it does not.
