# 0003 — Network namespaces, not eBPF, for v0.1

Status: accepted
Date: 2026-08-16

## Context

The containment pillar has to stop a prompt-injected agent from reaching a host the policy does not
allow, and it has to do so from outside the agent's control. eBPF is the fashionable answer and
several peer projects use it. It is also three weeks of work I do not have.

## Decision

For v0.1, put the agent in its own network namespace with a single veth pair to the mediator and no
other route. Enforcement of *which host* is allowed happens in the mediator, which is the only thing
the agent can reach.

eBPF moves to v0.3, for per-tool-call scoping and for agents that fork non-Python children.

## Consequences

- The namespace already delivers what the demo needs. There is no route out; a process that ignores
  `HTTPS_PROXY`, spawns a child, or writes its own socket code still has nowhere to send packets.
  Enforcement is kernel-level and out-of-process, and an unprivileged agent cannot undo it.
- `HTTPS_PROXY` becomes a convenience for well-behaved clients rather than the control. This is the
  answer to the most common interview question about this design.
- Egress denials are recorded as `EgressAttempt` followed by `EgressDecision`. The attempt is
  written before the verdict so that a process dying between the two still leaves the attempt on the
  record.
- What is given up: per-tool-call granularity. Every request from the agent looks the same to the
  namespace, so policy can only be as fine-grained as the mediator can parse. Good enough when the
  policy is a host allowlist; not good enough for "this tool may reach this host, that one may not",
  which is the v0.3 motivation.

## Alternatives considered

**eBPF with tc-egress and a BPF LSM.** The right long-term answer for granularity. Rejected for
v0.1 on cost: roughly three weeks including verifier fights and CO-RE portability work, in exchange
for zero additional demo capability. eBPF buys *scoping granularity*, not the *existence* of
enforcement, and v0.1 needs the latter.

**Landlock for network policy.** Does not work, and the reason is worth writing down because it is
easy to assume otherwise. Landlock's network rules are port-based — ABI v4 for TCP bind/connect,
v10 for UDP — not host-based. It cannot express "allow `api.google.com`, deny `evil.example`". This
is precisely why the design routes through a mediating proxy instead. Landlock is still used, for
filesystem scoping, where it is exactly the right tool.

**seccomp filtering of `connect()` by address.** Cannot work directly: seccomp filters cannot
dereference pointer arguments, so the `sockaddr` contents are unreachable, and reading them from
userspace after the fact is a time-of-check/time-of-use race. The correct construction is
`SECCOMP_USER_NOTIF` with `pidfd_getfd` and notify-id validation. Noted for v0.3; unnecessary at
v0.1 because the namespace makes the question moot.

**Firecracker or gVisor.** Firecracker needs nested virtualisation, which the free-tier cloud
instances this is developed on do not offer, and adds 150 ms–2 s of cold start. gVisor adds 10–40%
syscall overhead. Neither changes what the demo shows.
