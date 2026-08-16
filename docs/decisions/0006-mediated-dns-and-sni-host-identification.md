# 0006 — Mediated DNS and SNI-based host identification

Status: accepted
Date: 2026-08-16

## Context

W0's prototype exposed a hole in the containment design that the architecture document did not
account for.

The original model was a network namespace with no default route, plus `HTTPS_PROXY` pointing at the
mediator. A cooperating agent goes through the mediator; a non-cooperating one has no route and
fails. That reads as fail-closed and safe.

It is safe. It is also **silent**, and silence is a defect here. An agent that ignores its proxy
variables never reaches the mediator, so no `EgressAttempt` is recorded and the bundle contains no
evidence that anything was attempted. The project claims every attempt to leave the boundary is on
the record. Dropping the packet at the routing layer breaks that claim precisely in the case that
matters most — the agent that is not behaving.

A second hole sat underneath the first. With no resolver in the namespace, the prototype's
non-cooperating client failed at DNS, before any TCP connection existed. Giving the namespace a
normal resolver would fix that and simultaneously open a textbook exfiltration channel: DNS tunneling
needs nothing but the ability to resolve attacker-controlled names.

## Decision

The mediator serves DNS for the namespace, and answers every A query with its own address. The agent
then connects to the mediator for any host it tries to reach, and the mediator recovers the intended
hostname from the TLS ClientHello's SNI field.

Per-namespace resolver configuration uses the kernel's existing mechanism: `ip netns exec` bind-mounts
`/etc/netns/<name>/` over `/etc/`, so `/etc/netns/harkns/resolv.conf` becomes the namespace's
`resolv.conf` with no container runtime involved.

Both the DNS query and the SNI are recorded as events, and both are policy decision points.

## Consequences

- **Every attempt is recorded, including from agents that ignore all proxy configuration.** Verified
  in W0: a `curl` with `HTTPS_PROXY`, `https_proxy` and `ALL_PROXY` all unset still produced a DNS
  query and a TLS connection at the mediator, both carrying `evil.example` in full.
- **DNS stops being an exfiltration channel.** The only resolver reachable from the namespace is the
  mediator, so a name lookup is a mediated, recorded, policy-checked event rather than a covert
  write primitive.
- **Two independent observations of intent.** The DNS query and the SNI both name the destination. A
  disagreement between them is itself a signal worth recording.
- `SO_ORIGINAL_DST` is not needed, which matters more than it first appears — the conntrack state for
  a DNAT performed inside the namespace lives in that namespace, so a mediator running outside it
  could not query the original destination anyway. SNI sidesteps the problem rather than working
  around it.
- The mediator must bind privileged ports (53 and 443). It runs as the supervisor, which already
  needs `CAP_NET_ADMIN` to create the namespace, so this adds no new privilege requirement.
- W2 gains two event kinds, `DnsQuery` and `DnsDecision`, following the existing
  `EgressAttempt`/`EgressDecision` shape. They take the next free numbers; existing numbers are
  untouched.

## Limitations

- **Non-TLS traffic carries no SNI.** Plain HTTP must be identified from the `Host` header instead,
  and a raw TCP connection to a resolved name can only be attributed via the DNS query that preceded
  it. Recording the DNS query is what makes that attribution possible at all.
- **Encrypted ClientHello would hide the SNI.** Not a concern today for the model endpoints in scope,
  and the DNS query still names the host. Worth revisiting if ECH becomes common.
- **An agent that dials a literal IP address skips DNS entirely.** It still reaches the mediator,
  because there is nowhere else to route, but the mediator has no hostname for it. Policy in that
  case can only be evaluated on the address. Recorded as an attempt with an empty host rather than
  silently allowed.
- **DNS answers are deliberately wrong.** Every A record points at the mediator. Anything that
  validates DNS answers independently — DNSSEC, or a client that compares the resolved address to a
  pinned value — will notice. This is the same class of visibility as the TLS interception and is
  documented alongside it.

## Alternatives considered

**No resolver, no default route (the original design).** Rejected on the recording gap above. Its
one virtue is simplicity, and the cost is that the most interesting failure mode leaves no trace.

**Real DNS plus DNAT to the mediator.** Would preserve genuine resolution, but leaves DNS itself
unmediated and therefore usable for exfiltration, and needs `SO_ORIGINAL_DST` to recover the intended
destination — which does not work across a namespace boundary.

**Forcing proxy environment variables and refusing to run without them.** Unenforceable. The agent
can unset them, and the whole premise of the threat model is that the agent's behaviour is not
trusted.
