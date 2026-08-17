# 0009 — Upstream redirection is recorded, not hidden

Status: accepted
Date: 2026-08-17

## Context

Two things v0.1 needs cannot be built against a live endpoint.

The demo has to run from a clean clone with no API key, no cost and no network, or nobody will run
it. And the benchmarks explicitly must not measure a hosted model: upstream latency varies by orders
of magnitude with load and would swamp everything else being measured.

Both need the mediator to dial somewhere other than the host the agent asked for.

That is a testing seam pointed directly at the project's central claim. A bundle whose events name
`model.example` while the mediator actually spoke to a stub on loopback would be a lie of exactly the
kind the format exists to prevent — and it would be invisible to every check `hark verify` performs,
because the bundle would be internally consistent.

## Decision

`-upstream HOST=ADDR` redirects a host's traffic, and **the mapping is recorded in `RunStart`**
(payload key 10, sorted `host=addr` strings, empty for an ordinary run).

Three constraints keep it from becoming a hole:

- A redirected host still has to be in the policy allowlist. The redirection changes where a
  connection goes, never whether it was permitted.
- TLS still verifies the name the agent asked for. A stub must hold a certificate for the host it
  stands in for, named with `-upstream-ca`, so the redirection does not also become an identity
  exemption. The alternative — skipping verification for redirected dials — would silently weaken
  every connection an operator did not think of as a stub.
- The mapping is surfaced everywhere a human reads a run: `hark inspect`, the HTML report's first
  row, and the demo's own README.

`hark replay` carries the recorded value through into its own `RunStart` rather than rebuilding it. A
replay dials nothing, so the redirection cannot apply to it — but it is part of the run's starting
conditions, and dropping it would report a divergence on every replay of a run that used one.
`hark fork` defaults to the recording's mapping, because a live suffix has to reach the same world
the recording did.

## Consequences

- A bundle can never quietly claim it reached a host it did not. The claim it makes is checkable
  against one field.
- The replay digest includes `RunStart`, so a bundle recorded against a stub and replayed as though
  it were not would diverge at action 0. The check is structural rather than a convention.
- The demo is hermetic and the benchmarks are meaningful, at the cost of one flag and one payload
  field.

## Alternatives considered

**Leave it out and require a real endpoint.** The demo then needs an API key and a network, which
means most people who clone the repo never run it, and the benchmark numbers become unrepeatable.

**Redirect without recording it.** Rejected outright. It would make the most convenient way to
produce a demo bundle also the way to produce a dishonest one.

**A hosts-file or DNS override instead of a flag.** The mediator already answers every DNS query with
its own address, so this would have to happen at the dial. Doing it through the environment would put
the redirection outside the artifact, which is the whole thing being avoided.
