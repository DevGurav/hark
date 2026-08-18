# Architecture

## Trust zones

```text
┌─ Zone 0: hark supervisor (trusted) ─────────────────────────┐
│  policy loader · secrets vault · log writer · Ed25519 key   │
│  MMR builder · Rekor client                                 │
│                                                             │
│  ┌─ Zone 1: mediator (same trust, separate task) ────────┐  │
│  │  DNS resolver (:53) · TLS terminator + SNI (:443)     │  │
│  │  HTTP/SSE recorder · MCP JSON-RPC router              │  │
│  │  egress policy · credential injector                  │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                      veth │  the trust boundary.
                           │  everything crossing it is an event.
┌─ Zone 2: agent process tree (UNTRUSTED) ────────────────────┐
│  own netns, no route except the veth                        │
│  Landlock: ro /app, rw /tmp/work, no path to the log        │
│  seccomp + NO_NEW_PRIVS, all capabilities dropped           │
│  env: GEMINI_API_KEY=hark-placeholder-<runid>               │
│  PYTHONPATH → sitecustomize shim (clock, RNG, uuid)         │
└─────────────────────────────────────────────────────────────┘
```

Three invariants fall out of this layout, and they are the ones to preserve when changing anything:

1. The agent cannot write to its own audit log — the log lives in Zone 0 and no Landlock rule grants
   a path to it.
2. The agent cannot reach the network except through the recorder — the namespace has no other
   route, so this holds regardless of what the agent's code does.
3. The agent cannot see the credentials it uses — the broker substitutes real values on egress,
   after the boundary.

## Package structure

| Package | Responsibility |
| --- | --- |
| `internal/hashchain` | Domain-separated BLAKE3: leaf, node, chain. Everything else builds on these three functions. |
| `internal/logfmt` | Event kinds, payload structs, canonical CBOR encoding, frame codec. |
| `internal/mmr` | Merkle Mountain Range, inclusion proof generation and verification. |
| `internal/signer` | Ed25519 signed tree heads over `(runID, leafCount, root, signedAt)`. |
| `internal/bundle` | `.hark` reader and writer, and the end-to-end verifier. |
| `internal/runid` | ULID generation. |
| `internal/policy` | The run allowlist. Exact matches only. |
| `internal/launcher` | Namespace, veth, Landlock, seccomp, capability drop, and the re-executed init child that applies them. |
| `internal/mediator` | DNS resolver, TLS termination, SNI, egress policy, forwarding, playback. |
| `internal/broker` | Placeholder credentials, substituted at the boundary. |
| `internal/reqkey` | Canonical request identity, so a replayed request finds its recorded response. |
| `internal/replay` | Indexes a recording for playback, and reduces a run to its comparable actions. |
| `internal/fork` | The branch-point gate that verifies a fork's prefix as it happens, and the patch applied at it. |
| `internal/rekor` | Submits a signed tree head to a transparency log, and checks an inclusion proof against RFC 6962 arithmetic. |
| `internal/report` | Renders a bundle as one self-contained HTML file. |
| `internal/shim` | The supervisor's side of the in-process clock and RNG capture channel. |
| `shim/` | The Python side, injected via `PYTHONPATH`. |
| `cmd/hark` | CLI. |

Dependencies run strictly downward: `bundle` → `{logfmt, mmr, signer}` → `hashchain`. No cycles, and
`hashchain` imports nothing from the project. The mediator depends on `replay` only through an
interface, so the recording path does not pull in the bundle reader.

### How the agent is started

The supervisor re-executes its own binary with a sentinel argument. That child locks an OS thread,
applies every restriction on it, and calls `execve` on the same thread — because Landlock and seccomp
restrict the *calling thread*, not the process, and Go moves goroutines between threads freely. It
blocks on a pipe until the parent has built the namespace, so the agent cannot run before the
boundary around it exists. See
[ADR-0007](decisions/0007-re-executing-init-child.md).

Capabilities are dropped first, then Landlock, then seccomp. Neither of the last two needs privilege,
and dropping first is both the safer default and a hard requirement — the capability drop reads
`/proc`, which Landlock would otherwise have already closed off.

### How a fork branches

A fork re-executes the agent rather than resuming it — there is no process checkpoint — so the gate
that decides *when* it has reached the branch point is driven by the child's own event stream. Each
event is folded into the same digest `hark replay` compares, and checked against the parent's step at
that index as it happens; a divergence kills the agent rather than producing a bundle whose
`ParentRoot` it has no claim to. Past the branch point the mediator dials for real and the shim tells
the agent to draw its own clock and randomness. See
[ADR-0008](decisions/0008-forks-have-a-verified-prefix-and-a-live-suffix.md).

### MCP, recorded rather than specially handled

An MCP server reached over streamable HTTP needs no dedicated support: it is a host in the
allowlist receiving ordinary POST requests, so it already goes through the same TLS termination,
recording and replay path proven for model traffic. On top of that transcript, `internal/mediator`
recognises a JSON-RPC 2.0 `tools/call` request and its matching response, and records a second,
semantic layer — `ToolCallRequest`/`ToolCallResult`, correlated by `Exchange` the same way
`LlmRequest`/`LlmResponseEnd` are. Additive by construction: a call the parser fails to recognise
still replays correctly through the generic events, and only the readability of `hark inspect`
degrades.

### Not yet built

`hark bisect` — automated counterfactual search for the minimal injected span that flips a plan. See
[roadmap.md](roadmap.md).

## How the agent's destination is learned

The mediator is the namespace's only resolver and the only reachable address. It therefore observes
the intended destination twice, before any traffic leaves:

1. **The DNS query.** `/etc/netns/<ns>/resolv.conf` points at the mediator, which answers every A
   query with its own address. This closes DNS as an exfiltration channel and names the destination
   before a TCP connection exists.
2. **The TLS SNI.** Because every name resolves to the mediator, the agent connects to it for any
   host, and the ClientHello carries the hostname it believes it is talking to.

This matters because it holds for an agent that ignores every proxy convention. Proxy environment
variables are a convenience for well-behaved clients; the routing table and the resolver are the
controls. Verified in W0 — see
[ADR-0006](decisions/0006-mediated-dns-and-sni-host-identification.md) for the reasoning, the
limitations, and why `SO_ORIGINAL_DST` cannot be used here.

## Recording flow

```text
agent process                mediator                    supervisor
     │                          │                             │
     ├── DNS: evil.example ────►│  (the only resolver there is)
     │                          ├── DnsQuery ────────────────►│ append
     │                          ├── DnsDecision ─────────────►│ append
     │◄── A 10.200.1.1 ─────────┤  every name resolves here
     │                          │                             │
     ├── connect ──────────────►│                             │
     │      (SNI names the intended host, even with no proxy configured)
     │                          ├── EgressAttempt ───────────►│ append
     │                          ├── policy check              │
     │                          ├── EgressDecision ──────────►│ append + fsync
     │                    denied ✗                            │
     │◄── connection refused ───┤                             │
     │                          │                             │
     ├── connect (allowed) ────►│                             │
     │                          ├── inject credential ───────►│ SecretInjected
     │                          ├── LlmRequest ──────────────►│ append
     │                          ├── upstream ...              │
     │                          ├── LlmResponseChunk × n ────►│ append
     │                          ├── LlmResponseEnd ──────────►│ append
     │◄── response ─────────────┤                             │
```

Every append advances the chain and adds a leaf to the MMR. The writer buffers, and calls `Sync` at
points where losing an event would matter — notably right after an egress denial, since the denial
is the evidence the bundle exists to carry and a crash immediately afterwards must not erase it.

## Concurrency model

The mediator serialises concurrent boundary crossings into a total order and, on replay, releases
them in the recorded order. This is an RPC-layer analogue of `rr`'s serialised scheduling, at a tiny
fraction of the cost.

What this does **not** capture is two threads racing on an in-process dictionary. That is stated
rather than papered over: if replay diverges, the action digest differs and the replayer names the
first divergent action instead of claiming success. A tool that says "I could not reproduce this,
here is where it diverged" is more trustworthy than one that always says OK.

## What replay compares

Not the Merkle root. Two runs of the same agent cannot produce the same root: the run id is fresh,
timestamps differ, and a credential placeholder embeds the run id. Comparing roots would report a
divergence on every replay, including a perfect one.

`REPLAY-EQUAL` is a digest over the *normalised actions*. Zeroed before hashing: run id, recorder
version, wall-clock timestamps, inter-chunk delays, and the clock values themselves (served back
verbatim over the shim channel, and stored only as a lossy nanosecond rendering). Placeholder tokens
are normalised, since they embed the run id.

Everything else participates — request bodies, response bodies, policy decisions, hosts, ordering,
and the exit code.

A divergence reports the first differing action and names both sides, because "not equal" leaves the
reader diffing two bundles by hand.

## Fork semantics

```text
hark fork run-01J8X.hark --at 47 --patch strip-injection.json
  1. replay events [0..47) bit-exactly     ← provably identical prefix
  2. apply the patch to event 47's payload
  3. mediator switches to LIVE from 47     ← real model, real cost
  4. emit a child bundle carrying parent_root, fork_point, patch_hash
```

Forks form a DAG anchored to the original's Merkle root. **A fork is not bit-exact** — it is a
provably identical prefix followed by a live suffix. The novelty is that the prefix is provable,
which is what makes an attribution claim about the divergence meaningful.

## What determinism means here

Determinism is a property of the harness, not the model. Given the same recorded external inputs,
the agent produces the same sequence of externally-visible actions and the same log root.

It cannot mean the model re-emits the same tokens: hosted temperature-0 inference is nondeterministic
because kernel numerics depend on server-side batch size, and `hark` does not control the serving
stack. Recording what the model said is the only sound approach.

Anything mutating external state cannot be re-executed either. Replay serves recorded results; fork
requires an explicit `may_reexecute` annotation on a tool before it will call out again. This is the
same rule durable-execution engines apply to non-deterministic activities.
