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
| `cmd/hark` | CLI. |

Dependencies run strictly downward: `bundle` → `{logfmt, mmr, signer}` → `hashchain`. No cycles, and
`hashchain` imports nothing from the project.

### Not yet built

`internal/launcher` (netns, Landlock, seccomp), `internal/mediator` (DNS, TLS termination, SNI,
recording, egress policy), `internal/broker` (secrets), `internal/replay` (playback and request
keying), and the Python `sitecustomize` shim. See [roadmap.md](roadmap.md).

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
rather than papered over: if replay diverges, the chain root differs and the replayer reports the
first divergent event instead of claiming success. A tool that says "I could not reproduce this,
here is where it diverged" is more trustworthy than one that always says OK.

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
