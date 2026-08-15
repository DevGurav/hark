# hark

Deterministic record and replay for AI agents — with a proof the replay is real.

**Status: W1 of 8. The bundle format, hash chain, Merkle Mountain Range, signing and verifier are
implemented and tested. The recorder and replayer are not — see [docs/roadmap.md](docs/roadmap.md).**

Linux only. `hark` depends on network namespaces, Landlock and seccomp; there is no Windows or macOS
port planned.

---

## What this is

An agent runtime where the component that *contains* the agent is the same component that *records*
it, and the recording is externally verifiable.

That sentence is the whole design. Containment and recording happen at one boundary, so a single
artifact is simultaneously the security record and a sufficient input to re-derive the run. A
transparency-log commitment over that artifact is what makes it evidence rather than a log file.

```text
hark run --policy demo.toml -- python agent.py    → run-01J8X.hark
hark replay run-01J8X.hark                        → REPLAY-EQUAL (chain root matches)
hark verify run-01J8X.hark                        → signature + inclusion proof OK
```

Three properties, none of which is useful without the other two:

1. **Deterministic replay.** Every LLM call, tool result, clock read, RNG draw and blocked egress
   attempt is recorded at the RPC boundary. A past run replays on another machine and lands on the
   same root, or reports the first event where it diverged.
2. **Kernel-enforced containment.** The agent runs in its own network namespace with no route except
   through the mediator, a Landlock-scoped filesystem, seccomp and no capabilities. Enforcement is
   out-of-process: a prompt-injected agent cannot switch it off.
3. **Tamper-evident audit.** A hash chain for streaming integrity, a Merkle Mountain Range for
   O(log n) inclusion proofs, an Ed25519 signed tree head, anchored in a public transparency log.

The agent cannot write to its own audit log, cannot reach the network except through the recorder,
and cannot see the credentials it uses.

## Why the third property is not optional

An operator-signed hash chain proves nothing against the operator. They can discard a run, rewrite
its events, re-sign the result, and present it as the only run that ever happened. Signatures give
integrity against third parties, never against the log's author.

Non-equivocation needs a witness the operator does not control. That is why `hark verify` reports
the transparency anchor as a separate line rather than folding it into one boolean, and why an
unanchored bundle says so in plain words:

```text
transparency  not anchored -- integrity only, no non-equivocation
```

The reasoning is in [ADR-0004](docs/decisions/0004-transparency-log-over-operator-signed-receipts.md).

## What "deterministic" does and does not claim

> Determinism is a property of the harness, not the model. Given the same recorded external inputs,
> the agent produces the same sequence of externally-visible actions and the same log root. We do
> not — and cannot — claim the model would re-emit the same tokens.

Temperature-0 inference is not reproducible on hosted endpoints: server-side batch size changes the
numerical path through the kernels, so identical requests diverge. `hark` does not control the
serving stack, so it records what the model said rather than pretending it could re-derive it.

Overclaiming here is the most common flaw in this category of tool, and it is the first thing a
reviewer should check.

## Quickstart

Requires Go 1.23+.

```sh
go build ./cmd/hark

./hark keygen -out hark.key             # Ed25519 signing key
./hark synth -key hark.key run.hark     # synthetic bundle: a prompt-injection incident
./hark inspect run.hark                 # list the events
./hark verify run.hark                  # check chain, root, signature
./hark prove -seq 14 -out proof.json run.hark
./hark prove -check proof.json          # verify one event without the bundle
```

`synth` fabricates a bundle so the format and verifier can be exercised before the recorder exists.
It is a test fixture with a CLI, and the bundles it writes say so in their `RunStart`.

To watch the verifier catch things:

```sh
./hark synth -corrupt 9 bad.hark      && ./hark verify bad.hark      # BROKEN, names the event
./hark synth -truncate 14 part.hark   && ./hark verify part.hark     # TRUNCATED, keeps the prefix
./hark verify -key <wrong-hex> run.hark                              # REJECTED
```

Exit codes: `0` verified, `1` broken or rejected, `3` truncated. A killed run is a real state rather
than a failure, so it gets its own code.

## Why inclusion proofs

Proving that one event happened costs a few hundred bytes and log₂(N) hashes. Shipping the bundle
could cost hundreds of megabytes, and would disclose the entire run to whoever you are trying to
convince about one line of it.

```text
$ ./hark prove -seq 14 run.hark        # the egress denial, out of 17 events
  4 sibling hashes + 1 peak            # ~300 bytes
```

## Layout

```text
cmd/hark/            CLI
internal/hashchain/  domain-separated BLAKE3 primitives
internal/logfmt/     event kinds, canonical CBOR payloads, frame codec
internal/mmr/        Merkle Mountain Range, inclusion proofs
internal/signer/     Ed25519 signed tree heads
internal/bundle/     .hark reader, writer, verifier
internal/runid/      ULID run identifiers
```

Design documents: [architecture](docs/architecture.md) · [wire protocol](docs/protocol.md) ·
[threat model](docs/security.md) · [testing](docs/testing.md) · [roadmap](docs/roadmap.md) ·
[decisions](docs/decisions/)

## Related work

Containment and audit logging for agents are both actively worked on; the combination with
bit-comparable replay under one mediator is where `hark` differs.

| Category | Examples | Difference |
|---|---|---|
| Agent sandboxes | Pipelock, Clawker, Nono | Contain the agent; do not produce a replayable artifact |
| System observability | AgentSight | Observes syscalls and TLS; does not enforce or replay |
| MCP recorders | Agent VCR, mcpsnoop | Record and replay tool calls; no containment, no proofs |
| Tracing and eval | LangSmith, Braintrust, Arize | Observation and regression testing, not a runtime |
| Durable execution | Temporal | Event-sourced replay, but not LLM-aware and with no security model |

> These rows are a positioning sketch, not a verified comparison. Each one must be checked against
> the actual project before this repo is made public — see the W0 item in
> [docs/roadmap.md](docs/roadmap.md). Misstating a peer project's capabilities would be a worse
> outcome than omitting the table.

## Licence

[Apache 2.0](LICENSE) — the prevailing choice for Go infrastructure (Kubernetes, Docker, Temporal,
Cilium), and its explicit patent grant matters more than permissiveness for anything an enterprise
might adopt.
