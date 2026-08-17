# Roadmap

Eight weeks, with v0.1 standing alone as a complete artifact at week 4. Weeks 5–8 overlap with
placement interviews and are treated as upside, not as part of the commitment.

This file is the state of the work. The implementation specs in [build/](build/) are how each phase
gets executed — file paths, interfaces, acceptance commands and traps. Open the spec for the current
phase before writing code.

## W0 — groundwork · **mostly done**

Spec: [build/w0-groundwork.md](build/w0-groundwork.md)

- [x] Provision the Linux box. Azure for Students, Ubuntu 24.04, kernel 6.17, 2 vCPU / 3.8 GiB.
- [x] Confirm `landlock` appears in `/sys/kernel/security/lsm` — present, **ABI version 7**.
- [x] Throwaway prototype: netns + veth, containment proven, TLS interception through a per-run CA
      proven, and mediated DNS + SNI host identification proven. Transcript in
      [build/w2-launcher.md](build/w2-launcher.md).
- [x] Repo builds and tests green on the target box, race detector included.
- [ ] Verify every row of the README's related-work table against the actual projects. The table
      ships only once each claim has been checked against source, not against a summary.

## W1 — bundle format and verifier · **done**

- [x] `internal/hashchain` — domain-separated BLAKE3 leaf, node and chain constructions.
- [x] `internal/mmr` — append, root, inclusion proofs, verification without the tree.
- [x] `internal/logfmt` — event kinds, canonical CBOR payloads, frame codec.
- [x] `internal/signer` — Ed25519 signed tree heads.
- [x] `internal/bundle` — writer, reader, end-to-end verifier with prefix recovery.
- [x] `internal/runid` — ULID run identifiers.
- [x] CLI: `verify`, `inspect`, `prove`, `synth`, `keygen`.
- [x] Test suite green: 47 tests (52 including subtests) across 6 packages.
- [x] ADRs 0001–0005.

## W2 — launcher, mediator, broker · **done**

Spec: [build/w2-launcher.md](build/w2-launcher.md)

The highest-variance week. Deliverable met: a `curl`-driven agent produced a bundle containing a real
denial, verified end to end on kernel 6.17.

```text
 7  EgressAttempt    example.com:443 (tcp)
 8  EgressDecision   allowed example.com by allow_hosts:example.com
 9  LlmRequest       GET example.com/
10  LlmResponseChunk chunk 0, 559 bytes
12  DnsQuery         A evil.example
13  DnsDecision      evil.example -> 10.200.1.1 (policy: DENIED)
16  EgressAttempt    evil.example:443 (tcp)
17  EgressDecision   DENIED evil.example by allow_hosts: host not in the policy allowlist
```

The agent had every proxy variable unset and still named its destination twice. An inclusion proof
for the denial is 517 bytes against a 3,574-byte bundle; a killed run verifies as `TRUNCATED` with
its prefix intact.

- [x] `internal/launcher` — network namespace and veth pair; Landlock filesystem scoping; seccomp
      with `NO_NEW_PRIVS`; drop all capabilities.
- [x] `internal/mediator` — TLS termination with a CA under `hark`'s control, HTTP recording,
      egress allowlist evaluation.
- [x] `internal/broker` — placeholder credentials in the agent's environment, real values injected
      on egress to allowlisted hosts only.
- [x] TOML policy loader. Not a DSL — an allowlist.
- [x] `hark run`.

## W3 — replay · **done**

Spec: [build/w3-replay.md](build/w3-replay.md)

Second-highest variance. Deliverable met: a Python agent drawing a uuid, a random number and the
clock, fetching an allowed host and being denied a disallowed one, replayed identically.

```text
REPLAY-EQUAL  22 actions, digest f6ac72c5...
```

Measured on kernel 6.17: 18 packets to :443 during the recording, **0 during the replay**. Changing
the agent produces `REPLAY-DIVERGED at action 6` naming both sides. Replaying a replay yields the
same digest, so a replayed bundle is itself a faithful recording.

- [x] Mediator playback mode.
- [x] Request keying on `(canonical_request_hash, occurrence_ordinal)` with strict sequence position
      as fallback, and a `KeyMismatch` diagnostic rather than a guess. Budget two full days for
      canonicalisation: header ordering, `Date`, connection-specific headers, JSON key order, float
      formatting.
- [x] Python `sitecustomize` shim for `time.time`, `time.monotonic`, `random`, `uuid4`,
      `os.urandom`, plus `PYTHONHASHSEED=0`.
- [x] Replay equality: a digest over normalised actions, or the first divergent event named. Not the
      Merkle root — see the build log for why comparing roots could never work.

## W4 — the incident, and v0.1 · **built, awaiting the box**

Spec: [build/w4-v0.1.md](build/w4-v0.1.md)

**v0.1 ships here and must be independently interview-ready.**

Everything below is implemented and green off the box: 22 test files across 16 packages, `go vet`
clean, and the Linux target cross-builds. What has *not* happened is the part that can only happen on
the Linux box — the demo has never been run end to end, so no acceptance below is ticked on the
strength of code review alone. W2 and W3 both found real defects the moment they ran; assuming this
week will not is the mistake those weeks exist to warn against.

- [x] The prompt-injection demo, written: agent, poisoned page, stub upstream, policy, `demo/run.sh`.
- [x] `hark fork -at N -patch p.json`, with the branch-point gate that verifies the prefix as it
      happens. [ADR-0008](decisions/0008-forks-have-a-verified-prefix-and-a-live-suffix.md).
- [x] Static HTML trace report from a bundle. No server, no framework, no JavaScript, no external
      request — asserted by test, not by intention.
- [x] Rekor anchoring at seal time, non-fatal, with `hark verify` recomputing the inclusion proof
      rather than believing the log's answer.
- [x] `-upstream HOST=ADDR`, recorded in `RunStart`, which the hermetic demo and the benchmarks both
      need. [ADR-0009](decisions/0009-upstream-redirection-is-recorded-not-hidden.md).
- [x] Benchmark harnesses for four of the five figures, each behind a documented command.
- [ ] **Run `demo/run.sh` on the box.** Record, verify, replay, fork, report.
- [ ] **Anchor one run for real** and verify its inclusion from a second machine.
- [ ] Fill in `docs/benchmarking.md` from the box, then quote those numbers in the README.
- [ ] README with the demo GIF, and the verified related-work table from W0.
- [ ] Tag `v0.1.0`, once the above are true rather than expected to be.

## W5 — a real workload · not started

Spec: [build/w5-w8-later.md](build/w5-w8-later.md)

- [ ] Record UrbanHeat's LangGraph agents with **zero code changes** — `HTTPS_PROXY`, the CA, and
      `PYTHONPATH`. Its retry-on-429 path exercises "same logical call, multiple HTTP requests", and
      its TTLCache produces the cache hit/miss interleaving that makes request keying interesting.
- [ ] Streaming: chunk-granular SSE record and replay.
- [ ] MCP servers recorded behind the proxy.

## W6 — fidelity evidence · not started

- [ ] Replay-fidelity suite: N recorded runs across M agent shapes, percentage replay-equal, **with
      the failures published**. Never claim 100%.
- [ ] CI determinism badge from that suite.
- [ ] Trace viewer polish.

## W7 — launch · not started

- [ ] 90-second demo video, captions rather than narration, split screen.
- [ ] Show HN, leading with the security incident rather than the architecture.
- [ ] Technical writeup.

## W8 — buffer · not started

Respond to feedback. Fix what the launch surfaces.

## Deliberately out of scope

Permanently, unless something changes:

- Windows and macOS.
- Multi-machine or distributed agents.
- Syscall-level record/replay in the style of `rr`.
- Zero-knowledge proofs of execution — [ADR-0005](decisions/0005-why-not-zero-knowledge-proofs.md).
- Non-equivocation against a colluding transparency log.
- A hosted service, a web UI, or a policy DSL.
- Cert-pinning agents. Documented as a limitation; the shim is the workaround.

## Later than v1.0

- eBPF and BPF-LSM for per-tool-call scoping and non-Python child processes.
- `SECCOMP_USER_NOTIF` for address-aware syscall filtering.
- `hark bisect` — automated counterfactual search for the minimal injected span that flips a plan.
- An E2B-compatible API subset, as an adoption lever.
- Porting the launcher to Rust.
