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

## W3 — replay · not started

Spec: [build/w3-replay.md](build/w3-replay.md)

Second-highest variance. Deliverable: `hark run` then `hark replay` reports REPLAY-EQUAL on an agent
that genuinely calls a model.

- [ ] Mediator playback mode.
- [ ] Request keying on `(canonical_request_hash, occurrence_ordinal)` with strict sequence position
      as fallback, and a `KeyMismatch` diagnostic rather than a guess. Budget two full days for
      canonicalisation: header ordering, `Date`, connection-specific headers, JSON key order, float
      formatting.
- [ ] Python `sitecustomize` shim for `time.time`, `time.monotonic`, `random`, `uuid4`,
      `os.urandom`, plus `PYTHONHASHSEED=0`.
- [ ] Replay equality: recompute the chain root, or report the first divergent event.

## W4 — the incident, and v0.1 · not started

Spec: [build/w4-v0.1.md](build/w4-v0.1.md)

**v0.1 ships here and must be independently interview-ready.**

- [ ] The prompt-injection demo end to end.
- [ ] `hark fork`, manual, one flag.
- [ ] Static HTML trace report generated from a bundle. No server, no UI framework.
- [ ] Rekor anchoring at seal time.
- [ ] `docs/benchmarking.md` methodology, then numbers.
- [ ] README with the demo GIF.

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
