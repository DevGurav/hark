# Deterministic record and replay for AI agents — with a proof the replay is real

A small agent fetches a web page, asks a model what to do with it, and does what the model says.
The page carries an instruction the agent never asked for: post its API key to `evil.example`. The
model, which has no way to distinguish an instruction in its context from one in its prompt,
follows it. The agent, which has no reason to distrust a plan it asked for, tries to carry it out.

That's prompt injection, and it is not a contrived vulnerability. There is no `eval`, no shell, no
disabled check in the agent that causes it — the only thing it does wrong is believe what it reads,
which is the entire failure mode, and the reason the fix can't live inside the agent.

Two things stop it here. First, the egress attempt itself:

```text
EgressAttempt    evil.example:443 (tcp)
EgressDecision   DENIED evil.example by allow_hosts: host not in the policy allowlist
```

That's the control everyone expects — an allowlist, enforced outside the process that got
compromised. The second is the one worth staying for: the value the agent tried to leak was
`hark-placeholder-01J8X-api_key`. The real credential is substituted at the boundary, on the way
out, for allowed hosts only — so it was never in the agent's address space to lose in the first
place. Even had the egress been allowed, there was nothing real to steal.

Both controls are on the same record. That record is what `hark` is.

## What it actually is

An agent runtime where the component that *contains* the agent is the same component that
*records* it, and the recording is externally verifiable.

That's the whole design, and it's worth sitting with why it's one sentence and not three products.
Containment and recording happening at the same boundary means a single artifact is simultaneously
the security record and a sufficient input to re-derive the run. Nothing needs to be reconciled
between an enforcement log and an observability trace, because there was only ever one boundary and
one artifact.

```text
hark run -policy demo.toml -- python agent.py     → run-01J8X.hark
hark replay run-01J8X.hark                        → REPLAY-EQUAL, 22 actions
hark fork -at 47 -patch strip-injection.json ...  → provably identical prefix, live suffix
hark verify run-01J8X.hark                        → signature + transparency inclusion OK
hark report run-01J8X.hark                        → one self-contained HTML file
```

Three properties, and each is close to useless without the other two:

**Deterministic replay.** Every LLM call, tool result, clock read, RNG draw and blocked egress
attempt is recorded at the RPC boundary. A bundle carried to a second machine — no source code, no
credentials, no network — replays the identical sequence of actions, or names the first place it
diverged. The comparison is a digest over normalised actions, not the Merkle root; the root carries
a wall-clock timestamp and a fresh run id on every run, by design, so two honest recordings of the
same deterministic agent never share one. Comparing roots would have been the obvious thing to try
and the wrong one.

**Kernel-enforced containment.** The agent runs in its own network namespace with no route except
through the mediator, a Landlock-scoped filesystem, seccomp, and every capability dropped.
Enforcement is out-of-process — a prompt-injected agent has no privileged path to switch it off,
because it never had the privilege to begin with.

**Tamper-evident audit.** A hash chain for streaming integrity, a Merkle Mountain Range for
O(log n) inclusion proofs, an Ed25519 signed tree head, anchored in a public transparency log.

## Why the third property isn't optional

Here's the argument most tools in this space skip, and skipping it is the tell.

An operator-signed hash chain proves nothing *against the operator*. They can discard a run,
rewrite its events, re-sign the result, and hand you the only version that ever existed. A
signature gives you integrity against a third party who tampers with the log in transit — it gives
you nothing against the party who wrote it.

Non-equivocation needs a witness the operator doesn't control. That's the entire reason `hark
verify` reports the transparency anchor as its own line instead of folding it into one boolean, and
why an unanchored bundle says so in plain words instead of pretending the distinction doesn't
matter:

```text
transparency  not anchored -- integrity only, no non-equivocation
```

A run from this project is anchored for real in Sigstore's public Rekor log — entry `108e9186…`,
log index `2498575532` — and its inclusion was verified from a second machine that had never seen
the run, with the proof recomputed locally against a tree that had grown since the anchor. That's
the difference between "trust me" and "check it yourself."

## What "deterministic" does not claim

> Determinism is a property of the harness, not the model. Given the same recorded external
> inputs, the agent produces the same sequence of externally-visible actions and the same log root.
> We do not — and cannot — claim the model would re-emit the same tokens.

Temperature-0 inference on a hosted endpoint is not reproducible: server-side batch size changes
the numerical path through the kernels, so identical requests to the same model can diverge. `hark`
doesn't control the serving stack, so it records what the model actually said rather than
pretending it could be re-derived. Overclaiming here is the single most common flaw in this
category of tool, and it should be the first thing a skeptical reader checks — which is exactly why
it's stated this plainly, this early.

## It works on an agent that wasn't written for it

The easiest way to fake "framework independence" is to only ever demonstrate it on a stub built to
cooperate. So the test was to point `hark` at a real LangGraph application — four agents, a
Gemini-backed model, a TTLCache, retrieval-augmented generation over a real document store — with
**zero source changes**, and see what happened.

What happened: a real 503 followed by a real 429 from Gemini's free-tier rate limiter, retried by
the target's own backoff logic exactly as it does in production, recorded as ordinary traffic and
reproduced byte-for-byte on replay with zero network calls made the second time:

```text
LlmRequest  ...generateContent  occurrence 0   -> LlmResponseEnd status 503
LlmRequest  ...generateContent  occurrence 1   -> LlmResponseEnd status 200
```

And separately, the application's own response cache produced the other interesting case for free:
an identical question asked twice in one run — an 88-second miss with seven real requests, then a
0.00-second hit that made none. Both replayed exactly, including *which half made a network call at
all*.

Neither of these was staged. They're what a rate-limited, cached, real application actually does
when you ask it two questions, and `hark` recorded both without knowing either was coming.

## The suite that caught its own bug

Testing replay fidelity against a live endpoint measures the endpoint's rate limiter, not the
recorder — so the published fidelity numbers come from five *hermetic* agent shapes instead, each
isolating one property replay has to get right: response streaming, retry-after-error, a repeated
identical request, a JSON-RPC tool call, and the original prompt-injection incident. Twenty-five
recordings, twenty-five replays, twenty-five matches — with the exact count published, not rounded,
because twenty-five passing twenty-five times is twenty-five, not "always."

The more useful fact is what the suite found about itself before it ever published that number. The
first real run reported the retry shape passing 5/5 replays but with the *wrong shape* on four of
those five runs — a shared stub process meant only the first of five independent recordings
actually exercised the retry path; the other four silently degenerated into a trivial single-request
call while still, technically, reporting "replay-equal." True and uninteresting. The fix — giving
every recording its own fresh stub process — is a two-line change; the fact that a fidelity suite
found a bug in its own fixtures before trusting its own headline number is the part worth
mentioning, and it's why the failure stayed in the published report instead of being quietly
corrected.

## What it costs

Measured on a 2 vCPU shared Azure instance, method and full tables published alongside the numbers:

| | |
| --- | --- |
| Mediation, versus dialling the same stub directly | +0.18 ms at p50, +0.28 ms at p99 |
| Replaying a run that waited 0.9 s on its model call | 1052 ms → 145 ms |
| Verifying a 100,000-event bundle | 276 ms, 188 MB/s |
| Proving one event happened | 448 bytes, 14 hashes |
| A bundle, per 1,000 events | 518 KB raw, 79 KB gzipped |

Replay saves exactly the upstream latency it doesn't wait for — an agent making thirty model calls
saves thirty times as much. The floor is constant: a replay costs roughly what starting the agent
costs, about 145 ms of namespace setup and interpreter start, and almost nothing past that.

## Where this sits next to everything else

Checked against each project's own repository, not a summary of it, because getting this table
wrong in either direction — understating a competitor or overstating the gap — is worse than a
smaller, accurate claim.

**Containment is a crowded field, and this should never be pitched as a sandbox.** Pipelock in
particular reaches the same kernel primitives (Landlock, seccomp, network namespaces) *and* signs a
hash-chained evidence log with optional Rekor anchoring — it is the nearest neighbour by a real
distance, and the honest difference is that its artifact is forensic rather than re-executable: it
records what was decided, not enough to re-derive the run. Clawker and nono contain without
recording an artifact at all. AgentSight observes via eBPF without enforcing or producing a
replayable recording.

**Deterministic replay already exists, done well, at the MCP layer** — Agent VCR records and
replays MCP JSON-RPC sessions deterministically, cross-language, for CI. It's a real prior art for
half of this project's claim, at a narrower layer and for a narrower purpose (a test fixture, not a
security artifact).

What nothing in that table does is produce *one* artifact that is simultaneously the enforcement
record and a sufficient input to re-execute the run — with a fork that can prove which part of a
counterfactual is the original, verified prefix and which part is a fresh, live re-execution. That
intersection is the whole claim, and it is deliberately narrower than "agent sandbox with an audit
log."

## Try it

```sh
sudo ./demo/run.sh
```

Linux and root, because the containment is real and not a wrapper around good intentions. No API
key, no cost, no network — the upstream is a stub that says so out loud. The whole incident above,
plus the replay, the fork, and the report, runs from one terminal in about a second once the model
calls stop being the bottleneck, which they're not, because nothing here waits on one.

Everything in this writeup traces to a command in the repository. That was the bar going in.
