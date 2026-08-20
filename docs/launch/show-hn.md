# Show HN draft

Drafted only. Submitting this is the maintainer's own action — not something to be posted on their
behalf, and not something this repo does for them. Review, edit, then post it yourself when ready.

## Title

```text
Show HN: Deterministic record and replay for AI agents – with a proof the replay is real
```

(HN strips the em dash in titles historically without issue, but a plain hyphen is safer than
relying on that.)

## Post text

```text
I built hark: an agent runtime where the thing that contains the agent is the same thing
that records it, and the recording is externally verifiable.

The demo: a small agent gets prompt-injected via a page it fetches, and tries to post its
API key to an attacker's server. Two independent controls stop it — an egress denial, and
the fact that the "key" it tried to leak was a placeholder substituted at the boundary, so
the real one was never in the agent's memory to steal. Both controls are on the same
tamper-evident record. That record then replays exactly on a second machine (no network,
no credentials), forks with the injection stripped to prove the counterfactual, and is
anchored in a public transparency log so the operator can't quietly rewrite it later.

Recording works with zero code changes against a real, unmodified LangGraph app — caught
its own real 429 from Gemini's free-tier limiter mid-recording, replayed the retry
byte-for-byte. A separate hermetic fidelity suite is at 25/25 runs replay-equal across 5
agent shapes, published with the one fixture bug it found in itself along the way.

Repo: https://github.com/DevGurav/hark
Writeup: [link to hosted writeup.md, or the README if unhosted]

Linux only (netns + Landlock + seccomp), v0.1. Happy to answer anything about the design —
particularly interested in pushback on the replay-fidelity claim, since that's the one most
worth someone trying to break.
```

Keep it this short or shorter. HN rewards a post that gets out of its own comments' way.

## Pre-written replies

Two comments are close to guaranteed. Having the answer ready, in the post's own voice, is worth
more than any amount of README polish once the thread is live.

### "This is just Pipelock / Clawker / Agent VCR"

```text
Fair pushback, and I tried to get ahead of it — the README has a related-work table
checked against each project's own repo, not a summary of it.

Short version: Pipelock is the closest thing here, genuinely — same kernel primitives
(Landlock, seccomp, netns), and it signs a hash-chained evidence log with optional Rekor
anchoring. The difference is that its artifact is forensic (what was decided) rather than
re-executable (enough to re-derive the run). No replay, no fork.

Agent VCR does real deterministic replay, well, at the MCP layer — but as a test fixture
for CI, not a security artifact, and with no containment or tamper-evidence.

Containment alone is genuinely crowded now — I'd never pitch hark as "a sandbox." The
claim is narrower than that: one artifact that's simultaneously the enforcement record
and a sufficient input to re-execute the run, with a fork that can prove which part of a
counterfactual is the verified original and which part is a fresh live re-run. Nothing
in the table does that combination.
```

### "The model is nondeterministic, so what does replay prove?"

```text
This is the right question and I tried to state the scope plainly rather than bury it:

Determinism here is a property of the harness, not the model. Given the same recorded
external inputs — every LLM response, tool result, clock read, RNG draw, blocked egress
attempt — the agent produces the same sequence of externally-visible actions and the same
log root. hark does not and cannot claim the model would re-emit the same tokens if called
again live; temperature-0 on a hosted endpoint isn't reproducible anyway (server-side batch
size changes the numerical path).

What replay proves is narrower and, I'd argue, still the useful thing: given what the model
actually said in the original run, does the agent's own logic + the recorded tool/environment
responses reproduce the same decisions? That's what lets you fork at event N, patch one
input, and get a real counterfactual instead of a guess about what "would have" happened.
```
