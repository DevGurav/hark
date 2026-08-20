# W6 — fidelity evidence

**Goal.** Publish the replay-fidelity suite, including its failures. This is the project's central
empirical claim, so it is also where dishonesty would be most damaging — never round to 100%.

## Prerequisites

- W5 complete: streaming, MCP and a real external workload (UrbanHeat) all recorded and verified
  `REPLAY-EQUAL`.

## Why hermetic, when W5 was deliberately live

W5's point was proving hark needs zero code changes against a real target, so it had to be live —
free-tier quota and all. W6's point is a repeatable pass rate, and a live Gemini endpoint makes that
number about Google's rate limiter, not about hark. Every shape here runs against a local stub, the
same posture `demo/` already takes and for the same reason
([docs/benchmarking.md](../benchmarking.md)'s "benchmarking against a live endpoint" trap). UrbanHeat's
live retry-on-429 and cache-hit evidence (build-log.md, 2026-08-18) stands on its own and is not
re-counted into this suite's N.

## Deliverables

| File | Responsibility |
| --- | --- |
| `fidelity/shapes/*/agent.py`, `stub.py`, `policy.toml` | M hermetic agent shapes, one request pattern each. |
| `fidelity/run.sh` | Records N runs per shape, replays each, tallies, writes the report. |
| `docs/fidelity.md` | The published numbers. Every non-equal result named and explained. |
| `.github/workflows/ci.yml` | A fidelity job, gated on the same Landlock/netns preflight the launcher tests use. |
| `README.md` | A badge sourced from the report. |

## Tasks

### 1. Five agent shapes

Each isolates one property replay has to get right, and each runs standalone against its own stub
with hark out of the loop — so a failure is visibly the shape's bug, not hark's, before it is ever
blamed on the recorder.

- [ ] `incident` — reuse `demo/agent.py` and `demo/stub.py` as-is. The one shape already proven end
      to end since W4; included so the suite has a known-good baseline, not just new surface.
- [ ] `streaming` — the model reply arrives as a multi-chunk SSE stream (`internal/mediator`'s
      `sseUpstream` test pattern, promoted to a standalone stub); the agent must branch on partial
      reads, not a reassembled body.
- [ ] `retry` — the stub answers 503 then 200 for the same logical call; the agent retries with a
      short backoff. A hermetic version of what W5 found for real in UrbanHeat
      (`ChatGoogleGenerativeAI`'s retry against a genuine 429) — same shape, no quota.
- [ ] `repeat` — the agent sends the identical request twice in one run. Exercises
      `(canonical_request_hash, occurrence_ordinal)` keying directly, the same property W5's cache
      hit/miss pair demonstrated live, minus the need for a real cache to produce it.
- [ ] `mcp` — the agent makes a JSON-RPC `tools/call` against a stub shaped like an MCP server
      (`internal/mediator`'s `mcp_test.go` fixtures, promoted the same way).

**Acceptance.** Each shape's `agent.py` runs to completion against its own `stub.py` with a plain
`python3 agent.py`, no `hark` involved, before it is ever wired into the suite.

### 2. The run/replay/tally harness

- [ ] `fidelity/run.sh -n N`: build `hark` once, then for each shape run `hark run` N times
      (default 5), `hark replay` every bundle, and classify each as `REPLAY-EQUAL`, `DIVERGED`
      (naming the first differing action, not just the fact of a mismatch), or *errored before
      sealing* (a third bucket — a run that never produced a bundle is not the same failure as one
      that produced a wrong replay, and conflating them would hide which).
- [ ] Deterministic inputs via the shim mean a hermetic shape's N recordings should also match each
      other, not only their own replay. Record that second number too; it is a useful canary even
      though the suite's headline claim is replay-equality, not run-to-run identity.

**Acceptance.** `fidelity/run.sh -n 5` completes on the box and produces a table: shape, N,
replay-equal count, first divergence (if any).

### 3. `docs/fidelity.md`

- [ ] The published report. One row per shape, worst case first, in the exact form the roadmap
      already commits to: "47/47 runs replay-equal across 6 agent shapes; 3 shapes excluded, reasons
      below" — never a bare percentage, never a shape quietly dropped from the denominator.
- [ ] Every non-equal result gets the event sequence number and a one-line cause, not a category.
      "diverged at action 14, LlmRequest body differs — canonicalisation missed a
      float-formatting difference" is the bar; "flaky" is not an acceptable entry.

### 4. CI wiring

- [ ] A `fidelity` job in `.github/workflows/ci.yml`, gated behind the same preflight
      `internal/launcher`'s tests use: skip with a named reason when Landlock or network namespaces
      are unavailable, never fail silently and never skip silently either.
- [ ] This is genuinely unverified going in — `docs/testing.md` already flags Landlock-dependent
      tests as "not yet wired into CI, which needs a privileged runner step." Find out on a real
      GitHub-hosted runner rather than assuming either way; the outcome (works, needs
      `runs-on: self-hosted`, or needs a specific runner image) is itself worth recording here.

### 5. README badge

- [ ] Sourced from `docs/fidelity.md`'s numbers. Static and hand-updated alongside the report for
      now — a live CI-generated badge is a v1.0 concern, and a badge that silently goes stale is
      worse than one that is honestly manual.

## Traps

**Benchmarking against a live endpoint, again.** W5 already paid this lesson down for the demo; W6
is where it would be easiest to re-spend it by folding UrbanHeat's live numbers into this suite's N
for a bigger-looking denominator. Don't.

**Rounding to 100%.** N runs passing N times is still an N. Say the number, not "always."

**Blaming hark for a stub's bug.** Task 1's acceptance step — running each shape's agent against its
stub with no `hark` in between — exists specifically to keep this from happening.

## Definition of done

- [ ] Five shapes, each independently runnable and each wired into `fidelity/run.sh`.
- [ ] A real run of `fidelity/run.sh -n 5` on the box, numbers taken from that run, not invented.
- [ ] `docs/fidelity.md` published, every non-equal result named by action and cause.
- [ ] CI outcome recorded either way: wired in, or documented why not yet.
- [ ] README badge added.

## Expected commits

```text
feat(fidelity): four hermetic agent shapes -- streaming, retry, repeat, mcp
feat(fidelity): the run/replay/tally harness
docs: publish the W6 replay-fidelity report
ci: wire the fidelity suite into CI
```
