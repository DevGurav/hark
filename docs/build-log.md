# Build log

Newest first. Append-only.

---

## 2026-08-20 — W6: the fidelity suite, and the fixture bug it caught on its first real run

Five agent shapes under `fidelity/shapes/`, each isolating one property replay has to get right:
`streaming` (chunk boundaries, not just bytes), `retry` (the same logical call as two HTTP
requests after a 503), `repeat` (an identical request sent twice with no error in between), `mcp`
(a JSON-RPC `tools/call` layered on ordinary HTTP), and `incident` -- reused from `demo/` rather
than duplicated, so there is exactly one copy of the prompt-injection scenario in the repo.
Deliberately hermetic, all four new ones: a local stub upstream apiece, no network, no quota to
hit. W5 already paid down the lesson that a live endpoint measures somebody else's rate limiter,
not hark, and this suite's whole point is a repeatable number.

**The suite found a bug in itself before it ever published one.** The first real run at `-n 5`
reported `retry` at 22/13/13/13/13 events instead of 22 every time. Not a replay bug -- a fixture
bug: `fidelity/run.sh` started one stub process and reused it across all N iterations of a shape,
and the retry stub's "have I failed once yet" counter is process-global. Only the first iteration
ever saw a 503; the other four silently degenerated into the trivial single-request case while
still reporting `REPLAY-EQUAL` -- true and uninteresting, since replaying a call that never
retried proves nothing about retry fidelity. Fixed by giving every iteration of every shape its
own fresh stub process, so N independent recordings cannot see each other's server-side state.
`docs/fidelity.md` keeps this in the published report rather than quietly fixing it and moving on.

A second thing worth recording precisely because it *didn't* turn into a check: independent
recordings of the same hermetic shape produce different Merkle roots every time, by design --
`RunStart` carries a wall-clock timestamp and a fresh run id, both legitimately unique per run.
W3 already ruled out comparing roots for exactly this reason (build-log, W3 entry); this session
almost reintroduced the same mistake as a "run-to-run consistency" metric before checking event
counts instead, which are structurally deterministic for a hermetic shape and were what actually
caught the retry bug above.

**Verified.** `sudo fidelity/run.sh -n 5` on the box: **25/25 runs replay-equal across 5 shapes**,
`retry` confirmed at 22 events on every one of the five independent recordings. Published as
`docs/fidelity.md`, in the exact form the roadmap already committed to -- the count and the
shapes, never a bare percentage.

**Not yet verified.** A `fidelity` job landed in `.github/workflows/ci.yml`, gated behind a
preflight (Landlock in the active LSM list, `unshare --net` works) that skips with a visible
`::warning::` rather than failing or passing silently when either is missing. Whether a
GitHub-hosted `ubuntu-24.04` runner actually has both is genuinely unknown going in --
`docs/testing.md` flagged this exact gap before W6 started. Next entry says which.

---

## 2026-08-20 — the fidelity job's first CI run: exit 126, and it was never about Landlock

Pushed and watched. The `fidelity` job failed in 19 seconds -- too fast to have reached the
preflight check at all, and `exit 126` is the shell's code for "found the file, could not execute
it," not a Landlock or namespace refusal. `git ls-files -s` confirmed it on the first guess:
`fidelity/run.sh` was tracked as `100644`, `demo/run.sh` as `100755`. Created fresh on Windows this
session, never `chmod +x`'d *before* the commit that added it -- every box test afterward ran a
copy `chmod +x`'d by hand over `scp`, which is edited-in-place, not what git had stored. A clean
`actions/checkout@v4` gets exactly the stored mode. `git update-index --chmod=+x` fixed it in the
index directly rather than needing a working-tree chmod plus a second diff.

So the actual question W6 opened with -- does a GitHub-hosted runner have Landlock and network
namespaces for `hark run` -- is still unanswered, one mundane bug later. Next entry says which, for
real this time.

---

## 2026-08-18 — W5 closed: the cache hit needed no wait, just a repeat

The previous entry left the TTLCache hit/miss interleaving blocked on Gemini's free-tier quota (5
req/min): a single agent turn's retries already exhausted it, so a second, *different* question
never got a chance to run. The fix wasn't patience — `Supervisor.handle`'s cache
(`backend/agents/supervisor.py`) keys on `(message.strip(), data_version)`, so asking the *same*
question a second time immediately after the first completes is a guaranteed cache hit that makes
no request at all, regardless of quota state.

One more external driver script (`demo_workload_cache.py`, the same non-invasive role as the
others — UrbanHeat's source still untouched) asked "what should we do about ward L" twice in one
process:

```text
[miss]  routed=planning  elapsed=88.46s   (7 real requests: routing, tool loop, one 503 retry)
[hit]   routed=planning  elapsed=0.00s    (zero requests)
```

Both answers were byte-identical, and `hark inspect` confirms the shape: the last `LlmResponseEnd`
(status 200, occurrence 1) is followed only by clock/random reads and `RunEnd` — no further
`LlmRequest`, `DnsQuery`, or `EgressAttempt` for the second call. `hark replay` reproduced the
asymmetry exactly:

```text
REPLAY-EQUAL  135 actions, digest 2d5c1549d109c327bd480916fc70f630fd0c4b744f240a8a6d6c3db176dc6537
```

This closes W5. All three items are now real, verified, zero-code-change recordings of an
unmodified LangGraph app: streaming, MCP, and now a genuine cache-miss/cache-hit pair replaying
identically down to which half made a network call at all.

**Verified.** `hark verify` clean. `hark replay` reproduces the digest with no network calls.
UrbanHeat's staging (`/opt/urbanheat`, the cloned `urbanheat-mumbai`, the run bundles) removed from
the box afterward; nothing UrbanHeat-specific remains checked into hark's repo except the two
roadmap/build-log entries describing what was verified.

**Next.** W6 — the replay-fidelity suite.

---

## 2026-08-18 — W5: UrbanHeat, zero code changes, real retry-on-429

Pointed hark at a real target for the first time: UrbanHeat's Supervisor (four LangGraph agents,
`langchain-google-genai` against Gemini, a TTLCache, RAG over Chroma) — not a stub, not written for
this project. Not one line of its source changed. What changed was environment: the repo cloned to
`/opt/urbanheat` (world-traversable, per the same Landlock constraint the W4 demo already
documented), its prebuilt `data/processed`/`models`/`chroma_db` artifacts staged alongside, and a
standalone driver script — `demo_workload.py`, playing the same role `demo/agent.py` plays for the
W4 incident — that imports `backend.agents.supervisor.Supervisor` and calls `.handle()` with a real
question. `hark run` did the rest: DNS mediation, TLS interception, egress allowlisting against
`generativelanguage.googleapis.com` and `api.open-meteo.com`, and credential substitution for
`GEMINI_API_KEY` via the same `[secrets]` mechanism the demo uses, with `SecretInjected` on the
record nine times in each of the two runs below and the real key never in the child's environment
or on disk.

**Two real, live runs, both `REPLAY-EQUAL`.** Each recorded 144 events and reproduced the identical
digest on replay, with zero network calls made during that replay:

```text
run4  root 97226da1...  REPLAY-EQUAL  144 actions, digest 1c658563...
run5  root 1af6ed98...  REPLAY-EQUAL  144 actions, digest a1676a15...
```

**The retry-on-429 path fired for real, unprompted** — this is the property W5 staged UrbanHeat for,
and it showed up from genuine free-tier rate limiting rather than a contrived test: a single agent
turn's tool-calling loop makes several model calls, `ChatGoogleGenerativeAI`'s own retry (ADR-0002,
`MAX_RETRIES=3`) fires on a 503 or 429, and the mediator recorded every attempt as its own
`LlmRequest`/`LlmResponseEnd` pair, `occurrence` incrementing on each:

```text
LlmRequest  ...generateContent (852 bytes, occurrence 0)   -> LlmResponseEnd status 503
LlmRequest  ...generateContent (852 bytes, occurrence 1)   -> LlmResponseEnd status 200
LlmRequest  ...generateContent (9499 bytes, occurrence 0)  -> LlmResponseEnd status 429
LlmRequest  ...generateContent (9499 bytes, occurrence 1)  -> LlmResponseEnd status 429
LlmRequest  ...generateContent (9499 bytes, occurrence 2)  -> LlmResponseEnd status 429
```

"Same logical call, multiple HTTP requests" was the thing W5's spec worried naive recorders would
get wrong. Recording it turned out to need nothing extra: it is already just more traffic through
the same allowed host, keyed by `(canonical_request_hash, occurrence_ordinal)` exactly as W3 built
it. Replay reproduced the 503s and the 429s in the same order at the same digest — the failure mode
is as replayable as the success.

**What this did not reach.** Both runs died inside the *first* question, never getting far enough to
demonstrate the TTLCache hit/miss interleaving the spec also wanted: the free-tier quota is 5
requests/minute, and the retries inside one agent turn exhaust it before a second question's first
call. A 65-second pause between questions did not help, because the exhaustion happens within a
single turn, not between them. Genuinely blocked on quota rather than on anything hark does — either
a paid key or a deliberately simpler single-tool-call question would clear it, left for next time.

**Friction, for the record.** Two Landlock-shaped defects in the setup, neither in hark: `.env`
world-unreadable (my own `chmod`, not a hark default) produced a permission error indistinguishable
at first glance from a sandboxing bug, and Chroma's SQLite needed both a `write_paths` grant and
actual filesystem write bits — Landlock and DAC are enforced independently, and satisfying only one
looks identical to satisfying neither until the error names which. Both are operator error, both
instructive: a policy that grants access Landlock enforces is not sufficient if the underlying file
mode still says no.

**Verified.** `hark verify` clean on both bundles. `hark replay` reproduces both digests with no
network calls. `hark inspect` shows the same shape on each: 1 EgressDecision (allowed), 2
DnsQuery/2 DnsDecision, 9 SecretInjected, 9 LlmResponseEnd.

**Next.** A slower or paid-tier run to reach the TTLCache interleaving; then W6.

---

## 2026-08-17 — W5 begins: streaming and MCP, both additive

Two of W5's three items, both off the box for now but built to the same standard: real tests against
a real flushing stream, not an assertion about intent.

**Streaming was already correct; nothing had checked it.** `internal/mediator` framed a streamed
response by writing chunks separately as they arrived, which W3's chunk-granular design got right
from the start. What it lacked was a test against a genuinely flushing SSE upstream rather than an
ordinary buffered one. Three properties, all confirmed: one recorded chunk per flush, the same
boundaries reproduced on replay, and the first event reaching the agent before a 450ms stream had
finished -- proof the mediator forwards rather than buffers.

While writing that test, a second defect turned up in the format rather than the code.
`LlmRequest.Streaming` was declared, set to `true` only by the synthetic bundle generator, and
populated by the real recorder never. Every genuine bundle therefore said no request had ever asked
for a stream, including the ones that had -- a field that is always false is a false statement in
every artifact carrying it. It now means what is knowable at the moment the request event is
written: an `Accept: text/event-stream` header, or a top-level `"stream": true` in the body, the
latter parsed rather than searched so the words inside a prompt do not count.

**MCP, recorded without a second protocol path.** An MCP server reached over streamable HTTP is, at
the wire, an allowed host receiving POST requests -- already recorded and replayed exactly as model
traffic is, with that path already proven. Rather than build a parallel MCP-aware forwarding path
and risk the machinery W2-W4 verified on the box, the mediator recognises a JSON-RPC 2.0
`tools/call` request and its matching response and records a second, semantic layer on top:
`ToolCallRequest`/`ToolCallResult`, gaining an `Exchange` field each so they correlate the same way
`LlmRequest`/`LlmResponseEnd` do.

Additive is the whole design. A call the parser fails to recognise -- a different JSON-RPC shape, an
unrelated API that happens to use the word "method" -- still replays correctly through the generic
events; the only thing that degrades is how readable `hark inspect` is for that one call. The
worst-case failure mode of a new feature landing here is strictly smaller than anywhere else in the
mediator, on purpose.

One efficiency point worth keeping: the response body is accumulated into memory only when the
request was recognised as a tool call. Every other response -- which is most of them, and which can
be arbitrarily large model output -- pays nothing for a reading nobody asked for.

**Verified.** Full suite green, `go vet` clean, Linux cross-build clean. New: streaming tests against
a real flushing upstream, and MCP tests covering both the parser in isolation and the whole mediator
path in both live and playback mode, plus the negative case -- ordinary traffic must record no
`ToolCall*` events at all.

**Next.** UrbanHeat's LangGraph agents with zero code changes, which is what W5 was actually staged
for -- these two were the prerequisites its retry-on-429 and TTLCache paths are likely to exercise
immediately.

---

## 2026-08-17 — W4 on the box: five defects, one of them the important one

The demo runs end to end on kernel 6.17. Recorded 31 events, `REPLAY-EQUAL`, forked at event 11 with
the injection stripped, both runs rendered.

```text
FORKED  provably identical prefix, live suffix
  branch at    event 11, after 11 verified actions
  patch        strip the injected instruction from the fetched briefing
```

Given a briefing with nothing hidden in it, the model returned a summary instead of a plan to post
anywhere, and the forked run contains no egress denial because nothing tried to leave. That is the
whole argument of the project, run rather than described.

**Five defects, and not one was visible from the code.** This is the third week running that has been
true, and it is the reason the roadmap does not tick an acceptance from a review.

**1. The one that matters: a real credential reached the log.** The recorded request carried
`Authorization: Bearer demo-not-a-real-key-01J8X` — the operator's actual value, in an artifact
designed to be published. The broker was working perfectly; the agent had simply been handed the real
key to begin with.

`buildEnv` appended `MODEL_API_KEY=<placeholder>` to `os.Environ()`, which already held
`MODEL_API_KEY=<real>` because the demo runs `MODEL_API_KEY=... hark run`. Appending reads as
equivalent to replacing and is not: CPython's `convertenviron` keeps the **first** occurrence of a
duplicated name. The placeholder was never seen by anything.

Two lessons, and the second is the sharper one. Variables are now removed before being set — the same
bug applied to `SSL_CERT_FILE`, where an inherited value would have quietly beaten this run's CA. And
`Broker.ContainsSecret`, whose doc comment reads *"the assertion the recorder runs on anything about
to be written to the log"*, was called by nothing at all. It is wired in now: an event carrying a real
value is refused and the run is failed rather than sealed. A bundle with a hole beats a bundle that
cannot be shared.

A defence that exists only in a comment is not a defence. It fired on its first real outing.

**2. Landlock could not open a path the agent was granted.** `landlock: opening
"/home/azureuser/harkv01/shim" for a rule: permission denied`, as root.

The agent runs as uid 0 with every capability dropped, which is the design — and it means
`CAP_DAC_OVERRIDE` is gone, so ordinary permissions apply to it like anyone else. `/home/azureuser`
is mode 0750. `O_PATH` needs no permission on the file itself, but *reaching* it still needs search
permission on every parent.

The init child now opens its rule handles before the capability drop and builds the ruleset from
them, so registration no longer depends on privilege the process deliberately gave up. And `Launch`
refuses up front, naming the directory that blocks the agent, because Landlock only ever removes
access and can never grant past DAC — a policy naming such a path is not wrong so much as
unachievable.

**3. Replay came out one event short.** The recording held a `SecretInjected` the replay did not,
because injection sat behind the playback branch and a replayed run never reaches it.

This is W3's lesson on a second channel. Then it was the shim serving clock values without recording
them; here it is the broker. **Whatever the harness serves, it must also record, or the replay reports
a divergence it caused itself.** Substitution now happens in both modes — the replayed copy is
discarded immediately, but the decision is genuinely re-derived — and the digest stops comparing
`ValueHash`, which a replay deliberately has no way to reproduce.

**4. A data race the race detector found on its first Linux run**, between `Serve` writing the shim's
listener and `Close` reading it. Not only a test artifact: a run that fails early runs its deferred
`Close` while `Serve` is still starting. The exported `Live` field invited the same mistake and is now
a method behind the mutex. Documentation is not a lock.

**5. `awk ... {exit}` under `set -o pipefail`.** Twice — in the demo and again in the benchmark
script. Exiting at the first match closes the pipe, `inspect` dies of SIGPIPE, and pipefail turns a
successful replay into a failed script one line later. The benchmark version was worse: `elapsed()`
discards output by design, so five failed runs produced five plausible millisecond figures and a
ratio computed from them. It now verifies and replays once, loudly, before believing any number.

**The numbers.** Mediation costs **0.18 ms at p50** against a 5 ms target — invisible beside a model
call. A run that waited 0.9 s on its model replays in **145 ms**, and the useful form of that is not
the 7.3x ratio but the floor: *a replay costs what starting the agent costs*, almost all of it
namespace setup and interpreter start. Verifying 100k events takes 276 ms at 188 MB/s; proving one
event costs 448 bytes and 14 hashes. Full tables and the box's specification are in
[benchmarking.md](benchmarking.md).

**Verified.** Full suite green on kernel 6.17, race detector included, launcher suite green as root,
demo end to end from a clean `git clone`.

**Next.** Anchor a run in the public log for real and check inclusion from a second machine, record
the GIF, verify the related-work table W0 still owes, and tag v0.1.0.

---

## 2026-08-17 — W4 built: the fork, the anchor, the report, the incident

Everything v0.1 needs is implemented and green off the box. **None of it has been run on the box**,
which is the honest headline: W2 and W3 each found real defects the moment they ran, and there is no
reason to think this week is different. The roadmap ticks the code and leaves every acceptance
unticked.

**The fork, and what it is allowed to claim.** `hark fork -at N -patch p.json` re-executes an agent
against its own recording, checks the prefix action by action as it happens, changes one response at
the branch point, and goes live. The output is fixed wording:

```text
FORKED  provably identical prefix, live suffix
```

There is no process checkpoint, so a fork cannot resume at N -- it has to arrive there. That raised
the question the week turned on: if the prefix is re-run rather than resumed, what makes it the same
prefix? The answer is the gate, driven by the child's own event stream and folding each event into
the same digest `hark replay` compares. A divergence kills the agent at the action that caused it.
Continuing would produce a bundle carrying a `ParentRoot` it has no claim to, and someone would
eventually quote it. ADR-0008.

Three refusals rather than one, because a fork that *nearly* happened is the case most likely to be
misread: `FORK-DIVERGED`, `FORK-INCOMPLETE`, and `FORK-UNPATCHED` -- the branch point was reached but
no request followed it, so the patch never applied and the run is not the counterfactual it would
otherwise claim to be. In the same spirit, a patch that matches nothing is an error. The alternative
is a fork that runs, comes out clean, and lets the operator conclude the change was harmless when it
was never made.

**Two structural changes fell out of it.** The mediator now decides playback per exchange rather than
per connection, and dials upstream lazily -- a fork hands over mid-run and the agent is under no
obligation to open a fresh connection at that moment. A replayed run still opens no outbound
connection at all, now because nothing ever asks for one rather than because a branch was skipped.
And the shim gained a fork mode: the supervisor decides *when* to go live, because it is the side
that knows how far the verified prefix got, but the value is produced in the agent's process, because
that is the only side that can make a `uuid.UUID` the agent's own module will accept. The reply says
`live` and the shim draws and reports back.

**Anchoring, and the trap in it.** The obvious Rekor type is `hashedrekord`, which carries a digest.
It cannot work here: Ed25519 signs the whole message, so a log handed a digest has nothing to verify
against. The submission is a `rekord` over the signed-tree-head bytes -- small, public, and exactly
the commitment that matters.

`hark verify` recomputes the log's root from the inclusion proof rather than believing the API. That
is RFC 6962 arithmetic, SHA-256 with 0x00/0x01 prefixes, deliberately not reusing `internal/hashchain`
-- it is somebody else's tree, and BLAKE3 there would be correct hashes of the wrong thing. Checked
against a reference tree built by the recursive definition from the RFC, for every leaf of every size
up to 33.

Verification now distinguishes three outcomes where a lesser tool would have two: inclusion verified,
the log holds no such entry (a failed claim, exit 1), and the log could not be reached (nothing
established either way, exit unchanged). Anchoring itself is never fatal -- a log that is down must
not mean a run cannot be recorded.

**A seam that needed justifying.** The demo has to run with no key, no cost and no network, and the
benchmarks must not measure a hosted endpoint. Both need the mediator to dial somewhere other than
the host the agent asked for -- a testing seam pointed straight at the project's central claim. A
bundle whose events name `model.example` while the mediator spoke to loopback would be internally
consistent and untrue, and every check `hark verify` performs would pass.

So `-upstream HOST=ADDR` is recorded in `RunStart`, the redirected host still has to be in the
allowlist, and TLS still verifies the name the agent asked for against a CA that has to be named
explicitly. Skipping verification for redirected dials would have been one line and would have
silently weakened every connection an operator did not think of as a stub. `hark replay` carries the
recorded value through rather than rebuilding it, or every replay of a stub-recorded run would
diverge at action 0. ADR-0009.

**The report.** One HTML file, no server, no framework, no JavaScript, no external request. The
escaping is the part worth being deliberate about: a recorded body is attacker-controlled by
construction, so a page that interpolated it raw would turn the evidence into a way to attack whoever
reviews it. `html/template` escapes by context and a test asserts it. The footer says the page is not
a verification, because a picture of a verification is not one.

**The incident.** A naive agent, a briefing with an instruction hidden in it, a stub model that
follows instructions in its context -- the one model behaviour the demo depends on, and one every
current model has. The agent is deliberately typical: no eval, no shell, no disabled check. The only
thing it does wrong is believe what it reads, which is the whole of prompt injection and the reason
containment cannot live inside the agent.

The fork branches at the *page fetch*, not at the completion. Patching the model's reply would have
been easier and much weaker: it patches the conclusion rather than the cause. Forking at the fetch
asks whether the page was responsible.

**Benchmarks: harnesses, not numbers.** Four of the five run from a documented command. The replay
ratio gives the stub a 0.9s delay per completion, because replay's whole advantage is not waiting on
a model and measuring against a stub that answers instantly would leave nothing to skip -- it would
understate the figure most likely to be quoted. No number is published until the box produces it; a
plausible placeholder in a benchmarking document is worse than a blank.

Two things learned in passing. Go's monotonic clock on Windows advances in millisecond steps, so the
first percentile run reported a p50 of 0 against a mean of 100µs -- these belong on Linux. And
Windows Defender began refusing to link `cmd/hark` part-way through the session, so the CLI was never
executed here; the Linux cross-build and `go vet` are clean, and the package tests all pass.

**Verified.** `go build`, `go vet` and `go test` clean across the tree on Windows; `GOOS=linux`
cross-build and vet clean. New tests: the fork gate and patches, the Rekor arithmetic against a
reference tree, the report's self-containment and escaping, the shim's fork handover from both sides,
and the mediator's mid-connection handover.

**Not verified.** Everything that needs the box: `demo/run.sh` end to end, a real anchor, the
benchmark figures, and replay on a second machine.

**Next.** Run the demo on the box, fix what it finds, fill in the numbers, record the GIF, verify the
related-work table left over from W0, and tag v0.1.0.

---

## 2026-08-16 — W3 closes: REPLAY-EQUAL

```text
REPLAY-EQUAL  22 actions, digest f6ac72c536be07e635eb5b9f623b8cb8b1a9b8f7ea67e90e822e1526c751be13
```

A Python agent drawing a uuid, a random number and the clock, fetching an allowed host and being
denied a disallowed one, replayed identically. This is the claim the project rests on.

**What REPLAY-EQUAL compares, and why it is not the root.** Two runs of the same agent cannot produce
the same Merkle root and never could: the run id is fresh per run, wall-clock and monotonic
timestamps differ, and a credential placeholder embeds the run id. Comparing roots would report a
divergence on *every* replay, including a perfect one. So the comparison is a digest over normalised
actions, with the volatile fields zeroed and everything else — response bodies, policy decisions,
hosts, ordering, exit code — participating. Each exclusion is justified where it is made, because
anything excluded is something the digest does not check.

**Three bugs, and every one of them only appeared when it ran.**

The live path had the same framing bug I had already fixed in playback. Hand-writing the status line
and headers and streaming the body raw only works when the upstream sent a Content-Length; without
one the agent read until the connection closed, which never came because the mediator was waiting for
the next request. The symptom was an agent timing out while holding a complete response it could not
see the end of — and because the mediator had already recorded every byte, the *recording* looked
perfect. Only the live run failed. `Response.Write` now derives the framing the way a real server
does, with the body wrapped so chunk recording is unaffected.

Replay rebuilt the `PolicyLoaded` event instead of re-emitting the recorded one, so `Source` differed
(`demo.toml` versus `recorded`) and the digest diverged at action 1 over a field describing where the
policy came from rather than what it permitted.

The replaying shim served clock and RNG values without recording them, so the replayed bundle was
missing exactly the reads the shim had answered — three fewer actions, and a divergence the replay
had caused itself.

**Falsifiability, checked rather than assumed.** A tool that only ever says REPLAY-EQUAL is worthless.
Changing the agent produced `REPLAY-DIVERGED at action 6`, naming both sides —
`dns A example.com` against `dns A other.example` — with the preceding actions for context. And the
no-egress claim is now measured: 18 packets to :443 during the recording, **0** during the replay.

**A property worth having.** Replaying a replay produces the same digest as the original, so a
replayed bundle is a faithful recording in its own right. Replay also needs no credentials at all:
placeholders are rebuilt with dummy values, which works because canonicalisation normalises them
anyway. Someone who cannot authenticate to the endpoints a run used can still replay it.

**Verified.** Full suite green across thirteen packages on the box, race-clean, launcher suite green
as root. Record/replay verified end to end on kernel 6.17 with CPython 3.12.

**Next.** W4: the incident demo, `hark fork`, the static HTML trace report, Rekor anchoring, and
benchmarks. v0.1 ships there.

---

## 2026-08-16 — the shim, run for the first time

Ran the shim against a real interpreter, and it failed on the first test. Worth recording exactly
how, because the bug was invisible to reading and the symptom was the one this project exists to
prevent.

`uuid.uuid4()` calls `os.urandom()` underneath, and both are patched. Recording captured the inner
draw *and* the outer result; replay served only the outer one from its own queue and never consumed
the inner. The queues drifted apart, so a later `os.urandom(8)` came back with the sixteen bytes
recorded for the uuid:

```text
recorded  x=c8c779385d75de7a
replayed  x=2bc7bcf84663a7e715483fd4036a46ee   <- the uuid's bytes
```

The replay would have reported success while the agent saw a value it never saw. A thread-local
re-entrancy guard now records only the outermost patched call, so record and replay consume in step.
Thread-local rather than a plain flag, because an agent may draw from several threads and a global
would let one suppress another's capture.

The regression test asserts the recorded value *counts* — two uuids and two urandom draws, not four
urandom draws — so a reappearance fails on a number rather than on a confusing diff of random hex.

**The lesson, not the bug.** Everything about this was reasoned through carefully and written down
before it ran, and it was still wrong. Nesting between patched functions is not visible in either
function; it only exists in the pair. This is the second time in the project that running the code
found something reading it could not have — the first was the capability drop reading `/proc` after
Landlock had closed it.

**Verified.** All 9 shim tests green against CPython 3.12 on kernel 6.17. Full suite green on the box
across thirteen packages, launcher suite green as root.

**Next.** `hark replay` — the last piece of W3.

---

## 2026-08-16 — playback, and the in-process shim

**A structural flaw, found before it could bite.** The log has a total order over boundary
*crossings*, not over whole exchanges. Two concurrent connections interleave their events, so a
reader collecting chunks until the next end marker splices one response onto another's request — and
replay would serve that without noticing. Every LLM event now carries an exchange correlation id.
`TestInterleavedExchangesAreSeparated` builds exactly that shape; grouping by position passes every
other test and fails only this one.

**Refusing to guess, deliberately.** The W3 spec said to fall back to strict sequence position when a
key does not match. That is dropped rather than done. Falling back *is* guessing, and a replayer that
guesses can report success while the agent saw an answer it never received — which would make every
replay result untrustworthy. A miss now fails the run and names the request. The same applies to a
half-recorded exchange: left unindexed rather than served as a partial answer.

**A replayed run opens no outbound connection at all.** No side effects, no cost, no dependence on
the endpoint being up. The test proves it with a dialer that fails unconditionally, so falling
through to the live path fails rather than quietly succeeding against a real service.

**Body framing is normalised on replay**, and finding out why cost a debugging round. Replaying an
SSE stream's headers verbatim while writing the body raw leaves the client with no way to know where
the response ends — it reads until close, which never comes, because the mediator is waiting for the
next request on the same connection. Length-delimiting fixes it, and the chunk arrival boundaries
that actually matter for fidelity survive either way.

**The shim, and a Python trap worth knowing.** `site.py` wraps `sitecustomize` in `except Exception`.
An ordinary exception there is reduced to a one-line "Error in sitecustomize" warning and the
interpreter carries on *unpatched* — producing a recording that looks complete and can never replay.
Exactly the silent failure the shim exists to prevent. Everything now exits through `sys.exit`, whose
`SystemExit` derives from `BaseException` and passes straight through that handler.

Randomness is captured per draw rather than by re-seeding. Re-seeding is far cheaper and does not
work: the agent can build its own `random.Random` instances, and any library it imports may consume
draws in numbers that change between versions. Also `randint`, `choice` and `shuffle` are bound
methods of a hidden instance, so patching `random.random` alone leaves them on the unpatched
generator.

**A test-harness trap.** `exec.LookPath("python")` succeeds on Windows even with no Python installed:
the Microsoft Store ships an app execution alias, a real `python.exe` that resolves and then prints
an advertisement. The helper now probes the interpreter rather than trusting the path.

**Verified.** 134 tests, 184 with subtests, across 11 packages; build, vet, gofmt clean. **Not
verified:** the shim's Python side has never been executed — its tests are Linux-only and the box was
stopped. That is the first thing to run next session.

**Next.** `hark replay`: wire the playback source and the shim's replay mode together, recompute the
root, and report REPLAY-EQUAL or the first divergent event.

---

## 2026-08-16 — W3 begins: request identity

Canonicalisation, the task the spec flagged as most likely to overrun. Written off-VM, since none of
it needs a kernel.

**The asymmetry that shapes the whole package.** A key that is too loose makes two different requests
collide, and replay then serves the wrong response *and reports success*. Too tight, and a request
that is logically the same fails to match — which refuses a run that should have worked, but does so
loudly. The second is recoverable, the first is not, so everything errs toward distinguishing.

**Placeholders are normalised, not stripped.** A correction to the plan, which assumed the recorded
request holds a placeholder and the live one holds the real credential. Both hold placeholders: the
broker injects on a copy, so canonicalisation only ever sees the agent's original. The real problem
is that a placeholder embeds the run id, so a replayed run emits a different literal for the same
logical request. Normalising to a sentinel fixes that; stripping the header would have thrown away a
genuine distinction between two different secrets.

**Length prefixing, for a reason worth stating.** Without it the header pair `a: bc` and the pair
`ab: c` concatenate to identical bytes, and two different requests share a key. That is precisely the
silent failure above, so there is a test for it rather than a comment.

**Numbers keep their text.** Decoding JSON into `float64` rewrites `1` as `1e+00` and loses precision
above 2^53. Using `json.Number` keeps the original literal, so canonicalisation does not quietly
rewrite the body of a request nobody asked it to touch. Key order is normalised because Python does
not sort dict keys; array order is not, because a message list is an array.

**The mediator now keys through the same package.** It had a placeholder implementation hashing only
method, host, path and body. Two definitions of "the same request" would drift, and the way that
surfaces is replay matching the wrong response. Headers now participate, with the volatile ones
dropped — so a retry carrying a fresh `X-Request-Id` still keys to the call it repeats, which has its
own test because getting it wrong would mean retried requests never replay.

**Verified.** 15 tests in the new package, full suite green across ten packages, fuzzing clean.

**Next.** Mediator playback mode, then the Python shim for clock and RNG, then `hark replay`.

---

## 2026-08-16 — W2 closes: `hark run`, and three bugs only running it could find

The acceptance criterion is met. A `curl`-driven agent, with `HTTPS_PROXY`, `https_proxy` and
`ALL_PROXY` all unset, fetched an allowed host and then tried to exfiltrate to `evil.example`. Both
are on the record; the second was refused. `hark verify` returns VERIFIED over 19 events.

The three bugs are the story of this session, and none of them was visible in the code.

**Agent output went nowhere.** `Spec`'s stdio fields are `*os.File`, `exec.Cmd`'s are `io.Writer`.
Assigning a nil `*os.File` to an interface produces a non-nil interface holding a nil pointer, so the
`== nil` fallback never fired and every write failed silently. The agent ran fine and its exit code
propagated correctly — `RunEnd` recorded `exit 42` when asked for it — so the only symptom was a
program that appeared to produce nothing at all. Textbook Go, and invisible until something needed to
print.

**The bind-mounted resolv.conf needed its own Landlock rule.** A rule covers a hierarchy, and a bind
mount is its own mount point: the file is not beneath the rule on `/etc`, and it is no longer reached
through the rule on the source directory either. Granting both looks sufficient and is not. The agent
got EACCES on `/etc/resolv.conf`, every lookup failed, and nothing reached the mediator — which
presented as a run recording four events and an agent whose curls all returned HTTP 000.

**Landlock then refused that rule with EINVAL**, because the read set includes `READ_DIR` and the
kernel rejects directory-only rights on a regular file. Rights are now masked by what the path
actually is. Easy to miss, because every path in a policy is normally a directory — the first
non-directory rule is what surfaces it, and the error says only "invalid argument".

**A documented guarantee that was not true.** The format is built around a crashed run staying
verifiable up to its last intact frame. Buffered in userspace, a SIGKILL lost everything still in the
buffer — for a short run, the entire bundle, leaving a zero-length file that could not even be opened.
`hark verify` on a killed run said "reading magic: EOF" rather than reporting the prefix. Frames are
now handed to the OS as written; a killed run verifies as `TRUNCATED` with its events intact.

**Verified on kernel 6.17.** 19 events for the incident, `VERIFIED`. Signed runs verify against a
pinned key. An inclusion proof for the denial is 517 bytes against a 3,574-byte bundle. A killed run
reports `TRUNCATED` and exit 3 with its prefix readable. Leaked forwarding rules from that killed run
were pruned by the next one, 2 down to 0. No stray interfaces. Full suite green on both machines,
race-clean across all ten packages, launcher suite green as root.

**Next.** W3: replay. Request canonicalisation is the two-day task and the one most likely to
overrun.

---

## 2026-08-16 — the mediator listens

DNS responder, TLS termination, policy evaluation and the forwarding path. Written off-VM, because
none of it needs a kernel feature: bind address and ports became configuration, so the whole server
runs on loopback with high ports in tests and differs from a real run only in using the veth address
and 53/443.

**Where the total order comes from.** Recording happens under one lock in the mediator. That is the
only place concurrent boundary crossings are ordered, and it is what replay will follow. It
deliberately stops at the boundary: two threads racing on a dict inside the agent are not ordered by
anything here, and the replayer is meant to detect that rather than pretend otherwise.

**Denials are synced, and the attempt is written first.** A denial is the evidence the bundle exists
to carry, so a crash immediately afterwards must not be able to erase it. Writing the attempt before
the verdict means a crash between the two still leaves the attempt on the record.

**A connection with no SNI is denied, not allowed.** That is a literal-IP dial. Policy is expressed
in host names, so a connection carrying none cannot match it, and defaulting to permit would make
skipping DNS an escape hatch.

**The broker's guarantee, tested from both ends.** The recorded request holds the placeholder; only
the copy sent upstream holds the credential. That is structural rather than careful, because Inject
returns copies instead of mutating -- so the recorded request cannot accidentally be the injected
one. The test asserts the upstream received the real value *and* that neither the recorded request
nor the SecretInjected event contains it.

**ALPN pinned to http/1.1.** Letting the client negotiate h2 would mean unpacking framed
multiplexing before anything could be recorded per request, for throughput no agent notices beside
model latency.

**Occurrence ordinals now, matching later.** One run can send byte-identical requests and get
different answers -- a retry after a 429 is the ordinary case. The ordinal is recorded now so W3 has
it; headers stay out of the key for the moment, since they carry the injected credential and
canonicalising them properly is the two-day job that belongs with the replay work.

**A fixture bug worth noting.** The forwarding test first failed with an empty placeholder: the test
policy had no `[secrets]` mapping, and the broker takes environment-variable names from there. The
test now asserts the placeholder is non-empty before proceeding, so the same mistake fails with a
sentence rather than a confusing diff.

**Verified.** 109 tests, 156 with subtests, across 9 packages. Build, vet, gofmt clean; race clean.

**Next.** `hark run`: wire policy, broker, mediator, launcher and bundle together, write
`/etc/netns/<ns>/resolv.conf`, and run the whole thing on the VM against a real `curl`. That closes
W2.

---

## 2026-08-16 — the launcher: containment working end to end

The three restriction layers now actually reach an agent, via the re-executed init child that ties
them together. `ADR-0007` has the design; this is what building it taught.

**The integration test earned its place immediately.** Every unit test passed while the whole thing
was broken. `DropCapabilities` reads `/proc/sys/kernel/cap_last_cap`, and it ran *after* Landlock had
already made `/proc` unreadable — so the drop failed and the agent kept root's capabilities. Reading
the code, the order looked fine; the original comment even justified it, claiming the earlier steps
still needed `CAP_SYS_ADMIN`. They do not. Landlock is built for unprivileged callers and seccomp
needs only `NO_NEW_PRIVS`.

Fixed by dropping capabilities first, which is the better default anyway: everything after that line
runs unprivileged, so a mistake in it has less to work with.

**A second correction, this one to the design.** The original plan was a namespace with *no default
route*, on the theory that no route means no escape. True, and useless: the packet dies in the
routing table, the mediator never sees it, and nothing is recorded. The default route now points at
the mediator, with explicit `FORWARD` DROP rules so the host cannot route onward regardless of its
global `ip_forward` setting. Traffic reaches the mediator or it reaches nothing. This is ADR-0006
arriving in the code.

**A leak worth finding.** A veth pair is reaped with its namespace — deleting either end takes both —
so teardown is usually a no-op on the success path. The `iptables` rules are *not* reaped. A
supervisor killed before teardown leaves two rules naming an interface that no longer exists. They
are inert, but they accumulate for as long as the host is up. Every run now prunes stale
`hk`-prefixed rules before starting, so hark cleans up after its own past failures without anyone
needing to know it should. Tests cover both directions: stale rules go, live and unrelated ones stay.

That same fact caused a test failure that looked like a bug and was not: `TestTeardownRemovesTheBoundary`
checked for the host interface after launching `true`, which had already exited and taken the veth
with it. The agent sleeps now.

**Verified.** Full launcher suite green as root on kernel 6.17: the agent runs, exit codes propagate,
there is no route to the internet even with every proxy variable unset, the routing table contains
nothing but the mediator, the audit log is unreadable, granted paths work, `CapEff` is all zeros
despite a root supervisor, and `Seccomp: 2` confirms a filter is installed. Full suite green
unprivileged and under `-race`. Zero stray interfaces or rules afterwards.

**Next.** Bind the DNS responder and the TLS listener on the mediator address, record the boundary
crossings, and wire it together behind `hark run`.

---

## 2026-08-16 — seccomp, capabilities, and the DNS message layer

**Seccomp.** Hand-assembled classic BPF rather than libseccomp, which would drag cgo and a system
library onto every build host for a filter of about thirty instructions.

The architecture check earns its place. On x86_64 a process can issue 32-bit syscalls where the
numbers mean different things, so a filter matching numbers without pinning the ABI can be sidestepped
by calling through the other one. That case is killed rather than refused, because it cannot be an
accident.

Denials return EPERM rather than killing the process. The call is refused either way, but an error the
runtime can surface beats a process that vanishes and leaves whoever is debugging it with nothing.

Most of what the filter denies also needs a capability the child will not hold, so it is genuinely
defence in depth. The exceptions justify it on their own: `ptrace` and `process_vm_readv` work between
processes of the same user with no capability at all.

**Capabilities.** The order is fixed and not obvious. Dropping the bounding set needs `CAP_SETPCAP`, so
it must happen while capabilities are still held — clearing the permitted set first would strand the
bounding set populated with nothing left able to empty it, and a populated bounding set is exactly what
lets a setuid binary hand capabilities back across execve. Ambient goes first, since that is the set
designed to survive exec.

`cap_last_cap` comes from `/proc` rather than a constant. The list grows between releases, and a value
compiled in today would silently stop dropping the newest capabilities on a newer kernel — the ones
least likely to be audited.

**DNS message layer.** Written off-VM, since wire-format parsing needs no kernel.

The decision worth recording: non-A queries get NOERROR with an empty answer section, never NXDOMAIN.
NOERROR says the name exists but has no record of that type, so the client falls back to A and reaches
the mediator. NXDOMAIN would convince it the name does not exist at all and it would give up without
connecting — losing the connection *and* the SNI observation that ADR-0006 depends on.

Compression-pointer following is bounded at sixteen jumps, with a test that fails on non-termination
rather than trusting the bound. A name pointing at itself is the standard way to hang a resolver, and
hanging here would stall the run being recorded.

**Testing.** Both new pieces are checked against real implementations rather than fixtures. The
seccomp and capability work runs in helper subprocesses and measures whether the kernel actually
refused. The DNS layer is driven by Go's own `net.Resolver` over loopback UDP, which also exercises
the AAAA-fallback path for free — the resolver asks for AAAA, gets an empty NOERROR, retries with A.

**Verified.** 17 launcher tests green on the box; full suite green on both machines; DNS fuzzing 1.6M
executions clean.

**Next.** The netns/veth setup and the re-exec init child that ties Landlock, seccomp and the
capability drop together. Needs the VM.

---

## 2026-08-16 — Landlock, against the real kernel

First session working directly against the VM rather than writing code to be tested later. Edits
happen locally, sync to the box, build and test there — so the repo's git history and identity stay
on one machine while the syscalls get exercised on another.

**What landed.** `internal/launcher/landlock_linux.go`: ABI probe, rights masked to what the running
kernel supports, `NO_NEW_PRIVS`, `restrict_self`. A build-tagged stub covers non-Linux hosts so the
pure-logic packages still build on Windows — and the stub returns an error rather than succeeding
quietly, because a containment layer that reports success while doing nothing is the exact failure
this project exists to prevent.

**Two kernel facts worth writing down**, both now enforced by the code and its tests.

`landlock_restrict_self` restricts the *calling thread*, not the process. Go moves goroutines between
threads whenever it likes, so this cannot be called from an ordinary goroutine and trusted. It needs
`runtime.LockOSThread` with `execve` following on the same thread. That is the concrete justification
for the re-exec design the launcher will use — not a stylistic preference borrowed from runc.

An empty ruleset denies everything rather than allowing everything. A policy granting no paths
therefore fails closed, which is the right direction, but it is the sort of thing someone later
"simplifies" into an early return.

**Testing shape.** Landlock cannot be tested in-process, since the first test would restrict the test
binary and every later test would inherit that domain. So the tests re-execute the test binary as a
helper, apply a ruleset, attempt one filesystem operation, and read the answer from its exit code.
That measures whether the kernel actually refused rather than whether a syscall returned zero, which
is the whole difference between containment and the appearance of it.

`TestRealisticLayout` is the one to point at: the agent reads its own source, writes its workspace,
and can neither read nor write the bundle it is being recorded into.

**A dependency trap.** `go get golang.org/x/sys/unix` silently raised the module's Go directive to
1.25, which would have broken the VM's 1.23.5 toolchain and CI both. The bump came from the latest
x/sys and persisted after pinning an older one, because Go never lowers the directive on its own.
Set back to 1.23.0 by hand; the pinned x/sys builds fine there.

**Verified.** Landlock ABI 7 on kernel 6.17. Eight enforcement tests green on the box, full suite
green on both machines, vet and gofmt clean.

**Next.** Seccomp and capability drop, then the netns/veth setup and the re-exec init child that ties
them together.

## 2026-08-16 — W2 begins: policy loader and SNI parser

Started W2 with the parts that have no kernel dependency, so they could be written with the VM
stopped. Only netns, Landlock and seccomp actually need the box running, and leaving it up while
typing burns credit for nothing.

**Policy.** An allowlist, not a language. The interesting decisions are all about failing loudly:
wildcards rejected rather than half-implemented, unknown keys rejected rather than ignored, duplicate
and malformed hosts rejected. Each of those, done the lenient way, produces a policy that reads as a
restriction and behaves as an omission — which is the worst possible defect in this component.

`Load` returns the raw file bytes next to the parsed policy so `PolicyHash` covers what was actually
on disk. A re-serialisation would drop comments and formatting, and the artifact a reviewer diffs is
the file.

**A portability bug the tests caught.** `filepath.Clean("/app")` returns `\app` on Windows. Policy
paths describe locations inside a Linux namespace, so they must be cleaned with `path.Clean`
regardless of which OS parses them. Worth noting in the W2 spec because the launcher will face the
same trap.

**SNI.** The mediator learns the agent's intended destination from the ClientHello, and those bytes
come from the untrusted process. Everything goes through a bounds-checked cursor; a panic here would
take down the process holding the signing key and the audit log, on input the agent chooses.

Three outcomes stay distinct rather than collapsing into "error", because callers act differently on
each: still arriving (read more), not TLS (reject), valid but no SNI (record with an empty host —
what a literal-IP dial looks like).

The recovered name is validated before reaching policy or the log. Control characters could forge log
lines. Refusing beats sanitising, since a cleaned-up name might still match a rule it should not.

Tested against ClientHellos generated by Go's own TLS stack rather than hand-written fixtures, which
checks the parser against what clients actually send instead of against my reading of the RFC. Every
truncation prefix and every single-byte corruption of a real hello is exercised. Fuzzing ran ~2M
executions with no crash.

**Verified.** Full suite green, vet and gofmt clean.

Continued in the same session with the other two kernel-independent pieces.

**Broker.** The design decision worth recording is that `Inject` never mutates its inputs. It works
on copies and returns them, so the caller records the originals — which still hold placeholders — and
sends the copies. The alternative is a rule every call site has to remember, and forgetting once puts
a live credential into an artifact designed to be published. Structural beats documented here.

Two smaller things that would have been bugs. Placeholders carry both the run id and the logical
name: without the logical name, substitution cannot tell two secrets apart. And values are replaced
longest-first, because if one secret's value contains another's, replacing the shorter first mangles
the longer, which then fails to match and travels unsubstituted.

`Inject` also refuses to substitute for a denied host even though the mediator checks policy first.
Redundant by design — if that check regresses, the credential still does not travel.

**CA.** Fresh per run, memory only, P-256, 24-hour validity, path length constrained to zero, private
key with no accessor. A CA on disk can be stolen; one outliving its run can forge certificates long
after. Regenerating costs milliseconds against a standing risk.

Tested end to end through a real `tls.Listen` and a real client trusting only that CA. That is what
proves interception is transparent to the agent — asserting on certificate fields would not. The
converse matters too and is covered: a client with default roots must be rejected, and run B's CA
must not validate run A's leaf.

**Verified.** 88 tests, 118 with subtests, across 8 packages. Build, vet, gofmt clean.

**Next.** The off-VM work is done. One focused VM session remains for W2: the launcher (netns,
Landlock ABI detection, seccomp, capability drop), the DNS responder, egress recording, and wiring it
all behind `hark run`.

---

## 2026-08-16 — W0: the box, and a hole in the containment design

Provisioned the target machine and ran the prototype. It found a real defect in the design, which is
exactly what the phase was for.

**The box.** Ubuntu 24.04 on Azure, kernel 6.17, 2 vCPU / 3.8 GiB. `landlock` is in the active LSM
list at **ABI version 7**, so no kernel command-line surgery was needed and the full ruleset feature
set is available. No inherited seccomp filter, so the launcher is free to install its own. The repo
builds and its tests pass there, including under `-race`, which the Windows box cannot run for want
of cgo.

Before that box existed I ran the same probe in a hosted shell, which reported
`capability,lockdown,yama,loadpin,safesetid,apparmor,bpf` — no `landlock`. Namespaces, veth and
seccomp all worked there; only filesystem scoping did not. Worth recording because it is the
signature of every container-based environment, and it is now in `docs/troubleshooting.md`.

**Containment, proven rather than assumed.** A network namespace with a veth pair and a single link
route. A process inside it cannot reach the network. A process that unsets `HTTPS_PROXY`,
`https_proxy` and `ALL_PROXY` also cannot reach the network, because the routing table is the control
and the environment variable is only a convenience. TLS interception with a per-run CA works and is
transparent to the client — `curl` reported `ssl_verify_result=0` while the mediator logged the full
plaintext request and response.

**The defect.** The original design was netns with no default route plus `HTTPS_PROXY`. Cooperating
agents go through the mediator; non-cooperating ones have no route and fail. Safe, but *silent*: the
packet dies at the routing layer, the mediator never sees it, and nothing is recorded. The project
claims every attempt to cross the boundary is on the record, and that claim was breaking in precisely
the case that matters most — the agent that is misbehaving.

The prototype surfaced it concretely. With no resolver in the namespace, a non-cooperating `curl`
failed at DNS before any TCP connection existed, so the DNAT rule I had added never even fired. And
handing the namespace an ordinary resolver would have fixed that while opening a textbook
exfiltration channel, since DNS tunneling needs nothing more than the ability to resolve
attacker-chosen names.

**The fix**, now ADR-0006: the mediator serves DNS for the namespace and answers every A query with
its own address, then recovers the intended host from the TLS ClientHello's SNI. Verified end to end
— an agent with every proxy variable unset named `evil.example` twice, once in the DNS query and once
in the SNI, both at the mediator. Per-namespace resolver configuration needs no container runtime:
`ip netns exec` already bind-mounts `/etc/netns/<name>/` over `/etc/`.

A detail worth keeping: `SO_ORIGINAL_DST` is not merely unnecessary here, it cannot work. Conntrack
state for a DNAT performed inside the namespace is not visible to a process outside it. SNI sidesteps
the problem instead of fighting it.

**Verified.** Landlock ABI 7 confirmed by direct syscall probe. Three containment proofs. TLS
interception against two hosts. Mediated DNS and SNI recovery against an allowlisted host and a
disallowed one. Full test suite green on the target box under `-race`.

**Next.** The related-work table is the one W0 item still open — every row needs checking against the
actual project before the repo goes public. Then W2, which gained two tasks and two event kinds from
today's finding.

## 2026-08-16 — W1: bundle format, Merkle Mountain Range, verifier

Built the entire cryptographic and format layer, deliberately before touching anything kernel-related.

**Why this order.** W2 and W3 — the launcher and the replayer — are the two highest-variance weeks,
and they are consecutive. Starting there risks a fortnight with nothing to show. The bundle format
has no kernel dependencies, runs identically on Windows and Linux, and is the piece hardest to fake
later: a verifier that catches tampering is either real or it is not. So it went first.

**What landed.**

- `internal/hashchain` — three domain-separated BLAKE3 constructions. The prefix bytes are the
  second-preimage defence RFC 6962 uses for Certificate Transparency, and the tests assert the
  separation directly rather than assuming it.
- `internal/mmr` — flat post-order node array, `TrailingZeros(n)` merges per append, peaks bagged
  right-to-left. Inclusion proofs carry no direction bits: direction is derived from the leaf index
  during verification, so a forger cannot choose them.
- `internal/logfmt` — 16 event kinds with frozen numeric values, canonical CBOR payloads with
  integer keys, and a frame codec that stores the leaf hash alongside the payload.
- `internal/signer` — Ed25519 signed tree heads over a length-prefixed, domain-separated input.
- `internal/bundle` — writer, reader and verifier.
- `internal/runid` — ULIDs, chosen over UUIDv4 so a directory of bundles lists chronologically.
- CLI: `verify`, `inspect`, `prove`, `synth`, `keygen`.

**Two design points worth recording.**

Storing the leaf hash in each frame rather than recomputing it on read looked redundant at first. It
is what lets the verifier distinguish an edited payload from a reordered log: if the stored leaf
disagrees with the recomputed one, those bytes changed; if the leaf agrees but the chain link does
not, the frame is intact but was moved. Two different failures, two different remedies, and a
verifier for an audit tool should say which.

Keeping both a hash chain and an MMR seemed like belt and braces until the crashed-run case came up.
An MMR root only exists once sealed, so a `SIGKILL`ed run would have had no verifiable structure at
all. The chain gives streaming integrity over whatever was written. `hark verify` now reports
`TRUNCATED` with the surviving prefix and exit code 3 — a killed run is a real state, not a failure.

**Bugs found while building.**

`climb` collected sibling hashes top-down while `Verify` derived direction bits bottom-up. Every
proof for a mountain taller than one level would have failed. Caught by writing the exhaustive
round-trip test before trusting the implementation — sampling a few leaf counts would very likely
have missed it, since single-leaf mountains verify fine either way.

First pass at the verifier reported zero events and a zero root when it hit a fault, discarding the
prefix that had verified. Fixed to report how much of the run survived. Related: the fault message
was printed as `seq 9: seq 9: ...` because both `Validate` and the CLI prefixed it. `Validate` no
longer includes the sequence number — the caller has it.

Also: `hark verify -key` printed `VERIFIED` above a line saying the pinned key did not match. Now
`REJECTED`. For a tool whose entire pitch is precise reporting, a headline that contradicts the
detail below it is the worst possible defect.

**Verified.** 47 tests (52 with subtests) across 6 packages, `go vet` clean. End-to-end by hand:
keygen → synth → verify → inspect → prove → prove -check, plus the three negative paths (corrupted
payload, truncated run, pinned-key mismatch) each producing the right output and exit code.

**Next.** W0 groundwork, which W1 jumped ahead of: provision the Linux box, prototype netns + veth +
MITM in throwaway shell before writing any Go for it, and verify the related-work table against the
actual repositories rather than against summaries. Then W2, the launcher.
