# Replay fidelity

The project's central empirical claim: given the same recorded external inputs, a replayed run
reproduces the same sequence of externally-visible actions. This page is the evidence, run for
real on the box (kernel 6.17), not asserted.

**25/25 runs replay-equal across 5 agent shapes.** Zero exclusions, zero rounding — every run
counted, every result below is from an actual `hark run` + `hark replay` pair, not a projection.

| Shape | What it exercises | N | Replay-equal |
| --- | --- | --- | --- |
| `incident` | The W4 scenario: page fetch, model call, a denied exfiltration attempt. | 5 | 5/5 |
| `streaming` | An SSE response delivered as separate chunked-encoding flushes; replay must reproduce the chunk boundaries, not just the concatenated bytes. | 5 | 5/5 |
| `retry` | The same logical call sent twice after a 503, keyed by `(canonical_request_hash, occurrence_ordinal)` — the hermetic form of what W5 found live in UrbanHeat's Gemini traffic. | 5 | 5/5 |
| `repeat` | The identical request sent twice in one run, with no error in between — the plain case the occurrence ordinal exists for. | 5 | 5/5 |
| `mcp` | A JSON-RPC `tools/call` exchange over the same HTTP path ordinary model traffic uses. | 5 | 5/5 |

Each shape is hermetic — a local stub upstream, no network, no API key, no cost
([docs/build/w6-fidelity.md](build/w6-fidelity.md) explains why, having watched W5 hit Gemini's
free-tier rate limit for the reason this suite would not want to inherit). UrbanHeat's live
retry-on-429 and cache-hit evidence ([build-log.md](build-log.md), 2026-08-18) is real and stands
on its own; it is not folded into this N, because a live endpoint's availability is not what this
page is measuring.

## What 25/25 does and does not claim

Twenty-five runs passing twenty-five times is twenty-five runs, not a proof of always. The shapes
here cover request/response, streaming, retry, repetition and one RPC-shaped protocol layered on
HTTP — they do not cover concurrent in-process races, cert-pinned clients (a documented limitation;
see the README), or non-Python agents. A wider fidelity claim needs wider shapes, not a bigger N on
the same five.

## How to reproduce

```sh
cd fidelity
sudo ./run.sh -n 5
```

Linux and root, same reason as `demo/run.sh` — the containment is real, not a wrapper. Results land
in `fidelity/results.txt`, one line per `(shape, run)` pair.

## A defect this suite already found

The first real run of this suite reported `retry` at 22/13/13/13/13 events across five runs instead
of 22 every time — not a replay bug, a fixture bug. `fidelity/run.sh` started one stub process and
reused it across all N iterations of a shape; the retry stub's "have I failed once yet" counter is
process-global, so only the very first iteration ever saw a 503. The other four silently degenerated
into the trivial single-request case while still reporting `REPLAY-EQUAL`, which was true and
uninteresting — replaying a call that never retried proves nothing about retry fidelity.

Fixed by giving every iteration of every shape its own fresh stub process, so N independent
recordings cannot see each other's server-side state. Left here because a replay-equal count that
cannot also catch its own fixture being wrong is not worth much, and this one did.
