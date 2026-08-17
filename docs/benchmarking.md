# Benchmarking

Methodology first. No number appears in the README until the way it was produced is written down
here, because a number without its methodology is not evidence.

**Status: measured on the target box, 2026-08-17.** Every figure below was produced by the command
printed above it, on the machine described next to it. Anything not measured says so rather than
carrying a plausible-looking placeholder.

## The box these numbers come from

| | |
| --- | --- |
| CPU | AMD EPYC 7763, 2 vCPU — **shared**, Azure B-series |
| Kernel | 6.17.0-1022-azure, Ubuntu 24.04 |
| Go | 1.23.5 |
| Otherwise idle | yes |

A shared vCPU has noisy neighbours. Treat every figure here as an order of magnitude with a shape,
not as a specification.

## Environment to report with every number

- CPU model, core count, and whether the instance is shared or dedicated vCPU
- Kernel version and distribution
- Go version
- Whether the box was otherwise idle
- Instance type, if cloud

Shared-vCPU cloud instances have noisy neighbours. Any number from one is reported as a range across
runs, never as a single figure.

## Method

- `go test -bench` with `-benchtime` set so each measurement runs at least 10 seconds.
- Discard the first run entirely; report the median of the next five with min and max.
- p50 and p99 for anything latency-shaped. A mean latency for a proxy hides exactly the behaviour
  that matters.
- Never benchmark against a live model endpoint. Upstream latency varies by orders of magnitude with
  load and would swamp the thing being measured. Use a local stub for overhead measurements, and
  measure real end-to-end runs separately and label them as such.
- Run on Linux. Go's monotonic clock on Windows advances in millisecond steps, so sub-millisecond
  samples read as zero and every percentile derived from them is noise. A p50 of 0 against a mean of
  100µs is the signature of that mistake.

## How to run them

```sh
# 1. mediated-call overhead: direct, mediated and replayed, p50 and p99
go test ./internal/mediator -bench Call -benchtime 10s -run '^$'

# 2. replay wall time against the original run          (Linux, root)
sudo ./bench/replay-ratio.sh

# 3, 4. log size per 1,000 events, verify and proof cost at 100k
go test ./internal/bundle -bench . -benchtime 10x -run '^$' -v
```

## The five benchmarks

**1. Mediated-call overhead — p50 and p99 versus direct.**
`BenchmarkDirectCall`, `BenchmarkMediatedCall` and `BenchmarkPlaybackCall` in `internal/mediator`.
All three drive the same client shape against the same local stub, so the difference between them is
the mediator and nothing else. Read the delta, never either figure alone: the absolute numbers are
dominated by whatever the machine's TLS handshake costs.

Target under 5 ms added. Context matters more than the number: 5 ms against a 900 ms model call is
invisible, and the README should say so rather than presenting the figure alone.

| | p50 | p99 | mean |
| --- | --- | --- | --- |
| direct to the stub | 57 µs | 172 µs | 70 µs |
| through the mediator | 237 µs | 448 µs | 267 µs |
| replayed from a bundle | 140 µs | 276 µs | 162 µs |

**Mediation costs about 0.18 ms at p50 and 0.28 ms at p99**, against a target of 5 ms. Put beside a
model call of several hundred milliseconds it is not measurable by a user, and quoting it without
that context would make it sound like a finding.

Two things the table says that the headline does not. Playback is *faster* than dialling a stub on
loopback, which is the smallest possible version of the reason replay is fast at all: it does not
talk to anything. And the tail is roughly twice the median in all three rows, which is the shared
vCPU rather than the mediator.

**2. Replay wall time versus the original run.** *The headline number.*
`bench/replay-ratio.sh`. It records the demo agent against the stub with `HARK_STUB_DELAY=0.9`, then
replays it, five times each after a discarded warm-up.

The delay is the honest part. Replay's whole advantage is that it does not wait on a model, so
measuring it against a stub that answers instantly would understate the figure most likely to be
quoted — there would be no latency to skip. 0.9s per completion is the order of magnitude of a real
call.

31 events, one completion delayed by 0.9 s:

| | median | slowest |
| --- | --- | --- |
| recorded run | 1052 ms | 1054 ms |
| replayed run | 145 ms | 147 ms |
| **ratio** | **7.3x** | **7.2x** |

The ratio is the least interesting part of this table and the most likely to be quoted, so: **it is
not a constant, and this run understates it.** Replay's saving is exactly the upstream latency it
does not wait for, and this recording contains one 0.9 s call. An agent making thirty of them saves
thirty times as much, while the replay's own cost barely moves.

That cost is the number worth carrying: **about 145 ms of floor**, nearly all of it namespace setup
and interpreter start, and almost none of it hark's own work — the whole 31-event bundle verifies in
under a millisecond. So the honest form of the claim is not "7x" but: *a replay costs what starting
the agent costs, and nothing else.*

**3. Log size per 1,000 events**, raw and compressed, broken down by event kind. `BenchmarkLogSize`
in `internal/bundle`, over a bundle shaped like a real run: eight response chunks per exchange, which
is what dominates in practice.

Compression is measured with `compress/gzip` rather than zstd. Adding a compression dependency to
produce one number is a poor trade, and the shape of the answer is the same either way — response
chunks dominate, and they compress well. zstd would be modestly better on both size and speed.

For a synthetic run of 1,000 events with 512-byte chunks, eight chunks per exchange:

| | per 1,000 events |
| --- | --- |
| raw | 518 KB |
| gzipped | 79 KB (6.5x) |
| response chunks | 97.8% of payload bytes |
| requests | 1.9% |
| response ends | 0.3% |

The breakdown is the useful part and it is not a surprise: a bundle is mostly the model's output.
Size therefore tracks how much the model says, not how much hark records around it — the framing,
the policy decisions and the egress records together are under a fiftieth of the file.

**4. Verification and proof cost at scale.** `BenchmarkVerifyAtScale` and `BenchmarkProveAtScale`,
100,000 events. The contrast is the point: an inclusion proof is 14 hashes and 448 bytes for a
1,000-event bundle, against re-reading the whole log — and shipping the bundle to prove one line of
it would also disclose the entire run to whoever you are trying to convince.

| | 100,000 events (~52 MB) |
| --- | --- |
| full verify | 276 ms (188 MB/s) |
| inclusion proof for one event | 164 ms to produce |
| proof size | 448 bytes, 14 hashes (at 1,000 events) |

Verification is I/O-bound rather than hash-bound at this size, which is the answer you want: the
cost of checking a run is the cost of reading it once.

Producing a proof currently costs a full pass too, because the MMR is recomputed from the frames
rather than stored — a deliberate trade, documented in `internal/bundle`, that saves roughly 2N
interior nodes in every bundle for an operation that runs far less often than verification. Checking
a proof, which is the part a third party does, needs neither the bundle nor the tree.

**5. Replay fidelity.**
Not a performance number, but it belongs in the same document because it is the project's central
empirical claim. N recorded runs across M agent shapes; report the percentage that replay equal,
**with the failures enumerated and explained**. This is W6 work and nothing is claimed for it yet.

Never round this to 100%. A determinism tool that claims perfection invites someone to find the
counterexample publicly, and there will be one — cert-pinned clients, in-process races, and
unkeyable requests all exist. Publishing the failure modes first is both more honest and more
defensible.

## What is not benchmarked

Namespace and Landlock setup cost. It happens once per run, is dwarfed by process startup, and
optimising it would be effort spent where no user is waiting.
