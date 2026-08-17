# Benchmarking

Methodology first. No number appears in the README until the way it was produced is written down
here, because a number without its methodology is not evidence.

**Status: the harnesses exist and are reproducible; the published figures are the ones below, each
labelled with the machine that produced it.** Anything not filled in has not been measured, and says
so rather than carrying a plausible-looking placeholder.

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

| | p50 | p99 |
| --- | --- | --- |
| direct to the stub | *not yet measured on the target box* | |
| through the mediator | | |
| replayed from a bundle | | |

**2. Replay wall time versus the original run.** *The headline number.*
`bench/replay-ratio.sh`. It records the demo agent against the stub with `HARK_STUB_DELAY=0.9`, then
replays it, five times each after a discarded warm-up.

The delay is the honest part. Replay's whole advantage is that it does not wait on a model, so
measuring it against a stub that answers instantly would understate the figure most likely to be
quoted — there would be no latency to skip. 0.9s per completion is the order of magnitude of a real
call.

| | median | slowest |
| --- | --- | --- |
| recorded run | *not yet measured on the target box* | |
| replayed run | | |
| ratio | | |

**3. Log size per 1,000 events**, raw and compressed, broken down by event kind. `BenchmarkLogSize`
in `internal/bundle`, over a bundle shaped like a real run: eight response chunks per exchange, which
is what dominates in practice.

Compression is measured with `compress/gzip` rather than zstd. Adding a compression dependency to
produce one number is a poor trade, and the shape of the answer is the same either way — response
chunks dominate, and they compress well. zstd would be modestly better on both size and speed.

Measured on the development machine (Windows, i5-11300H), for a synthetic run of 1,000 events with
512-byte chunks:

| | per 1,000 events |
| --- | --- |
| raw | 518 KB |
| gzipped | 79 KB |
| response chunks | 97.8% of payload bytes |

Those are development-machine figures and depend entirely on chunk size; they are here to show the
breakdown, not as a performance claim.

**4. Verification and proof cost at scale.** `BenchmarkVerifyAtScale` and `BenchmarkProveAtScale`,
100,000 events. The contrast is the point: an inclusion proof is 14 hashes and 448 bytes for a
1,000-event bundle, against re-reading the whole log — and shipping the bundle to prove one line of
it would also disclose the entire run to whoever you are trying to convince.

Development machine, 100k events (~52 MB): verify 223 ms, ~232 MB/s. To be re-measured on the target
box before the README quotes it.

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
