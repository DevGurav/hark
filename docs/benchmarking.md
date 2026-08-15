# Benchmarking

Methodology first. No number appears in the README until the way it was produced is written down
here, because a number without its methodology is not evidence.

**Status: no published numbers yet.** The recorder does not exist, so four of the five benchmarks
below cannot run. `internal/mmr` carries `BenchmarkAdd` and `BenchmarkProve` as microbenchmarks; they
are not performance claims.

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

## The five benchmarks

**1. Mediated-call overhead — p50 and p99 versus direct.**
Target under 5 ms added. Context matters more than the number: 5 ms against a 900 ms model call is
invisible, and the README should say so rather than presenting the figure alone.

**2. Replay wall time versus the original run.** *The headline number.*
Replay does not wait on a model, so a four-minute run should replay in seconds. Report the ratio, the
absolute times, and the event count. This is the figure most likely to be quoted, so it is also the
one most worth being conservative about — report the slowest of the five runs alongside the median.

**3. Log size per 1,000 events**, raw and zstd-compressed, broken down by event kind. Response chunks
will dominate; showing that breakdown is more useful than a single total.

**4. Verification and proof cost at scale.**
Full-bundle verify time for 100k events, and inclusion-proof size and verify time for one event in
that bundle. The contrast is the point: roughly 17 hashes and a few hundred bytes, against
re-reading the whole log.

**5. Replay fidelity.**
Not a performance number, but it belongs in the same document because it is the project's central
empirical claim. N recorded runs across M agent shapes; report the percentage that replay equal,
**with the failures enumerated and explained**.

Never round this to 100%. A determinism tool that claims perfection invites someone to find the
counterexample publicly, and there will be one — cert-pinned clients, in-process races, and
unkeyable requests all exist. Publishing the failure modes first is both more honest and more
defensible.

## What is not benchmarked

Namespace and Landlock setup cost. It happens once per run, is dwarfed by process startup, and
optimising it would be effort spent where no user is waiting.
