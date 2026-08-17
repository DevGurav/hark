#!/usr/bin/env bash
#
# The headline number: replay wall time against the original run.
#
# Method, following docs/benchmarking.md:
#
#   * a local stub, never a live endpoint -- upstream latency varies by orders
#     of magnitude and would swamp what is being measured;
#   * the stub delays each completion by HARK_STUB_DELAY seconds, because a
#     stub that answers instantly has no latency for replay to skip and would
#     understate the figure most likely to be quoted;
#   * the first run of each is discarded, then five are measured;
#   * the median and the slowest are both reported. A determinism tool quoting
#     only its best run is quoting the wrong number.
#
# Linux and root. Roughly (5+1) x 2 x (delay x calls) seconds, plus overhead.

set -euo pipefail

cd "$(dirname "$0")"
BENCH="$PWD"
DEMO="$(cd ../demo && pwd)"
ROOT="$(cd .. && pwd)"

RUNS="${HARK_BENCH_RUNS:-5}"
DELAY="${HARK_STUB_DELAY:-0.9}"
STUB_ADDR="${HARK_DEMO_STUB:-127.0.0.1:8443}"
WORK="${HARK_DEMO_WORK:-/opt/hark-demo}"
PY="${PYTHON:-python3}"

die() { printf 'bench: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "hark runs on Linux only"
[ "$(id -u)" = "0" ] || die "run as root: the launcher creates network namespaces"

# Staged exactly as the demo stages it, and for the same reason: the agent runs
# as uid 0 with every capability dropped, so anything it needs has to sit
# somewhere world-traversable rather than in a home directory.
( cd "$ROOT" && go build -o "$WORK/hark" ./cmd/hark )
mkdir -p "$WORK"
cp "$DEMO/agent.py" "$WORK/agent.py"
rm -rf "$WORK/shim" && cp -r "$ROOT/shim" "$WORK/shim"
chmod -R a+rX "$WORK"
HARK="$WORK/hark"

if [ ! -f "$DEMO/stub.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$DEMO/stub.key" -out "$DEMO/stub.pem" -subj "/CN=hark demo stub" \
    -addext "subjectAltName=DNS:docs.example,DNS:model.example" 2>/dev/null
fi

rm -f "$BENCH/bench.hark" "$BENCH/bench-replay.hark"

HARK_STUB_DELAY="$DELAY" "$PY" "$DEMO/stub.py" "$STUB_ADDR" &
STUB_PID=$!
trap 'kill $STUB_PID 2>/dev/null || true' EXIT
sleep 1

UPSTREAM=(-upstream "docs.example=$STUB_ADDR" -upstream "model.example=$STUB_ADDR" -upstream-ca "$DEMO/stub.pem")

# Wall time in milliseconds for one command, output discarded.
elapsed() {
  local start end
  start=$(date +%s%N)
  "$@" >/dev/null 2>&1 || true
  end=$(date +%s%N)
  echo $(( (end - start) / 1000000 ))
}

record_once() {
  rm -f "$BENCH/bench.hark"
  MODEL_API_KEY="bench-not-a-real-key" \
    "$HARK" run -policy "$DEMO/policy.toml" -o "$BENCH/bench.hark" \
      -workdir "$WORK" "${UPSTREAM[@]}" -- "$PY" "$WORK/agent.py"
}

replay_once() {
  # Removed first: a bundle is created with O_EXCL so a run can never overwrite
  # a recording, and a divergent replay leaves its output behind.
  rm -f "$BENCH/bench-replay.hark"
  "$HARK" replay -o "$BENCH/bench-replay.hark" "$BENCH/bench.hark"
}

# A failed run measures nothing, and elapsed() discards output by design, so the
# shape of the recording is checked once before any timing is believed. This
# doubles as the discarded warm-up.
check_once() {
  record_once >"$BENCH/record.log" 2>&1 || true
  if ! "$HARK" verify -offline -quiet "$BENCH/bench.hark"; then
    sed -n "1,20p" "$BENCH/record.log" >&2
    die "the recorded run did not seal; there is nothing to measure"
  fi
  if ! "$HARK" replay -o "$BENCH/bench-replay.hark" "$BENCH/bench.hark" >"$BENCH/replay.log" 2>&1; then
    sed -n "1,20p" "$BENCH/replay.log" >&2
    die "the run does not replay equal; a ratio over a divergent replay is meaningless"
  fi
}

stats() { # median and max of the numbers on stdin
  sort -n | awk '{ v[NR]=$1 } END { printf "%d %d", v[int((NR+1)/2)], v[NR] }'
}

printf 'checking the run records and replays before timing anything\n'
check_once

printf 'recording %s runs (stub delay %ss)\n' "$RUNS" "$DELAY"
rec_times=""
for _ in $(seq 1 "$RUNS"); do
  rec_times="$rec_times$(elapsed record_once)\n"
done

printf 'replaying %s times\n' "$RUNS"
rep_times=""
for _ in $(seq 1 "$RUNS"); do
  rep_times="$rep_times$(elapsed replay_once)\n"
done

read -r rec_med rec_max <<<"$(printf "$rec_times" | stats)"
read -r rep_med rep_max <<<"$(printf "$rep_times" | stats)"
# awk reads to the end: exiting at the first match closes the pipe, verify dies
# of SIGPIPE, and pipefail turns a finished measurement into a failed script.
events="$("$HARK" verify -offline "$BENCH/bench.hark" | awk '/events/ && !seen {print $2; seen=1}')"

cat <<REPORT

replay wall time against the original
  events            $events
  stub delay        ${DELAY}s per completion
  runs measured     $RUNS (first of each discarded)

  record  median ${rec_med}ms   slowest ${rec_max}ms
  replay  median ${rep_med}ms   slowest ${rep_max}ms

  ratio   median $(awk "BEGIN{printf \"%.1f\", $rec_med/$rep_med}")x   worst case $(awk "BEGIN{printf \"%.1f\", $rec_max/$rep_max}")x

Report the environment with these: CPU model and count, whether the vCPU is
shared, kernel, distribution, Go version, and whether the box was idle. On a
shared-vCPU cloud instance, publish the range rather than a single figure.
REPORT

rm -f "$BENCH/bench-replay.hark" "$BENCH/record.log" "$BENCH/replay.log"
