#!/usr/bin/env bash
#
# The W6 replay-fidelity suite: N recordings across five agent shapes, each replayed and
# classified. Linux and root, same reason as demo/run.sh -- the containment is real.
#
# Every shape but `incident` is hermetic and lives under fidelity/shapes/. `incident`
# reuses demo/ as-is rather than duplicating it, so there is exactly one copy of the
# prompt-injection scenario in the repo.

set -euo pipefail

cd "$(dirname "$0")"
FIDELITY="$PWD"
ROOT="$(cd .. && pwd)"
WORK="${HARK_FIDELITY_WORK:-/opt/hark-fidelity}"
PY="${PYTHON:-python3}"
N=5

while [ $# -gt 0 ]; do
  case "$1" in
    -n) N="$2"; shift 2 ;;
    *) echo "fidelity: unknown argument $1" >&2; exit 1 ;;
  esac
done

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf 'fidelity: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "hark runs on Linux only"
[ "$(id -u)" = "0" ] || die "run as root: the launcher creates network namespaces"

# A missing kernel feature is an environment limitation, not a usage error -- skip
# visibly rather than fail (internal/launcher's tests take the same posture, and
# docs/testing.md already flagged this suite's CI wiring as unverified going in). Loud
# on purpose: `::warning::` is a GitHub Actions annotation, so a skip still shows up in
# the job summary instead of hiding inside a wall of green.
skip() {
  printf '::warning::fidelity: skipped -- %s\n' "$1"
  exit 0
}
grep -q landlock /sys/kernel/security/lsm 2>/dev/null \
  || skip "landlock not in the active LSM list (docs/troubleshooting.md)"
command -v unshare >/dev/null 2>&1 \
  || skip "unshare not found (needs util-linux)"
unshare --net true 2>/dev/null \
  || skip "cannot create a network namespace in this environment"

RESULTS="$FIDELITY/results.txt"
: > "$RESULTS"

record() {
  # shape, run index, status, detail -- one line per (shape, run) pair, appended as it
  # happens rather than held in memory, so a crash partway through still leaves a
  # readable partial report.
  printf '%-10s run=%-3s %-14s %s\n' "$1" "$2" "$3" "$4" >> "$RESULTS"
}

say "building hark"
( cd "$ROOT" && go build -o "$FIDELITY/hark" ./cmd/hark )
HARK="$FIDELITY/hark"

say "staging at $WORK"
mkdir -p "$WORK"
cp "$HARK" "$WORK/hark"
rm -rf "$WORK/shim" && cp -r "$ROOT/shim" "$WORK/shim"
chmod -R a+rX "$WORK"
HARK="$WORK/hark"

if [ ! -f "$FIDELITY/fidelity.pem" ]; then
  say "minting the fidelity suite's stub certificate"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$FIDELITY/fidelity.key" -out "$FIDELITY/fidelity.pem" \
    -subj "/CN=hark fidelity stub" \
    -addext "subjectAltName=DNS:stream.example,DNS:retry.example,DNS:repeat.example,DNS:mcp.example" \
    2>/dev/null
fi
cp "$FIDELITY/fidelity.pem" "$FIDELITY/fidelity.key" "$WORK/"
chmod a+r "$WORK/fidelity.pem" "$WORK/fidelity.key"
CERT="$WORK/fidelity.pem"
CERTKEY="$WORK/fidelity.key"

wait_for_port() {
  host="$1"; port="$2"
  for attempt in $(seq 1 100); do
    if "$PY" -c 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 0.2).close()' \
        "$host" "$port" 2>/dev/null; then
      return 0
    fi
    [ "$attempt" -lt 100 ] || die "stub on $host:$port never started listening"
    sleep 0.1
  done
}

# classify_replay reads `hark replay`'s output on stdin and prints one word:
# REPLAY-EQUAL, DIVERGED (with the first differing action), or UNKNOWN.
classify_replay() {
  out="$(cat)"
  if printf '%s' "$out" | grep -q '^REPLAY-EQUAL'; then
    echo "REPLAY-EQUAL"
  elif printf '%s' "$out" | grep -q 'REPLAY-DIVERGED'; then
    printf '%s\n' "$out" | grep 'REPLAY-DIVERGED' | head -1
  else
    echo "UNKNOWN: $(printf '%s' "$out" | tail -1)"
  fi
}

# --- the four hermetic shapes ------------------------------------------------------

run_generic_shape() {
  shape="$1" hostname="$2" port="$3"
  dir="$WORK/$shape"
  mkdir -p "$dir"
  cp "$FIDELITY/shapes/$shape/agent.py" "$FIDELITY/shapes/$shape/stub.py" "$FIDELITY/shapes/$shape/policy.toml" "$dir/"
  chmod -R a+rX "$dir"

  say "shape: $shape"

  for i in $(seq 1 "$N"); do
    # A fresh stub process per iteration, not one shared across all N: the retry shape's
    # stub carries state (has it failed once yet?), and a shared process across runs
    # means only the first iteration ever exercises the retry path -- found by the event
    # count differing between run 1 and runs 2-5 the first time this suite ran for real.
    # Every shape gets the same isolation, on the principle that N independent recordings
    # should not be able to see each other's side effects.
    "$PY" "$dir/stub.py" "127.0.0.1:$port" "$CERT" "$CERTKEY" >"$dir/stub-$i.log" 2>&1 &
    stub_pid=$!
    trap 'kill '"$stub_pid"' 2>/dev/null || true' RETURN
    wait_for_port 127.0.0.1 "$port"

    bundle="$dir/run-$i.hark"
    ok=1
    "$HARK" run -policy "$dir/policy.toml" -o "$bundle" -workdir "$dir" \
        -upstream "$hostname=127.0.0.1:$port" -upstream-ca "$CERT" \
        -- "$PY" -u "$dir/agent.py" >"$dir/run-$i.log" 2>&1 || ok=0

    kill "$stub_pid" 2>/dev/null || true
    wait "$stub_pid" 2>/dev/null || true  # let the port free before the next iteration rebinds it

    if [ "$ok" = 0 ]; then
      record "$shape" "$i" "AGENT-FAILED" "see $dir/run-$i.log"
      continue
    fi
    if [ ! -f "$bundle" ]; then
      record "$shape" "$i" "NO-BUNDLE" "hark run exited but wrote nothing"
      continue
    fi
    result="$("$HARK" replay "$bundle" 2>&1 | classify_replay)"
    record "$shape" "$i" "$(echo "$result" | cut -d' ' -f1 | tr -d ':')" "$result"
  done

  kill "$stub_pid" 2>/dev/null || true
  trap - RETURN
}

run_generic_shape streaming stream.example 8444
run_generic_shape retry     retry.example  8445
run_generic_shape repeat    repeat.example 8446
run_generic_shape mcp       mcp.example    8447

# --- incident: reuses demo/ rather than duplicating it -----------------------------

say "shape: incident"
# demo/policy.toml hardcodes read_paths=["/opt/hark-demo"] -- reusing demo/ as-is (rather
# than a modified copy) means staging where that policy already grants access, the same
# path demo/run.sh itself uses.
dir="${HARK_DEMO_WORK:-/opt/hark-demo}"
mkdir -p "$dir"
cp "$ROOT/demo/agent.py" "$dir/agent.py"
chmod -R a+rX "$dir"

if [ ! -f "$ROOT/demo/stub.pem" ]; then
  ( cd "$ROOT/demo" && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout stub.key -out stub.pem -subj "/CN=hark demo stub" \
      -addext "subjectAltName=DNS:docs.example,DNS:model.example" 2>/dev/null )
fi

"$PY" "$ROOT/demo/stub.py" "127.0.0.1:8443" >"$dir/stub.log" 2>&1 &
stub_pid=$!
trap 'kill '"$stub_pid"' 2>/dev/null || true' EXIT
wait_for_port 127.0.0.1 8443

for i in $(seq 1 "$N"); do
  bundle="$dir/run-$i.hark"
  # Unlike the four hermetic shapes, a non-zero exit here is the expected outcome, not a
  # failure: the agent's exfiltration attempt is denied at the boundary, so it fails by
  # design (demo/run.sh does the same `|| true`). Only a missing bundle is a real problem.
  MODEL_API_KEY="fidelity-not-a-real-key" "$HARK" run -policy "$ROOT/demo/policy.toml" \
      -o "$bundle" -workdir "$dir" \
      -upstream "docs.example=127.0.0.1:8443" -upstream "model.example=127.0.0.1:8443" \
      -upstream-ca "$ROOT/demo/stub.pem" \
      -- "$PY" -u "$dir/agent.py" >"$dir/run-$i.log" 2>&1 || true
  if [ ! -f "$bundle" ]; then
    record "incident" "$i" "NO-BUNDLE" "hark run exited but wrote nothing"
    continue
  fi
  result="$("$HARK" replay "$bundle" 2>&1 | classify_replay)"
  record "incident" "$i" "$(echo "$result" | cut -d' ' -f1 | tr -d ':')" "$result"
done

kill "$stub_pid" 2>/dev/null || true
trap - EXIT

# --- report --------------------------------------------------------------------------

say "results"
cat "$RESULTS"

total=$(wc -l < "$RESULTS")
equal=$(grep -c 'REPLAY-EQUAL' "$RESULTS" || true)
printf '\n%s/%s runs replay-equal across %s shapes\n' "$equal" "$total" 5
if [ "$equal" != "$total" ]; then
  printf 'not all runs matched -- see %s for which, and why\n' "$RESULTS"
  exit 1
fi
