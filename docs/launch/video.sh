#!/usr/bin/env bash
#
# The 90-second video cut, following docs/launch/video-script.md.
#
# Distinct from demo/run.sh in three ways, all in service of the recording:
#   * captions between beats, so the GIF reads without narration
#   * the stub answers with a 0.9s delay -- the same figure docs/benchmarking.md
#     uses -- so the replay speedup on screen is real, not asserted
#   * timing shown for both the recorded run and the replay, side by side
#
# Everything it demonstrates, demo/run.sh already does. This only reframes it.

set -euo pipefail

cd "$(dirname "$0")"
DEMO="$PWD/demo"
ROOT="$PWD"
WORK="/opt/hark-demo"
STUB_ADDR="127.0.0.1:8443"
PY="python3"

# Caption: dim rule, bold text, a beat to read it.
cap() {
  printf '\n\033[2m%s\033[0m\n\033[1;97m  %s\033[0m\n' \
    "────────────────────────────────────────────────────────────" "$*"
  sleep 2.2
}
run() { printf '\033[2m$\033[0m \033[1m%s\033[0m\n' "$*"; }

cd "$ROOT"
go build -o "$DEMO/hark" ./cmd/hark 2>/dev/null

mkdir -p "$WORK"
cp "$DEMO/agent.py" "$WORK/agent.py"
cp "$DEMO/hark" "$WORK/hark"
rm -rf "$WORK/shim" && cp -r "$ROOT/shim" "$WORK/shim"
chmod -R a+rX "$WORK"
HARK="$WORK/hark"

cd "$DEMO"
[ -f stub.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout stub.key -out stub.pem -subj "/CN=hark demo stub" \
  -addext "subjectAltName=DNS:docs.example,DNS:model.example" 2>/dev/null
[ -f demo.key ] || "$HARK" keygen -out demo.key >/dev/null

# 0.9s per completion: the same delay docs/benchmarking.md measures against, so
# the replay comparison later in this recording is the real one.
HARK_STUB_DELAY=0.9 "$PY" stub.py "$STUB_ADDR" 2>/dev/null &
STUB_PID=$!
trap 'kill $STUB_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
  "$PY" -c 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 0.2).close()' \
    "${STUB_ADDR%:*}" "${STUB_ADDR##*:}" 2>/dev/null && break
  sleep 0.1
done

rm -f incident.hark fork.hark incident.hark.html fork.hark.html run-*-replay.hark

UP=(-upstream "docs.example=$STUB_ADDR" -upstream "model.example=$STUB_ADDR" -upstream-ca stub.pem)

clear
cap "An agent fetches a page, asks a model what to do, and does it."
run "hark run -policy policy.toml -- python agent.py"
REC_START=$(date +%s.%N)
MODEL_API_KEY="demo-not-a-real-key-01J8X" \
  "$HARK" run -policy policy.toml -key demo.key -o incident.hark \
    -workdir "$WORK" "${UP[@]}" -- "$PY" -u "$WORK/agent.py" || true
REC_MS=$(awk -v a="$REC_START" -v b="$(date +%s.%N)" 'BEGIN{printf "%.0f", (b-a)*1000}')

cap "The page carried an instruction the agent never asked for."
run "hark inspect incident.hark"
"$HARK" inspect incident.hark

cap "Control one: the connection never left the namespace."
"$HARK" inspect incident.hark | grep -E 'EgressDecision.*DENIED' | sed $'s/.*/\033[1;31m&\033[0m/'
sleep 1.6

cap "Control two: the key it tried to leak was never the real one."
"$HARK" inspect incident.hark | grep -E 'SecretInjected' | head -1 | sed $'s/.*/\033[1;33m&\033[0m/'
sleep 1.6

cap "Chain, root, signature — checked, not asserted."
run "hark verify incident.hark"
"$HARK" verify incident.hark

cap "Now replay it. No network, no credentials, the second time."
run "hark replay incident.hark"
REP_START=$(date +%s.%N)
"$HARK" replay incident.hark
REP_MS=$(awk -v a="$REP_START" -v b="$(date +%s.%N)" 'BEGIN{printf "%.0f", (b-a)*1000}')
printf '\n  \033[1;32mrecorded %s ms  →  replayed %s ms\033[0m\n' "$REC_MS" "$REP_MS"
printf '  \033[2mthe difference is the model call it no longer waits on\033[0m\n'
sleep 2.4

AT="$("$HARK" inspect incident.hark | awk '$2=="LlmRequest" && /docs.example/ && !seen {print $1; seen=1}')"

cap "Fork at the page fetch, with the injected paragraph stripped."
run "hark fork -at $AT -patch strip-injection.json incident.hark"
MODEL_API_KEY="demo-not-a-real-key-01J8X" \
  "$HARK" fork -at "$AT" -patch strip-injection.json -key demo.key -o fork.hark "${UP[@]}" incident.hark

cap "Same prefix, verified action by action. Live from there — and nothing tried to leave."
run "hark inspect fork.hark | grep EgressDecision"
"$HARK" inspect fork.hark | grep -E 'EgressDecision' || true
sleep 1.8

cap "One HTML file. Opens with the network off."
run "hark report -offline incident.hark"
"$HARK" report -offline incident.hark

printf '\n\033[2m%s\033[0m\n' "────────────────────────────────────────────────────────────"
printf '\033[1;97m  hark\033[0m — deterministic record and replay for AI agents,\n'
printf '  with a proof the replay is real.\n\n'
printf '  \033[1mhark run\033[0m · \033[1mhark replay\033[0m · \033[1mhark fork\033[0m\n'
printf '  \033[2mgithub.com/DevGurav/hark\033[0m\n\n'
sleep 3
