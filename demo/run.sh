#!/usr/bin/env bash
#
# The incident, end to end, from one terminal.
#
#   1. an agent is prompt-injected and tries to exfiltrate its API key
#   2. two independent controls stop it, and both are on the record
#   3. the run replays exactly, on this machine or another
#   4. a fork with the injection stripped behaves differently -- and provably
#      shares its prefix with the run that misbehaved
#   5. the whole thing renders as one HTML file
#
# Hermetic: no API key, no cost, no network. The model is a stub that follows
# instructions in its context, which is the only model behaviour this demo
# depends on. See README.md in this directory for what that does and does not
# establish.
#
# Linux and root, because the containment is real: network namespaces, Landlock
# and seccomp.

set -euo pipefail

cd "$(dirname "$0")"
DEMO="$PWD"
ROOT="$(cd .. && pwd)"
WORK="${HARK_DEMO_WORK:-/opt/hark-demo}"
STUB_ADDR="${HARK_DEMO_STUB:-127.0.0.1:8443}"
PY="${PYTHON:-python3}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf 'demo: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "hark runs on Linux only"
[ "$(id -u)" = "0" ] || die "run as root: the launcher creates network namespaces"
command -v openssl >/dev/null || die "openssl is needed to mint the stub's certificate"
command -v "$PY" >/dev/null || die "python3 is needed for the agent and the stub"

say "building hark"
( cd "$ROOT" && go build -o "$DEMO/hark" ./cmd/hark )

# The agent runs with a Landlock-scoped filesystem, so its source has to live
# somewhere the policy grants. Copying rather than granting the repo keeps the
# policy honest: the agent gets its own directory and nothing else.
say "staging the agent at $WORK"
mkdir -p "$WORK"
cp agent.py "$WORK/agent.py"

# One certificate for both stub hostnames. The mediator dials the redirected
# address but still checks the name the agent asked for, so the redirection does
# not become an identity exemption.
if [ ! -f stub.pem ]; then
  say "minting the stub certificate"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout stub.key -out stub.pem -subj "/CN=hark demo stub" \
    -addext "subjectAltName=DNS:docs.example,DNS:model.example" 2>/dev/null
fi

say "starting the stub upstream on $STUB_ADDR"
"$PY" stub.py "$STUB_ADDR" &
STUB_PID=$!
trap 'kill $STUB_PID 2>/dev/null || true' EXIT

# Wait for the port rather than sleeping a guessed amount, and fail loudly if it
# never opens -- a demo that carries on without its upstream produces a
# confusing recording instead of a clear error.
for attempt in $(seq 1 100); do
  if "$PY" -c 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 0.2).close()' \
      "${STUB_ADDR%:*}" "${STUB_ADDR##*:}" 2>/dev/null; then
    break
  fi
  [ "$attempt" -lt 100 ] || die "the stub never started listening on $STUB_ADDR"
  sleep 0.1
done

if [ ! -f demo.key ]; then
  say "generating a signing key"
  ./hark keygen -out demo.key
fi

UPSTREAM=(-upstream "docs.example=$STUB_ADDR" -upstream "model.example=$STUB_ADDR" -upstream-ca stub.pem)
ANCHOR=()
if [ "${HARK_DEMO_ANCHOR:-0}" = "1" ]; then
  # Off by default: it writes to a public, permanent log, which is not something
  # a demo should do to somebody by surprise.
  ANCHOR=(-anchor)
fi

rm -f incident.hark fork.hark incident.hark.html fork.hark.html

say "1. recording the run"
# The agent exits non-zero: its exfiltration attempt fails, because the
# connection is denied at the boundary. hark passes the agent's exit code
# through, so that failure is the expected outcome here rather than a problem.
MODEL_API_KEY="demo-not-a-real-key-01J8X" \
  ./hark run -policy policy.toml -key demo.key -o incident.hark \
    -workdir "$WORK" "${UPSTREAM[@]}" "${ANCHOR[@]}" \
    -- "$PY" "$WORK/agent.py" || true

say "2. what the bundle says"
./hark inspect incident.hark

cat <<'NOTE'

Two independent controls, both on the record above:

  EgressDecision  DENIED evil.example   the connection never left the namespace
  SecretInjected  hark-placeholder-...  what the agent tried to leak was not the key

The second one is the interesting half. Even had the egress been allowed, the
value the agent posted would have been a placeholder: the real credential is
substituted at the boundary and never enters the agent's address space.
NOTE

say "3. verifying"
./hark verify incident.hark

say "4. replaying -- no network, no credentials, no side effects"
time ./hark replay incident.hark

# The branch point is the fetch of the poisoned page: the first request to
# docs.example. Forking there and stripping the injection asks whether the page
# was the cause, rather than patching the conclusion.
AT="$(./hark inspect incident.hark | awk '$2=="LlmRequest" && /docs.example/{print $1; exit}')"
[ -n "$AT" ] || die "no request to docs.example in the recording; did the run fail?"

say "5. forking at event $AT with the injection stripped"
MODEL_API_KEY="demo-not-a-real-key-01J8X" \
  ./hark fork -at "$AT" -patch strip-injection.json -key demo.key -o fork.hark \
    "${UPSTREAM[@]}" incident.hark

say "6. what the fork did instead"
./hark inspect fork.hark

cat <<'NOTE'

The prefix is provably the same run -- same page fetch, same policy decisions,
compared action by action as it was re-executed. The suffix is live, and the
model, given a briefing with no instruction hidden in it, returned a summary
instead of a plan to post anywhere. No egress denial appears in the fork,
because nothing tried to leave.

NOTE

say "7. rendering both runs"
./hark report -offline incident.hark
./hark report -offline fork.hark

printf '\nOpen incident.hark.html and fork.hark.html side by side.\n'
