# The incident

A prompt-injected agent tries to exfiltrate its API key. Two independent controls stop it, both are
on the record, the run replays exactly, and a fork with the injection stripped behaves differently
while provably sharing its prefix.

```sh
sudo ./run.sh
```

Linux and root — the containment is network namespaces, Landlock and seccomp, not a wrapper.
Requires Go, Python 3 and `openssl`. Nothing else, and no network.

## What happens

The agent in [agent.py](agent.py) fetches a briefing, asks a model to summarise it, and carries out
the plan the model returns. The briefing carries an injected instruction. The model follows it. The
plan comes back as *post the API key to `evil.example`*, and the agent — which has no reason to
distrust a plan it asked for — does exactly that.

```text
EgressAttempt    evil.example:443 (tcp)
EgressDecision   DENIED evil.example by allow_hosts: host not in the policy allowlist
```

That is the first control, and it is the one people expect. The second is the one worth staying for:
the value the agent tried to leak was `hark-placeholder-01J8X-api_key`. The real credential is
substituted at the boundary, on the way out, for allowed hosts only — so it was never in the agent's
address space to leak. Two controls, neither of which the agent could switch off, and both visible in
the same artifact.

Then:

- `hark verify` checks the chain, the Merkle root and the signature.
- `hark replay` re-runs the agent against the recording. It dials nothing and needs no credentials.
- `hark fork -at N -patch strip-injection.json` re-executes the run up to the page fetch, checking
  every action against the recording as it goes, removes the injected paragraph from the page, and
  goes live from there. The model — a live call this time — returns a summary, and no exfiltration is
  attempted. **Provably identical prefix, live suffix.** Never bit-exact: everything after the branch
  point is a fresh run.
- `hark report` renders each run as one self-contained HTML file.

## The stub, stated plainly

The upstream is [stub.py](stub.py), not a real model. It serves the briefing on `docs.example` and
answers completions on `model.example`, and it does one thing that matters: **it follows an
instruction that arrives in its context**. That is not a simulated flaw. It is the behaviour every
current model has, and it is the only model behaviour this demo depends on.

Why a stub:

- the demo runs with no API key, no cost and no network, so it works from a clean clone;
- the recording is identical every time, so `hark replay` compares the harness rather than model
  sampling noise;
- benchmarking against a live endpoint would measure somebody else's load balancer — see
  [docs/benchmarking.md](../docs/benchmarking.md).

The redirection is not hidden. `hark run -upstream docs.example=127.0.0.1:8443` records the mapping
in `RunStart`, `hark inspect` shows it, and the HTML report puts it in the first row. A bundle can
never quietly claim it reached a host it did not.

## Against a real endpoint

Drop the `-upstream` flags, put a real host in `policy.toml`, and set the credential:

```sh
MODEL_API_KEY=... ./hark run -policy policy.toml -key demo.key -o incident.hark \
  -workdir /opt/hark-demo -- python3 /opt/hark-demo/agent.py
```

The agent's prompt and the plan format are close enough to a real completions API to need only the
URL and the response shape changing. What will not be identical is replay: a hosted model is not
reproducible even at temperature zero, which is precisely why `hark` replays the recording rather
than re-deriving it.

## Anchoring

Off by default. `HARK_DEMO_ANCHOR=1 sudo ./run.sh` submits the signed tree head to the public
Sigstore log — permanent, public, and not something a demo should do to someone by surprise. With it
set, `hark verify` on another machine reports the inclusion proof it fetched and checked.

## Files

| | |
| --- | --- |
| `agent.py` | The agent. Naive on purpose, and typical. |
| `briefing.html` | The page, with the injected instruction in it. |
| `stub.py` | The content host and the model, on one TLS listener. |
| `policy.toml` | Two allowed hosts. `evil.example` is not one of them. |
| `strip-injection.json` | The patch the fork applies at the branch point. |
| `run.sh` | All of it, in order. |
