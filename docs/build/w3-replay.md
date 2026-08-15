# W3 — replay

**Goal.** `hark run` followed by `hark replay` reports `REPLAY-EQUAL` on an agent that genuinely
calls a model, or names the first event where it diverged.

This is the week that makes the project what it claims to be. Second-highest variance after W2.

## Prerequisites

- W2 complete: runs record, bundles verify, denials appear.
- A model API key with free-tier quota. Recording is paid once; replay is free, which is itself worth
  saying in the README.

## Deliverables

| File | Responsibility |
| --- | --- |
| `internal/mediator/playback.go` | Serve recorded responses instead of calling upstream. |
| `internal/reqkey/reqkey.go` | Canonicalise a request and derive its matching key. |
| `internal/replay/replay.go` | Drive a replayed run and compare roots. |
| `shim/sitecustomize.py` | Record and replay clock, RNG and UUID reads in-process. |
| `cmd/hark/replay.go` | `hark replay`. |

## Interfaces

```go
// internal/reqkey
type Key struct {
    Hash       [32]byte // canonical request hash
    Occurrence uint32   // nth identical request in this run
}

func Canonicalise(method, host, path string, h http.Header, body []byte) []byte
func Derive(canonical []byte, seen map[[32]byte]uint32) Key

// internal/replay
type Outcome struct {
    Equal          bool
    OriginalRoot   hashchain.Hash
    ReplayedRoot   hashchain.Hash
    FirstDivergent int64  // -1 when equal
    Reason         string
}

func Run(ctx context.Context, bundlePath string, out string) (*Outcome, error)
```

## Tasks

### 1. Request canonicalisation

Budget **two full days** for this. It is the task most likely to overrun, and the estimate is not
padding.

- [ ] Strip hop-by-hop and connection-specific headers: `Connection`, `Keep-Alive`,
      `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`.
- [ ] Strip headers that vary per request by nature: `Date`, `User-Agent` version suffixes,
      `X-Request-Id`, tracing headers.
- [ ] Strip the injected credential — the recorded request has the placeholder, the live one has the
      real value, and they must canonicalise identically.
- [ ] Lowercase header names, sort them, and join deterministically with length prefixes so
      `A: bc` and `Ab: c` cannot collide.
- [ ] For JSON bodies, re-serialise canonically: sorted keys, shortest float representation. For
      anything else, hash the bytes.

**Acceptance.** Property test: the same logical request canonicalises identically across 1,000
constructions with randomised header order and randomised map iteration.

### 2. Occurrence ordinals

One run can issue byte-identical requests that received different responses — a retry after a 429 is
the obvious case, and UrbanHeat's `llm.py` does exactly this.

- [ ] Key on `(canonical_hash, occurrence)`, where occurrence counts prior identical requests.
- [ ] On replay, match by key; fall back to strict sequence position.
- [ ] When neither matches, emit a `KeyMismatch` diagnostic and **stop**. Do not guess. A replayer
      that silently serves the wrong response is worse than one that refuses.

**Acceptance.** A test records two identical requests with different responses and confirms replay
returns each in the right order.

### 3. Playback mode

- [ ] The mediator serves from the bundle instead of dialling upstream.
- [ ] Reproduce chunk boundaries exactly — agent code branches on partial parses, so the boundaries
      are themselves a source of nondeterminism.
- [ ] Do **not** reproduce inter-chunk timing by default. Sleeping through a recorded four-minute run
      defeats the point of replay being fast. Put it behind `-realtime` for anyone who wants it.
- [ ] Replay every recorded egress denial as a denial.

**Acceptance.** A replayed run makes zero outbound connections. Verify with `tcpdump` on the host end
of the veth, not by trusting the code.

### 4. Language shim

- [ ] `sitecustomize.py` injected via `PYTHONPATH`, patching `time.time`, `time.monotonic`,
      `random.*`, `uuid.uuid4`, `os.urandom`.
- [ ] Set `PYTHONHASHSEED=0`.
- [ ] Record mode appends `ClockRead` and `RandomRead`; replay mode serves them back in order.
- [ ] Communicate with the supervisor over a unix socket bound into the namespace — not a file in the
      workspace, which the agent could tamper with.

**Acceptance.** A script printing `time.time()` and `random.random()` produces identical output on
replay.

### 5. `hark replay`

- [ ] Re-run the agent with the mediator in playback and the shim in replay.
- [ ] Recompute the chain and Merkle root over the replayed events.
- [ ] Print `REPLAY-EQUAL` with the matching root, or the first divergent sequence number with both
      sides rendered.

**Acceptance.** Record a real agent run, replay it on a **different machine**, and get
`REPLAY-EQUAL`. Then edit one recorded response and confirm the replayer names the right event.

## Traps

**"Bit-exact" cannot mean the model re-emits the same tokens.** Hosted temperature-0 inference is
nondeterministic because kernel numerics depend on server-side batch size. Replay serves what was
recorded; it never re-derives it. Keep the README wording exactly as it is.

**Side-effecting tools must never be re-executed.** Replay serves recorded results only. Forking past
a side-effecting tool requires an explicit `may_reexecute` annotation. This is the rule durable
execution engines apply to non-deterministic activities, and it is not negotiable.

**Concurrency.** The mediator imposes a total order on boundary crossings and replay follows it. It
does **not** capture two threads racing on an in-process dict. Do not pretend otherwise — detect it.
Divergence must surface as a differing root and a named first-divergent event.

**The shim is advisory, the mediator is not.** An agent can delete `sitecustomize.py` from its own
`PYTHONPATH`. Clock and RNG fidelity are therefore best-effort, while network fidelity is enforced.
Say so in `docs/security.md` rather than letting a reader assume both are equally solid.

**Streaming reassembly.** Record chunks as framed on the wire, not as reassembled by the HTTP client.
Once the client has reassembled them the boundary information is gone and cannot be recovered.

## Definition of done

- [ ] Build, vet, gofmt, test, race all green.
- [ ] Replay on a second machine reports `REPLAY-EQUAL`.
- [ ] `tcpdump` confirms zero outbound connections during replay.
- [ ] A tampered recorded response is caught and its event named.
- [ ] `KeyMismatch` stops replay rather than guessing.
- [ ] `docs/build-log.md`, architecture, roadmap, testing, CHANGELOG reconciled.
- [ ] `docs/security.md` states the shim's advisory status explicitly.

## Expected commits

```text
feat(reqkey): canonicalise requests for replay matching
feat(reqkey): disambiguate identical requests by occurrence
feat(mediator): serve recorded responses in playback mode
feat(shim): record and replay clock and RNG reads
feat(cli): add hark replay
docs: record the W3 replay work
```
