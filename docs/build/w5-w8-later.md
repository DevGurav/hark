# W5–W8 — after v0.1

Deliberately lighter than the earlier specs. These weeks overlap with interviews, and detailed plans
written now would be stale by the time they are read. Each section states its goal and its traps;
the task breakdown gets written at the start of that week, when what v0.1 actually taught is known.

**Everything here is upside.** v0.1 at W4 is the commitment.

---

## W5 — a real workload

**Goal.** Record UrbanHeat's LangGraph agents with **zero code changes**, proving the framework
independence that has so far only been claimed.

The entire integration should be three environment variables: `HTTPS_PROXY`, the CA bundle, and
`PYTHONPATH`. If it needs more, that is the finding, and it is worth writing up either way.

UrbanHeat is a good first target for two specific reasons:

- `backend/agents/llm.py` retries with backoff on 429, which exercises "same logical call, multiple
  HTTP requests" — the case that breaks naive recorders.
- `backend/agents/supervisor.py` has a `TTLCache` in front of the model, so a recorded run contains
  both cache hits and misses. That interleaving is what makes request keying interesting rather than
  trivial.

Also this week: chunk-granular SSE record and replay, and recording an MCP server behind the proxy.

**Trap.** Resist changing UrbanHeat to make it record cleanly. The zero-code-change property *is* the
deliverable; patching the target to fit destroys the claim.

---

## W6 — fidelity evidence

**Goal.** Publish the replay-fidelity suite, including its failures.

N recorded runs across M agent shapes; report the percentage that replay equal, with every failure
enumerated and explained. Wire it into CI and put the resulting badge in the README.

**This is the project's central empirical claim, so it is also where dishonesty would be most
damaging.** Never round to 100%. Cert-pinned clients, in-process races and unkeyable requests all
exist, and a tool claiming perfection invites someone to find the counterexample in public. Being the
project that published its own failure modes first is a stronger position than being the one that
got caught.

Prefer "47/47 runs replay-equal across 6 agent shapes; 3 shapes excluded, reasons below" to any
single percentage.

---

## W7 — launch

**Goal.** Show HN, a technical writeup, and the demo video.

Title: *Show HN: Deterministic record and replay for AI agents — with a proof the replay is real.*

Lead with the security incident, never the architecture. Nobody clicks through for a Merkle Mountain
Range; they click through for an agent that tried to steal a key and got stopped, then replayed.

**Trap.** The predictable top comment is "this is just Pipelock / Clawker / Agent VCR". The verified
related-work table answers it, and the post should get ahead of it in its own words: containment is
table stakes now, the combination with provable replay is not. Have the answer ready before posting,
not after.

Second most likely comment: "the model is nondeterministic, so what does replay prove?" The scoping
paragraph in the README answers it, and answering it crisply in the thread is worth more than any
amount of README polish.

---

## W8 — buffer

Respond to what the launch surfaces. Fix the things real users hit.

If the launch went nowhere, that is information rather than failure — the artifact still works as an
interview piece, which was always the primary goal.

---

## Beyond v1.0

Not scheduled. Recorded here so the ideas are not lost and so the roadmap does not quietly grow.

- **eBPF and BPF-LSM** for per-tool-call scoping and for agents that fork non-Python children. The
  v0.3 upgrade path from ADR-0003.
- **`SECCOMP_USER_NOTIF`** with `pidfd_getfd` for address-aware syscall filtering.
- **`hark bisect`** — automated counterfactual search for the minimal injected span that flips a
  plan. The most interesting remaining feature, and the one that most needs fork to be solid first.
- **E2B-compatible API subset** — create, exec, files. The single best adoption lever, since agent
  code already targeting E2B would get recording for free.
- **Porting the launcher to Rust**, once the format and protocol have stopped moving. A bounded piece
  of work at that point, and it closes the one gap in ADR-0001's reasoning.
- **Witness gossip** for non-equivocation against a colluding transparency log.
