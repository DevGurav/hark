# 0008 — A fork is a verified prefix and a live suffix

Status: accepted
Date: 2026-08-17

## Context

`hark fork` answers a counterfactual: *would this agent have exfiltrated the key if the page had not
carried that instruction?* The obvious way to describe such a run is "the same run up to event N,
then a different one" — and the obvious way to oversell it is to imply the whole thing is as
reproducible as a replay.

It is not, and cannot be. Everything after the branch point is a fresh run against a live upstream,
and a model is not reproducible even at temperature zero. There is also no process checkpoint: `hark`
does not snapshot the agent's memory, so a fork cannot resume from event N. It has to re-execute the
agent from the start and arrive there.

That re-execution raises the question this decision exists to answer. If the prefix is re-run rather
than resumed, what makes it *the same* prefix?

## Decision

**A fork replays its prefix and checks it action by action, against the parent's digest, as it
happens. A divergence stops the run.**

The gate is driven by the child's own event stream. Each event the child records is normalised and
folded into the same digest `hark replay` uses, and compared with the parent's step at that index.
The moment they differ, the agent is killed and the output says which action diverged and what both
sides did. Nothing is forked.

Once the child has produced the first N events and every one of them matched, the gate opens: the
recorded response at the branch point is served with the patch applied, and everything after is live
— real dials, real credentials, real clock and randomness.

The output says exactly this and no more:

```text
FORKED  provably identical prefix, live suffix
```

The phrase is fixed. A fork is never described as bit-exact.

## Consequences

- A fork inherits replay's guarantee for its prefix and claims nothing for its suffix. The child
  bundle records `ParentRoot`, `ForkPoint` and `PatchHash`, so the relationship is in the artifact
  rather than in a filename or a memory.
- The parent is verified before the run starts. A fork from a bundle that does not verify proves
  nothing, and discovering that after spending a live run would be the wrong order.
- Three refusals rather than one success and one failure, because a fork that *nearly* happened is
  the case most likely to be misread:
  - `FORK-DIVERGED` — the prefix stopped matching, naming the action and both sides.
  - `FORK-INCOMPLETE` — the run ended before the branch point.
  - `FORK-UNPATCHED` — the branch point was reached, but no request followed it, so the patch never
    applied. The run is not the counterfactual it would otherwise claim to be.
- A patch that matches nothing is an error, not a no-op. The alternative is a fork that runs, comes
  out clean, and lets the operator conclude the change was harmless when it was never made.
- The patched body is served as a single chunk. The recorded chunk boundaries described bytes that
  no longer exist, and redistributing a changed body across them would be an invented framing
  presented with the authority of a recorded one.
- The clock and RNG channel goes live at the branch point, not after the patched exchange. A draw
  between the two belongs to the counterfactual.

## Alternatives considered

**Checkpoint and restore the process at N.** CRIU, or an interpreter-level snapshot. It would make
the prefix a genuine resumption rather than a re-execution, and it would remove the divergence case
entirely. Rejected for v0.1: CRIU is a large dependency with its own kernel requirements, snapshots
are not portable between machines, and the re-execution approach has a property the snapshot lacks —
it *proves* the prefix reproduces, rather than assuming a restored process would have.

**Compare only at the branch point.** Fold the whole prefix, compare once, then go live. Simpler, and
strictly worse: a divergence at action 6 of 400 would still spend the entire prefix before being
noticed, and the report could say only "the prefix differed" rather than naming the action.

**Let the fork continue past a divergence and report it afterwards.** Rejected. The resulting bundle
would carry a `ParentRoot` it has no claim to, and someone would eventually quote it.

**Patch the model's response instead of the page.** Easier to implement and much weaker as evidence:
it patches the conclusion rather than the cause. Forking at the fetch and stripping the injection
asks whether the page was responsible; forking at the completion only asks what happens when the plan
is different, which nobody doubted.
