# Runbook

`hark` is a command-line tool, not a service. There is nothing deployed, nothing to roll back, and
no on-call surface.

What exists today:

**Recovering from a killed run.** A bundle without a footer is expected, not broken. `hark verify`
reports `TRUNCATED`, prints the surviving event count and root, and exits 3. The events that made it
to disk are as trustworthy as they would have been in a sealed bundle — there is simply no signed
root over them. Nothing needs repairing; the file is already in its correct final state.

**Losing the signing key.** New bundles can no longer be sealed with that identity. Existing bundles
remain verifiable, because the public key travels inside each one. Generate a new key with
`hark keygen` and re-pin it wherever the old one was pinned. There is no rotation or revocation
mechanism yet.

**Suspecting a bundle was altered.** `hark verify` names the first faulting event and distinguishes
an edited payload from a spliced or reordered log. A local check cannot detect an operator who
rewrote and re-signed the entire run; that requires the transparency anchor, and its absence is
reported explicitly.

**The transparency log is unreachable.** Sealing is unaffected: `hark run -anchor` prints why it
could not anchor and seals the bundle anyway, because a log that is down must never mean a run cannot
be recorded. On the verifying side the distinction is deliberate — a log that cannot be reached
leaves the exit code alone and says so on the transparency line, while a log that answers and holds
no such entry is a failed claim and exits 1. `hark verify -offline` skips the question entirely.

**A fork that will not branch.** Three refusals, and they mean different things. `FORK-DIVERGED` says
the re-executed prefix stopped matching the recording at the named action — usually the agent, its
interpreter or a dependency changed since the run. `FORK-INCOMPLETE` says the run ended before
reaching the branch point. `FORK-UNPATCHED` says the branch point was reached but no request
followed, so the patch never applied; the run happened, but it is not the counterfactual it would
otherwise claim to be. In all three cases the partial bundle is left on disk and named.

*Trigger: expand this into a real runbook if a hosted trace viewer, a bundle store, or any long-lived
process ships — see [roadmap.md](roadmap.md).*
