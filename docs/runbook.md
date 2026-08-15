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
an edited payload from a spliced or reordered log. Note that a local check cannot detect an operator
who rewrote and re-signed the entire run; that requires the transparency anchor, and its absence is
reported explicitly.

*Trigger: expand this into a real runbook if a hosted trace viewer, a bundle store, or any long-lived
process ships — see [roadmap.md](roadmap.md).*
