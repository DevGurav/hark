# 0004 — A transparency log, not operator-signed receipts

Status: accepted
Date: 2026-08-16

## Context

Several agent-audit tools sign their evidence with the operator's own key and treat that as the
integrity story. It is a reasonable-looking design and it does not hold up.

The threat that matters for an audit log is not an outsider editing the file in transit. It is the
operator who produced the log deciding, later, that a particular run should have gone differently.

## Decision

Signed tree heads are necessary but are explicitly not the security claim. `hark` anchors the root
in a public transparency log (Sigstore Rekor) and reports the anchor as a separate, visible line in
`hark verify`. An unanchored bundle says so:

```
transparency  not anchored -- integrity only, no non-equivocation
```

## Consequences

- The verifier makes a distinction most tools in this space collapse. A valid signature over a
  matching root proves the bundle is internally consistent and that *someone holding that key*
  vouched for it. It does not establish that this is the only bundle the operator produced for this
  run. Those are different claims and they are reported on different lines.
- The public key travels inside the bundle it authenticates, which by itself is circular. `hark
  verify -key <hex>` exists so a caller can pin the key they expect; `keygen` prints the reminder.
  Without pinning, the signature check says almost nothing.
- An inclusion proof against a published signed tree head, from a log the operator does not run,
  turns "I promise this is what happened" into "this commitment was public at time T and cannot now
  be changed without detection". That is the property the project actually needs.
- Cost: a network dependency at seal time, and a bundle that is less useful offline. Anchoring is
  therefore optional and its absence is stated rather than hidden.

## Alternatives considered

**Operator-signed receipts alone.** What the nearest peer projects do. Rejected: an operator can
rewrite the entire log and re-sign it, and no local check can tell. Signatures give integrity
against third parties, never against the author.

**A blockchain.** Delivers non-equivocation, at the cost of a wallet, fees, latency, and a
credibility problem in exactly the enterprise setting this targets. Certificate Transparency solved
this problem without one, and Rekor is CT applied to software artifacts.

**Zero-knowledge proofs of execution.** See [ADR-0005](0005-why-not-zero-knowledge-proofs.md).

## Out of scope

Non-equivocation against a *colluding* transparency log. A log operator who splits its view can
present different roots to different verifiers. The Certificate Transparency literature addresses
this with gossip protocols between verifiers; `hark` does not implement one and does not claim the
property.
