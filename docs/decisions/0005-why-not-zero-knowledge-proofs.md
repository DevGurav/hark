# 0005 — Why not zero-knowledge proofs

Status: accepted
Date: 2026-08-16

## Context

I have written Circom circuits and a Solidity verifier before, and "verifiable agent execution" is
the obvious place to reach for that toolkit. The phrase *proof of execution* appears in the project
description, so the question needs a written answer rather than a shrug — otherwise it gets
re-litigated every time someone reads the README.

## Decision

No zero-knowledge proofs. The commitment scheme is BLAKE3 hashing, an MMR, Ed25519, and a public
transparency log.

## Consequences

- What is proved is that *these recorded events are the ones that were committed to*. What is not
  proved is that a model, given this input, necessarily produced that output. The README states this
  distinction directly rather than letting "proof" imply the stronger claim.
- Verification is a few hundred bytes and log₂(N) hashes, checkable by any client in milliseconds,
  with no trusted setup, no proving key, no circuit, and no exotic dependency.
- If a genuine need for the stronger property appears, it arrives as a layer above an event log that
  already exists, rather than as a foundation that would have had to be right from the start.

## Alternatives considered

**ZK proof of the model's forward pass.** Proving a transformer inference in zero knowledge is
research-grade for models of any useful size, and completely out of reach for a hosted model whose
weights I do not have. This is not a matter of engineering effort; the information required is not
available to the prover.

**ZK proof over the event log rather than the model.** Technically feasible: prove "I know a log
whose root is R and which contains an event matching predicate P" without revealing the log. But a
Merkle inclusion proof already reveals only the single leaf being proved, which covers the actual
privacy requirement at a fraction of the cost. The extra hiding a ZK circuit would buy — concealing
*which* leaf, or the total count — is not something any user has asked for.

**A recursive SNARK over the chain, for constant-size verification.** Elegant, and the log₂(N)
proofs it would replace are already ~17 hashes at 100,000 events. Optimising a few hundred bytes
into a few dozen is not worth a proving system.

## The real reason this ADR exists

Half-building a ZK layer would be the single most attractive way to waste this project's schedule.
It is the piece I am most qualified to attempt, the most impressive-sounding, and the least
load-bearing. Hashing plus a transparency log delivers essentially all of the credibility for a
fraction of the cost, and the honest argument for why is worth more than a partial circuit would be.
