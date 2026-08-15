# 0002 — Both a hash chain and a Merkle Mountain Range

Status: accepted
Date: 2026-08-16

## Context

The event log needs two properties that pull in different directions.

While recording, events arrive one at a time and the run may be killed at any moment. Integrity has
to hold over whatever was written, without knowing the final length.

After recording, a third party needs to be convinced that one specific event occurred, ideally
without receiving the whole log — bundles reach hundreds of megabytes, and the rest of the run is
usually none of the verifier's business.

A single structure serves one of these well and the other badly.

## Decision

Maintain both, over the same leaves.

```text
leaf_n  = BLAKE3(0x00 || seq || kind || canonical_cbor(payload))
chain_n = BLAKE3(0x02 || chain_{n-1} || leaf_n)     stored in every frame
node    = BLAKE3(0x01 || left || right)             MMR interior nodes
```

The chain value of each frame's predecessor is written into the frame. The MMR is computed over the
same leaves and its root is sealed in the footer.

## Consequences

- A truncated bundle still verifies up to its last intact frame. `hark verify` reports `TRUNCATED`
  with the surviving prefix rather than rejecting the file, because a run killed by SIGKILL is a
  normal outcome and its events are still evidence.
- The two structures fail differently, and that difference is diagnostic. A payload that disagrees
  with its own leaf hash means those bytes were edited. A leaf that agrees with its payload but a
  chain link that does not means the frame is intact but was moved, removed or spliced in. The
  verifier reports which.
- Inclusion proofs cost log₂(N) hashes. Proving one event out of 100,000 takes roughly 17 hashes,
  a few hundred bytes.
- The MMR is not persisted. It is recomputed from the frames when a proof is requested, which costs
  one linear pass over a file that is being read anyway. Storing ~2N interior nodes would nearly
  double bundle size to accelerate an operation that runs far less often than verification.

## Alternatives considered

**Chain only.** Cheap and sufficient for tamper-evidence, but proving a single event requires
shipping every event before it. That destroys the inclusion-proof use case entirely.

**Balanced Merkle tree only.** Gives compact proofs, but has to be rebuilt whenever the leaf count
changes, making a signed tree head every K events quadratic. It also leaves a killed run with no
verifiable structure at all, since the root only exists once the tree is complete.

**MMR only.** Close to sufficient — an MMR is append-only and its historical nodes are immutable.
Rejected because detecting a splice would then require a full recomputation, whereas the chain
catches it at the exact frame with a single comparison, while streaming.

## Note on domain separation

The three prefixes are not decoration. Without them, an attacker controlling an event payload could
craft bytes equal to the concatenation of two child hashes and present that leaf as an interior node.
RFC 6962 fixes this the same way for Certificate Transparency. `TestDomainsAreSeparated` in
`internal/hashchain` locks the property down.
