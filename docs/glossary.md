# Glossary

Terms that mean one specific thing across this codebase and its docs.

**Bagging** — folding the peaks of an MMR into a single root, right to left. With peaks
`[p0, p1, p2]` the root is `Node(p0, Node(p1, p2))`. The direction is part of the wire format.

**Bit-exact** — a replay that recomputes the same chain and Merkle root as the original run. It
describes the harness's externally-visible actions, never the model's tokens. See *determinism*.

**Bundle** — a `.hark` file: header, frames, footer. One run, or one fork of a run.

**Chain** — the running hash `chain_n = H(0x02 || chain_{n-1} || leaf_n)`, with each frame storing
its predecessor's value. Gives O(1) streaming integrity, so a killed run still verifies up to its
last intact frame.

**Determinism** — a property of the harness, not the model. Given the same recorded external inputs,
the agent produces the same sequence of externally-visible actions and the same log root. Hosted
model inference is not reproducible even at temperature 0, so `hark` records what the model said
rather than claiming it could re-derive it.

**Domain separation** — the leading byte (`0x00` leaf, `0x01` node, `0x02` chain) that stops one
hash construction being mistaken for another. Without it a crafted payload could be presented as an
interior node.

**Fork** — a run branched from a recorded one at a chosen event, with a patch applied. The prefix is
replayed bit-exactly and is provable; the suffix is live. A fork is *not* bit-exact overall, and the
docs never say otherwise.

**Frame** — one recorded event on disk: length, kind, seq, monotonic timestamp, predecessor chain
value, canonical CBOR payload, leaf hash.

**Leaf** — the hash of a single event, binding its sequence number and kind as well as its payload,
so an event cannot be moved or relabelled without changing its hash.

**Mediator** — the process that terminates TLS, evaluates egress policy, injects credentials, and
records every crossing. It is both the enforcement point and the recorder; that identity is the
project's central design claim.

**MMR (Merkle Mountain Range)** — an append-only Merkle structure: a forest of perfect binary trees
of decreasing height, one per set bit of the leaf count. Amortised O(1) append, O(log n) inclusion
proofs, and historical nodes that never change.

**Non-equivocation** — the property that the operator cannot present two different histories of the
same run to two different verifiers. Requires an independent witness; signatures alone do not
provide it.

**Peak** — the root of one perfect subtree within an MMR.

**Placeholder** — the fake credential the agent actually holds, `hark-placeholder-<runid>`. The real
value is substituted at the boundary, so the agent never sees it and it never enters the log.

**Replay-equal** — the outcome when a replayed run produces the same root as the original. The only
alternative outcomes are a reported first-divergent-event or an error; there is no partial credit and
no similarity score.

**Request key** — `(canonical_request_hash, occurrence_ordinal)`, used to match a replayed request to
its recorded response. The ordinal exists because one run can issue byte-identical requests that
received different responses.

**Run ID** — a ULID: 48-bit millisecond timestamp plus 80 bits of randomness, Crockford base32, 26
characters. Sorts lexicographically in creation order.

**Sealed / truncated** — a sealed bundle has a footer, a Merkle root and optionally a signature. A
truncated one does not, because the run was killed. Truncated is a legitimate state reported as
exit code 3, not a verification failure.

**STH (signed tree head)** — an Ed25519 signature over `(runID, leafCount, root, signedAt)`.
Necessary but not sufficient: it proves someone holding that key vouched for the root, not that this
is the only history the operator produced.

**Zone 0 / 1 / 2** — the supervisor, the mediator, and the untrusted agent process tree. Zone 2 is
separated from the others by a network namespace, Landlock, seccomp and dropped capabilities.
