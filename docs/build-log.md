# Build log

Newest first. Append-only.

---

## 2026-08-16 — W1: bundle format, Merkle Mountain Range, verifier

Built the entire cryptographic and format layer, deliberately before touching anything kernel-related.

**Why this order.** W2 and W3 — the launcher and the replayer — are the two highest-variance weeks,
and they are consecutive. Starting there risks a fortnight with nothing to show. The bundle format
has no kernel dependencies, runs identically on Windows and Linux, and is the piece hardest to fake
later: a verifier that catches tampering is either real or it is not. So it went first.

**What landed.**

- `internal/hashchain` — three domain-separated BLAKE3 constructions. The prefix bytes are the
  second-preimage defence RFC 6962 uses for Certificate Transparency, and the tests assert the
  separation directly rather than assuming it.
- `internal/mmr` — flat post-order node array, `TrailingZeros(n)` merges per append, peaks bagged
  right-to-left. Inclusion proofs carry no direction bits: direction is derived from the leaf index
  during verification, so a forger cannot choose them.
- `internal/logfmt` — 16 event kinds with frozen numeric values, canonical CBOR payloads with
  integer keys, and a frame codec that stores the leaf hash alongside the payload.
- `internal/signer` — Ed25519 signed tree heads over a length-prefixed, domain-separated input.
- `internal/bundle` — writer, reader and verifier.
- `internal/runid` — ULIDs, chosen over UUIDv4 so a directory of bundles lists chronologically.
- CLI: `verify`, `inspect`, `prove`, `synth`, `keygen`.

**Two design points worth recording.**

Storing the leaf hash in each frame rather than recomputing it on read looked redundant at first. It
is what lets the verifier distinguish an edited payload from a reordered log: if the stored leaf
disagrees with the recomputed one, those bytes changed; if the leaf agrees but the chain link does
not, the frame is intact but was moved. Two different failures, two different remedies, and a
verifier for an audit tool should say which.

Keeping both a hash chain and an MMR seemed like belt and braces until the crashed-run case came up.
An MMR root only exists once sealed, so a `SIGKILL`ed run would have had no verifiable structure at
all. The chain gives streaming integrity over whatever was written. `hark verify` now reports
`TRUNCATED` with the surviving prefix and exit code 3 — a killed run is a real state, not a failure.

**Bugs found while building.**

`climb` collected sibling hashes top-down while `Verify` derived direction bits bottom-up. Every
proof for a mountain taller than one level would have failed. Caught by writing the exhaustive
round-trip test before trusting the implementation — sampling a few leaf counts would very likely
have missed it, since single-leaf mountains verify fine either way.

First pass at the verifier reported zero events and a zero root when it hit a fault, discarding the
prefix that had verified. Fixed to report how much of the run survived. Related: the fault message
was printed as `seq 9: seq 9: ...` because both `Validate` and the CLI prefixed it. `Validate` no
longer includes the sequence number — the caller has it.

Also: `hark verify -key` printed `VERIFIED` above a line saying the pinned key did not match. Now
`REJECTED`. For a tool whose entire pitch is precise reporting, a headline that contradicts the
detail below it is the worst possible defect.

**Verified.** 47 tests (52 with subtests) across 6 packages, `go vet` clean. End-to-end by hand:
keygen → synth → verify → inspect → prove → prove -check, plus the three negative paths (corrupted
payload, truncated run, pinned-key mismatch) each producing the right output and exit code.

**Next.** W0 groundwork, which W1 jumped ahead of: provision the Linux box, prototype netns + veth +
MITM in throwaway shell before writing any Go for it, and verify the related-work table against the
actual repositories rather than against summaries. Then W2, the launcher.
