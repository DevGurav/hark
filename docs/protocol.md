# Bundle wire format

Version 1. Frozen once the repo is public: the values here are hashed into every leaf, so changing
one invalidates every bundle ever written.

All integers are big-endian.

## File layout

```text
"HARK" 0x01              5 bytes: magic and format version
u32 + CBOR               header
frames...                zero or more, see below
u32 0xFFFFFFFF           footer sentinel
u32 + CBOR               footer
```

A bundle with no footer is a run that was killed, not a corrupt file. Everything up to the last
intact frame verifies against the hash chain. `hark verify` reports this as `TRUNCATED` and exits 3.

## Frame

```text
offset  size  field
     0     4  payload length, n
     4     1  kind
     5     8  seq
    13     8  monotonic nanoseconds since run start
    21    32  chain value of the preceding frame
    53     n  canonical CBOR payload
  53+n    32  leaf hash of this frame
```

The leaf hash is stored rather than recomputed on read. This lets a verifier distinguish a corrupt
payload (stored leaf disagrees with recomputed leaf) from a reordering or splice (leaf agrees,
chain link does not). Those are different failures and a reader should be able to tell them apart.

Payloads are capped at 64 MiB — far above any realistic single chunk, low enough to refuse an
unbounded allocation from a hostile file.

## Hashing

```text
leaf_n  = BLAKE3(0x00 || seq_be64 || kind_u8 || payload)
node    = BLAKE3(0x01 || left || right)
chain_n = BLAKE3(0x02 || chain_{n-1} || leaf_n)      chain_0 predecessor is 32 zero bytes
```

The leading domain byte prevents a crafted payload from being reinterpreted as an interior node.
See [ADR-0002](decisions/0002-hash-chain-and-merkle-mountain-range.md).

## Merkle Mountain Range

Nodes are conceptually stored in post-order: both children before their parent. Appending leaf
number n (1-based) triggers exactly `TrailingZeros(n)` merges.

```text
leaves  nodes
1       L0
2       L0 L1 P01
3       L0 L1 P01 L2
4       L0 L1 P01 L2 L3 P23 P0123
```

The structure is a forest of perfect binary trees of strictly decreasing height, one per set bit of
the leaf count. Their roots are the peaks.

**Root = peaks bagged right to left.** With peaks `[p0, p1, p2]` the root is
`Node(p0, Node(p1, p2))`. The direction is part of the format; folding the other way produces a
different, valid-looking root.

An empty range has the all-zero root.

The MMR is not persisted. It is recomputed from the frames when a proof is requested.

## Inclusion proofs

A proof carries the leaf index, the leaf count it was issued under, the sibling path up the leaf's
own mountain (bottom first), and the other peaks split into those left and right of it.

It carries **no direction bits**. Whether a sibling joins from the left or the right is derived
during verification from the leaf index, which is already bound into the statement being proved.
Storing directions would let a forger choose them.

Verification:

1. Re-derive which mountain holds the leaf, from `LeafIndex` and `LeafCount`.
2. Check that the sibling path length equals that mountain's height, and that the left and right
   peak counts match. A proof of the wrong shape is rejected before any hashing.
3. Fold the leaf upward; at level `i` the direction is bit `i` of the leaf's offset within its
   mountain.
4. Re-bag with the recomputed peak in place and compare against the root.

## Header

| Key | Field | Notes |
| --- | --- | --- |
| 1 | RunID | ULID, 26 characters |
| 2 | CreatedAt | Unix nanoseconds |
| 3 | Recorder | version string of the writer |
| 4 | ArgvHash | |
| 5 | PolicyHash | |
| 6 | EnvHash | |
| 7 | ParentRoot | forked runs only |
| 8 | ForkPoint | seq the fork diverged at |
| 9 | PatchHash | |

## Footer

| Key | Field | Notes |
| --- | --- | --- |
| 1 | LeafCount | must equal the number of frames |
| 2 | Root | MMR root |
| 3 | FinalChain | last chain value |
| 4 | STH | signed tree head, optional |
| 5 | RekorEntry | transparency log reference, empty if unanchored |
| 6 | RekorIndex | |

## Signed tree head

Signed bytes, with lengths prefixed so no two distinct heads can produce the same input:

```text
"hark/sth/v1" || len(runID)_be64 || runID || leafCount_be64 || root || signedAt_be64
```

Ed25519. The verifier checks the signature, that the signed root equals the recomputed root, and
that the signed leaf count equals the observed one — a valid signature over an unrelated tree must
not pass.

## Event kinds

| # | Kind | # | Kind |
| --- | --- | --- | --- |
| 1 | RunStart | 9 | ToolCallResult |
| 2 | PolicyLoaded | 10 | EgressAttempt |
| 3 | EnvSnapshot | 11 | EgressDecision |
| 4 | FsManifest | 12 | SecretInjected |
| 5 | LlmRequest | 13 | ClockRead |
| 6 | LlmResponseChunk | 14 | RandomRead |
| 7 | LlmResponseEnd | 15 | Checkpoint |
| 8 | ToolCallRequest | 16 | RunEnd |

Numbers are never reused or renumbered. An unknown kind does not prevent verification — a leaf hash
covers opaque payload bytes and never needs them decoded — but replay must refuse to proceed past a
kind it cannot interpret rather than silently skipping it.

| 17 | DnsQuery | 18 | DnsDecision |

`DnsQuery` and `DnsDecision` mirror the `EgressAttempt`/`EgressDecision` pair. The mediator is the
namespace's only resolver, so a name lookup is a policy decision point and an event in its own right,
and it names the destination before any TCP connection exists — see
[ADR-0006](decisions/0006-mediated-dns-and-sni-host-identification.md).

## Payload encoding

CBOR Core Deterministic Encoding (RFC 8949 §4.2.1): shortest-form integers, definite-length
containers, map keys sorted by encoded bytes, indefinite lengths and tags forbidden.

Fields use integer keys rather than names. Smaller, but the real reason is stability: renaming a Go
field cannot change bytes that were already hashed.

Without a canonical form, two encoders disagreeing about map ordering would produce different leaf
hashes for identical events, and replay would report a divergence that never happened.

## Secrets

`SecretInjected` records a credential substitution **by reference only** — a logical name, the
placeholder the agent held, and optionally a hash of the real value for equality checks. The value
itself never enters the log. A bundle is meant to be shared with reviewers, auditors, and a public
transparency log; it must not be the thing that leaks the key.
