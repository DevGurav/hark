# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/); the bundle format carries its own
independent version number, documented in [docs/protocol.md](docs/protocol.md).

## [Unreleased]

### Added

- Bundle format version 1: header, hash-chained frames, sealed footer.
- `internal/hashchain` — domain-separated BLAKE3 leaf, node and chain constructions.
- `internal/mmr` — append-only Merkle Mountain Range with O(log n) inclusion proofs, verifiable
  without the tree.
- `internal/logfmt` — 16 event kinds, canonical CBOR payloads, frame codec.
- `internal/signer` — Ed25519 signed tree heads.
- `internal/bundle` — writer, reader and end-to-end verifier that recovers the verified prefix of a
  damaged or truncated bundle.
- `internal/runid` — ULID run identifiers.
- `hark verify`, with `-key` for pinning and exit codes distinguishing verified, broken and
  truncated.
- `hark inspect`, `hark prove` (generate and check), `hark keygen`.
- `hark synth`, which writes a synthetic prompt-injection bundle with `-corrupt` and `-truncate`
  options so the verifier can be exercised before the recorder exists.

### Not yet implemented

`hark run`, `replay`, `fork` and `bisect` exit 2. See [docs/roadmap.md](docs/roadmap.md).
