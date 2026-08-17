# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/); the bundle format carries its own
independent version number, documented in [docs/protocol.md](docs/protocol.md).

## [Unreleased]

Everything below is implemented and tested; `v0.1.0` is tagged once `demo/run.sh` has been run end to
end on Linux and the benchmark figures are filled in. See [docs/roadmap.md](docs/roadmap.md).

### Added — W4

- `hark fork -at N [-patch FILE]` — replays a recorded prefix, checking it action by action against
  the parent as it happens, applies a patch to the response at the branch point, and goes live from
  there. Refuses in three distinguishable ways rather than overstating a fork it did not perform:
  `FORK-DIVERGED`, `FORK-INCOMPLETE`, `FORK-UNPATCHED`.
- `hark report` — renders a bundle as one self-contained HTML file. No server, no framework, no
  JavaScript, no external request.
- Transparency-log anchoring: `hark run -anchor` and `hark fork -anchor` submit the signed tree head
  to Sigstore Rekor; `hark verify` fetches the entry, checks it covers this run, and recomputes the
  log's root from the inclusion proof. Anchoring is never fatal — a log that is down must not mean a
  run cannot be recorded.
- `hark verify -offline` and `-rekor URL`.
- `-upstream HOST=ADDR` and `-upstream-ca FILE` on `run` and `fork`, recorded in `RunStart` so a
  bundle cannot claim it reached a host it did not.
- `demo/` — the prompt-injection incident, hermetic: no API key, no cost, no network.
- Benchmark harnesses for mediated-call overhead (p50/p99), replay wall time, log size by event kind,
  and verify and inclusion-proof cost at 100k events.
- ADR-0008 (a fork is a verified prefix and a live suffix) and ADR-0009 (upstream redirection is
  recorded, not hidden).

### Changed — W4

- The mediator decides playback per exchange rather than per connection, and dials upstream lazily,
  which is what lets a fork hand over mid-connection. A replayed run still opens no outbound
  connection at all.
- The shim gained a fork mode: recorded clock and RNG values up to the branch point, real ones after.

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

`hark bisect` exits 2. See [docs/roadmap.md](docs/roadmap.md).
