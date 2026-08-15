# API

`hark` has two external surfaces.

**The CLI** is documented in the [README](../README.md) quickstart. Its contract is the exit codes:
`0` verified, `1` broken or rejected, `2` usage error, `3` truncated. Output wording is not part of
the contract and may change.

**The bundle format** is the more important interface, because bundles outlive the binary that wrote
them and must be verifiable by third-party tooling. It is specified in
[protocol.md](protocol.md), which is the authority.

There is no network API and no library API stability guarantee. Everything under `internal/` is
private by construction and will move.

*Trigger: promote this file to a real specification if a stable Go API surface is published, or if
the E2B-compatible endpoint subset lands (post-v1.0 — see [roadmap.md](roadmap.md)).*
