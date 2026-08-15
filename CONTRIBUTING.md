# Contributing

The project is pre-release and moving fast; the format is not yet stable. Issues and discussion are
more useful than pull requests right now.

## Development

Requires Go 1.23+. No other toolchain, no code generation, no build system beyond `go`.

```sh
go build ./...
go test ./...
go test ./... -race
go vet ./...
```

The bundle format, hashing, MMR and verifier are platform-independent and develop fine on Windows or
macOS. Everything from W2 onward — namespaces, Landlock, seccomp — is Linux-only.

**Do not develop the sandbox layer under WSL2.** Its kernel is Microsoft's, Landlock is typically
absent from the active LSM list, and NAT'd networking makes veth and namespace work
non-representative. Use a real Linux box.

## Before opening a pull request

- `go test ./...` and `go vet ./...` clean.
- Read [docs/decisions/](docs/decisions/) first. If a numbered ADR already settled the question, the
  path forward is a new ADR that supersedes it, not a patch that quietly contradicts it.
- Changes to the wire format, hash constructions or event kind numbers need an ADR and a format
  version bump. Those values are hashed into bundles that must stay verifiable.

## Commits

Conventional-Commits subject, then a body that explains the reasoning rather than the diff.

```
type(scope): imperative, lowercase summary, no trailing period

Why this change exists and what it trades off. Wrap near 72 columns.
Reference the ADR or build-log entry when there is deeper context.
```

Types: `feat fix refactor perf test docs build chore`.

One commit is one logical change, and each one should build and pass its tests on its own. Length
should track substance — a typo fix gets one line, a change to a hashing invariant gets a paragraph
about what it preserves.

No emoji. No AI or tool attribution of any kind.

## Docs are part of the change

A feature without its doc update is unfinished. At minimum, every session that produces a real change
adds a `docs/build-log.md` entry recording what was built, why, what was verified, and what is next.
Reconcile architecture, roadmap, protocol and testing docs in the same commit where the change makes
them wrong.

## Security

Do not open a public issue for a vulnerability. Mail `dev.gurav011@gmail.com`.
