# Working in this repo

## Orientation

Read in this order: [docs/roadmap.md](docs/roadmap.md) for where the work is,
[docs/architecture.md](docs/architecture.md) for how it fits together,
[docs/decisions/](docs/decisions/) before proposing anything that a numbered ADR already settled.

[docs/protocol.md](docs/protocol.md) is the authority on the wire format. Code follows it, not the
other way round.

## Commands

```sh
go build ./...
go test ./...
go test ./... -race
go vet ./...
```

Green means tests pass and vet is clean.

## Conventions

- Comments explain *why*, not *what*. The code already says what it does. A comment that restates
  the line below it is noise; one that records the reasoning, the tradeoff, or the attack it
  prevents is the reason the file is maintainable.
- Every non-obvious constant, ordering or construction gets a sentence explaining what breaks
  without it. The domain-separation bytes, the bagging direction, and the absence of direction bits
  in proofs are all examples.
- Errors say what went wrong in terms the caller can act on. No error message includes a sequence
  number that the caller already has.
- Prefer clear over clever. Every line here has to be defensible in a viva.

## What not to touch

- **Hash construction and domain bytes** (`internal/hashchain`). Changing one invalidates every
  bundle ever written.
- **Event kind numbers** (`internal/logfmt/kind.go`). Frozen. New kinds get new numbers; existing
  numbers are never reused or renumbered.
- **Wire layout and the bagging direction.** Both are specified in `docs/protocol.md`. A change here
  is a format version bump, not an edit.
- **Accepted ADRs.** Never edited. Supersede with a new one.

## Definition of done

Per `Repos/ENGINEERING_PLAYBOOK.md`:

- [ ] Builds; relevant tests green
- [ ] `docs/build-log.md` entry added; living docs reconciled
- [ ] New decisions captured as ADRs
- [ ] Roadmap state markers moved
- [ ] Committed atomically, with messages that read as an engineer's
- [ ] Pushed

## Attribution

This is a solo-authored project. No AI assistance is referenced anywhere in the repository — not in
commits, code comments, docs, or issue text. No `Co-Authored-By` trailers, no "generated with" lines.

Commits are authored as `DevGurav <dev.gurav011@gmail.com>`.
