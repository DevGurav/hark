# Build guide

Implementation specifications, one per phase. These are the working documents: open the spec for the
current phase, execute its tasks in order, and run its acceptance checks before moving on.

`docs/roadmap.md` says *what* ships and *when*. These specs say *how* — file paths, interfaces,
acceptance commands, and the traps that will otherwise cost days.

## Phases

| Spec | Phase | State |
| --- | --- | --- |
| — | W1 · bundle format and verifier | **done** |
| [w0-groundwork.md](w0-groundwork.md) | W0 · Linux box, shell prototype, prior-art check | next |
| [w2-launcher.md](w2-launcher.md) | W2 · launcher, mediator, secrets broker | not started |
| [w3-replay.md](w3-replay.md) | W3 · playback, request keying, shims | not started |
| [w4-v0.1.md](w4-v0.1.md) | W4 · the incident, fork, anchoring — **v0.1 ships** | not started |
| [w5-w8-later.md](w5-w8-later.md) | W5–W8 · real workload, fidelity, launch | not started |

W1 has no spec because it is already built. Read the code and `docs/build-log.md` instead.

## How to use a spec

Each one has the same shape:

1. **Goal** — one sentence. If a task does not serve it, the task is out of scope.
2. **Prerequisites** — what must be true before starting. Do not start without them.
3. **Deliverables** — the files to create and what each is responsible for.
4. **Tasks** — ordered, each with its own acceptance check.
5. **Interfaces** — Go signatures to implement against, so the pieces fit without redesign.
6. **Traps** — the specific things that will eat a day. Read these first, not after.
7. **Definition of done** — the commands that must pass, and the docs to reconcile.
8. **Expected commits** — the atomic slices this phase should land as.

Tasks are ordered so each builds on the last and the phase can be abandoned partway without leaving
the tree broken.

## The working loop

Run this at the end of every session that produced a real change. It is the loop whose absence leaves
code uncommitted with stale docs.

1. **Verify green.** `go build ./... && go vet ./... && go test ./... -count=1`, plus the phase's own
   acceptance commands.
2. **Update the docs the change touched.** `docs/build-log.md` always — a new entry saying what was
   built, why, what was verified, what is next. Then architecture, roadmap, protocol, testing,
   security, CHANGELOG as applicable. A new decision means a new ADR.
3. **Move the roadmap state markers** and tick the boxes in the phase spec.
4. **Stage deliberately and commit atomically.** One logical change per commit; split a session that
   covered several concerns.
5. **Push.**

## Rules that apply to every phase

- **Read `docs/decisions/` before proposing anything.** If a numbered ADR settled it, the path
  forward is a new ADR that supersedes it, not a patch that quietly contradicts it.
- **`docs/protocol.md` is the authority on the wire format.** Code follows the spec.
- **Never change** hash constructions, domain bytes, event kind numbers, or the bagging direction
  without a format version bump and an ADR. Those values are hashed into bundles that must stay
  verifiable.
- **Scope discipline.** If a pillar cannot be demonstrated with one terminal command, it is not in
  v0.1. The cut list in `docs/roadmap.md` is binding.
- **Never claim 100%** replay fidelity, and never claim the model is reproducible. See
  `docs/architecture.md` on what determinism means here.
- **Comments explain why.** A comment restating the line below it is noise; one recording the
  tradeoff or the attack it prevents is why the file stays maintainable.
- **Every line must be defensible in a viva.** Prefer the clear implementation over the clever one.

## Environment

| Work | Where |
| --- | --- |
| Pure-logic packages: format, hashing, MMR, signer, verifier | Windows or WSL2, either is fine |
| Anything touching netns, Landlock, seccomp, veth | A real Linux box only |
| Race detector | Linux or CI — it needs cgo, which the Windows box does not have configured |

**Never do sandbox work under WSL2.** Its kernel is Microsoft's, Landlock is typically absent from
the active LSM list, and NAT'd virtual-switch networking makes namespace and veth behaviour
unrepresentative of a real host. Debugging that difference is a day you do not get back.
