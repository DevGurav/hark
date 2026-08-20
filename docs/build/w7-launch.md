# W7 — launch

**Goal.** Show HN, a technical writeup, and the demo video. Lead every posting with the incident,
never the architecture — nobody clicks through for a Merkle Mountain Range; they click through for
an agent that tried to steal a key and got stopped, then replayed.

## Prerequisites

- W6 complete: 25/25 runs replay-equal across 5 shapes, published, CI-verified on a stock
  GitHub-hosted runner.

## What's genuinely different about this week

W0–W6 were artifacts I could write, run, verify and push without asking each time — code, tests,
CI, all reversible and checkable on the box. W7 is a public action with the maintainer's name on
it: a Show HN post is not something to submit on someone else's behalf even when technically
possible, and a launch has exactly one first impression. So the split here is deliberate:

- **Drafted in full, here:** the technical writeup, the Show HN title and post text, the video's
  shot list and captions.
- **Never submitted by anything other than the maintainer:** the actual HN post, and the final
  video render if it involves the maintainer's own voice or presence.

## Deliverables

| File | Responsibility |
| --- | --- |
| `docs/launch/writeup.md` | The technical writeup — long-form, for a personal site or a dev.to-style post. |
| `docs/launch/show-hn.md` | Title and post text, ready to paste, plus the two rebuttal comments pre-written. |
| `docs/launch/video-script.md` | 90-second shot list: captions, timing, what's on screen. |

## Tasks

### 1. The technical writeup

- [ ] Lead with the incident (the same one `demo/run.sh` runs), not the architecture. A reader
      decides whether to keep reading in the first two paragraphs.
- [ ] State the three properties (deterministic replay, kernel-enforced containment, tamper-evident
      audit) and *why third is not optional* — the operator-signed-log argument from
      [ADR-0004](../decisions/0004-transparency-log-over-operator-signed-receipts.md). This is the
      part most similar tools skip, and skipping it is the tell.
- [ ] The determinism scoping paragraph, verbatim or near it — overclaiming here is "the first
      thing a reviewer should check" (README's own words), so the writeup should pass its own bar.
- [ ] The verified related-work table, or a tightened version of it. Get ahead of "this is just
      Pipelock" in the writeup's own words, not just in a reply thread.
- [ ] The W6 fidelity numbers (25/25 across 5 shapes) as evidence the replay claim was tested
      against itself, including the fixture bug the suite caught on its own first run — a tool
      that publishes its own near-miss is more credible than one that only shows the polished
      number.
- [ ] Real numbers only, each traceable to [benchmarking.md](../benchmarking.md) or
      [fidelity.md](../fidelity.md). No figure invented for the writeup that isn't already
      published somewhere in the repo.

**Acceptance.** A reader who stops after the first three paragraphs already knows what happened,
what's novel, and where to look for proof.

### 2. Show HN

- [ ] Title: *Show HN: Deterministic record and replay for AI agents — with a proof the replay is
      real.*
- [ ] Post text: the incident in three sentences, a link to the repo, a link to the writeup. Short —
      HN rewards a post that gets out of the way of its own comments.
- [ ] Pre-write the two replies the spec already predicted:
      - *"this is just Pipelock / Clawker / Agent VCR"* — the related-work table's own answer,
        compressed to comment length: containment is table stakes now, the combination with
        provable replay is not.
      - *"the model is nondeterministic, so what does replay prove?"* — the scoping paragraph,
        compressed: determinism is a property of the harness, not the model.
- [ ] **Not this repo's job to submit it.** Drafted, reviewed, handed over.

### 3. The demo video

- [ ] A shot list extending the incident GIF's own beats (`docs/build/w4-v0.1.md`'s "shot by shot"
      section) to a full 90 seconds: record → the two controls → replay → fork → verify → report.
- [ ] Captions, not narration — text overlays timed to the terminal, the same posture the GIF
      already takes. No voiceover to record, no narration script to write.
- [ ] Split screen: agent terminal left, mediator event stream right — matches the GIF, extended.
- [ ] The actual recording and any editing is the maintainer's own session on the box
      (`asciinema` + `agg`, as the GIF was made) or screen-capture tooling of their choice; this
      spec's job is the shot list and caption text, not operating a video editor.

## Traps

**Leading with the architecture.** Every draft gets checked against its own first paragraph: does
it open with the agent trying to steal a key, or with a Merkle Mountain Range? If the latter,
rewrite the opening before touching anything else.

**Rounding the fidelity or benchmark numbers for punch.** The writeup's credibility *is* its
refusal to do this — see W6's whole reason for existing.

**Treating "drafted" as "posted."** Nothing in this week's task list authorizes actually
submitting the HN post or publishing the video under the maintainer's name. That action belongs to
a human, deliberately, every time.

## Definition of done

- [ ] `docs/launch/writeup.md`, `show-hn.md`, `video-script.md` all written and internally
      consistent with the repo's own published numbers.
- [ ] Every claim in all three traces to something already true in the repo — no forward-looking
      promises stated as done.
- [ ] Handed to the maintainer for review before any of it goes anywhere public.

## Expected commits

```text
docs: draft the W7 technical writeup
docs: draft the Show HN post and its two rebuttal replies
docs: draft the demo video's shot list and captions
```
