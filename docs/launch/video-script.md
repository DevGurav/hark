# Demo video: shot list

**Recorded.** [`video.gif`](video.gif) — 30 seconds, 1282×735, produced by [`video.sh`](video.sh) on
the box with `asciinema` + `agg`, the same toolchain as the original incident GIF:

```sh
asciinema rec video.cast --overwrite --cols 140 --rows 34 -c ./docs/launch/video.sh
agg --font-size 15 --speed 1 video.cast video.gif
```

It came in at 30 seconds rather than the 90 planned below. The plan assumed narration-paced beats;
in practice the commands are fast enough that the only real time cost is caption reading, and
padding it to 90 would have meant inserting dead air. Shorter is also better for a GIF, which is
the form this is most likely to be viewed in. The beat list below is what it follows.

Captions rather than narration — no voiceover to record, no script to read aloud. Single terminal
rather than the split screen originally sketched: the mediator's event stream *is* `hark inspect`'s
output, so showing it as its own pane would have meant inventing a view that doesn't exist. Showing
the real command is both more honest and more reproducible.

**Every number below is real, not placeholder** — pulled from `docs/benchmarking.md` and the
README's own anchored-run record. Where a shot depends on a value that changes per recording (an
event's sequence number, a root hash), the caption says to use whatever that run actually prints,
not a hardcoded figure that will drift from the footage.

| Beat | On screen | Caption |
| --- | --- | --- |
| 1 | `hark run` — the agent fetches the briefing, asks the model, gets a plan, tries to post. | *An agent fetches a page, asks a model what to do, and does it.* |
| 2 | `hark inspect` — the full 31-event record scrolls, ending at `RunEnd exit 1`. | *The page carried an instruction the agent never asked for.* |
| 3 | The `EgressDecision DENIED evil.example` line, alone, in red. | *Control one: the connection never left the namespace.* |
| 4 | The `SecretInjected hark-placeholder-…` line, alone, in yellow. | *Control two: the key it tried to leak was never the real one.* |
| 5 | `hark verify` — `VERIFIED`, root, chain head, signature, and the unanchored transparency line. | *Chain, root, signature — checked, not asserted.* |
| 6 | `hark replay`, then the measured comparison in green. | *Now replay it. No network, no credentials, the second time.* → **recorded ~1060 ms → replayed ~160 ms** |
| 7 | `hark fork -at 11 -patch strip-injection.json` — parent root, branch point, patch hash, child root. | *Fork at the page fetch, with the injected paragraph stripped.* |
| 8 | The fork's `EgressDecision` lines: two allowed, no denial. | *Same prefix, verified action by action. Live from there — and nothing tried to leave.* |
| 9 | `hark report -offline` — one HTML file written. | *One HTML file. Opens with the network off.* |
| 10 | Closing card: the three commands and the repo URL. | *hark — deterministic record and replay for AI agents, with a proof the replay is real.* |

## Notes

- **The replay figures are measured live in the recording, not captioned in.** `video.sh` times both
  the recorded run and the replay and prints the comparison, so the number on screen is that run's
  own. It lands within a few ms of `docs/benchmarking.md`'s published 1052 ms → 145 ms every time,
  which is the point — the benchmark is reproducible, so the video doesn't need to quote it.
- **The 0.9 s stub delay is the honest part.** `video.sh` sets `HARK_STUB_DELAY=0.9`, the same figure
  `docs/benchmarking.md` measures against, because a stub answering instantly would leave replay
  with no latency to skip and understate the one number most likely to be quoted.
- **The anchoring beat is deliberately absent.** Anchoring writes to a public, permanent log, which
  is not something a demo re-recording should do on every take. The project has one real anchored
  run (Rekor entry `108e9186…`, log index `2498575532`, verified from a second machine) if the beat
  is ever wanted — but use that one, or a fresh real anchor. Never stage an inclusion proof.
- **The red DENIED frame is the thumbnail.** It's the single image most likely to end up in the HN
  post, a screenshot, or a tweet, which is why it gets its own beat rather than scrolling past
  inside the `inspect` output it's already part of.
