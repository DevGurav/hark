# Demo video: shot list

90 seconds, captions rather than narration — no voiceover to record, no script to read aloud. Split
screen: agent terminal left, mediator event stream right, the same framing `docs/build/w4-v0.1.md`
specified for the original incident GIF. This extends those beats rather than replacing them; `demo/
demo.gif` and `demo.cast` (recorded on the box with `asciinema` + `agg`) are the source material to
re-cut or re-record from, not a from-scratch shoot.

**Every number below is real, not placeholder** — pulled from `docs/benchmarking.md` and the
README's own anchored-run record. Where a shot depends on a value that changes per recording (an
event's sequence number, a root hash), the caption says to use whatever that run actually prints,
not a hardcoded figure that will drift from the footage.

| Time | On screen | Caption |
| --- | --- | --- |
| 0:00 | Left pane: `sudo ./demo/run.sh` starts. Agent fetches the briefing. | *An agent fetches a page. Right pane starts filling with mediator events as it happens.* |
| 0:08 | Right pane: `EgressAttempt`/`EgressDecision` for the allowed host scroll past. | *Every request is on the record before the agent sees the response.* |
| 0:14 | Left pane: agent prints "asking the model what to do." Right pane: the model call. | |
| 0:20 | Left pane: agent prints "plan is post." | *The page carried an instruction the agent never asked for. The model followed it.* |
| 0:26 | Right pane, highlighted/red frame: `EgressDecision DENIED evil.example`. | *Control one: the connection never leaves the namespace.* |
| 0:34 | Right pane: `SecretInjected hark-placeholder-...`. | *Control two: the "key" it tried to leak was never the real one.* |
| 0:42 | Cut to `hark verify incident.hark` output. | *Chain, root, signature — checked, not asserted.* |
| 0:50 | Cut to `time hark replay incident.hark` output, both numbers on screen. | *1052ms recorded → 145ms replayed. No network, no credentials, the second time.* (Real figures, `docs/benchmarking.md`.) |
| 1:00 | Cut to `hark fork -at N -patch strip-injection.json ...` — use the actual event number and root this recording's `hark inspect` reports. | *Same prefix, checked action by action as it re-executes. Live from there.* |
| 1:10 | Cut to the fork's `hark inspect` — no `EgressDecision DENIED` line this time. | *Provably identical prefix, live suffix. Never bit-exact — this half is a fresh run.* |
| 1:18 | Cut to `hark report -offline` output, then the rendered HTML opening in a browser with the network panel showing zero requests. | *One file. Opens with the network off.* |
| 1:25 | Final card: the three commands (`run`, `replay`, `fork`) and the repo URL. | *hark — deterministic record and replay for AI agents, with a proof the replay is real.* |

## Notes for whoever cuts this

- **The anchoring beat is optional and situational.** If re-recording with `-anchor`, insert a shot
  after 1:10 showing `hark verify` reporting transparency inclusion — this project has one real
  anchored run (Rekor entry `108e9186…`, log index `2498575532`, verified from a second machine) if
  a live anchor isn't wanted for the video itself. Don't fabricate an inclusion proof on screen; use
  a real one or skip the beat.
- **Captions, not subtitles-of-narration.** These are short declarative lines timed to the action,
  not a transcript of anyone talking. If they read awkwardly out loud, that's fine — they're not
  meant to be read aloud.
- **The red frame at 0:26 is the one shot worth spending real effort on.** It's the single image
  most likely to be the thumbnail, the HN post's implicit hook, and the frame someone screenshots
  into a tweet. Everything else can be a plain terminal capture.
