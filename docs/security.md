# Threat model

## What hark defends

An agent that has been prompt-injected. The agent's own reasoning is assumed compromised — the whole
premise is that instructions arriving in tool output are indistinguishable from legitimate ones at
the point they are read. Defences that depend on the agent choosing correctly are therefore
worthless here, and the design contains rather than persuades.

## Adversaries

**A1 — injected agent.** Untrusted code running in Zone 2, executing attacker-influenced plans. Can
call any syscall not blocked, spawn children, ignore environment variables, write its own sockets.

**A2 — network attacker.** Can observe or modify traffic outside the boundary, and controls the
content the agent fetches.

**A3 — the operator.** Runs `hark` and holds the signing key. Wants a run to have gone differently
than it did. This is the adversary most audit tools omit, and the one that motivates
[ADR-0004](decisions/0004-transparency-log-over-operator-signed-receipts.md).

**A4 — a bundle recipient.** Receives a bundle or a proof and wants to be convinced without trusting
the sender.

## Controls

| Threat | Control | Status |
| --- | --- | --- |
| A1 exfiltrates a credential | Broker: the agent's environment holds `hark-placeholder-<runid>`; real values are injected at the boundary, after Zone 2 | W2 |
| A1 reaches a disallowed host | Network namespace with no route except the veth; allowlist evaluated in the mediator | W2 |
| A1 evades the proxy by ignoring `HTTPS_PROXY` | Namespace, not the environment variable, is the control — there is no other route regardless of the agent's code | W2 |
| A1 reads files outside its workspace | Landlock filesystem scoping | W2 |
| A1 escalates privilege | `NO_NEW_PRIVS`, all capabilities dropped, seccomp | W2 |
| A1 edits or deletes its own audit log | The log lives in Zone 0; no Landlock rule grants a path to it | W2 |
| A1 hides an attempt by crashing afterwards | `EgressAttempt` is written before the decision, and the writer fsyncs after a denial | done (writer) |
| A2 or A3 edits a bundle | Per-frame leaf hashes and a hash chain; the verifier names the faulting event and distinguishes an edit from a splice | done |
| A2 substitutes a whole bundle | Ed25519 signed tree head, with `hark verify -key` for pinning | done |
| A3 rewrites a run and re-signs it | Transparency log inclusion proof against a published tree head | W4 |
| A4 must trust the sender | Inclusion proofs verify against a root obtained independently; one event costs log₂(N) hashes and discloses nothing else | done |

## Known limitations

Stated here rather than discovered by a reader.

- **Cert-pinning agents.** An agent that pins certificates will refuse the mediator's CA. Its traffic
  cannot be recorded; the in-process shim is the workaround. Not solved.
- **Per-read filesystem determinism.** `FsManifest` hashes the granted read-set at `RunStart`. `hark`
  asserts the readable files had those contents when the run began, not that each read returned
  particular bytes. Per-read interception requires FUSE or an eBPF LSM.
- **In-process races.** The mediator orders boundary crossings, not two threads sharing a dict.
  Replay detects the resulting divergence and reports the first divergent event; it does not prevent
  it.
- **Per-tool-call scoping.** Every request looks alike to the namespace, so policy is only as
  granular as the mediator can parse. "This tool may reach this host, that one may not" needs eBPF.
- **Colluding transparency log.** A log operator that splits its view can show different roots to
  different verifiers. Certificate Transparency addresses this with verifier gossip; `hark` does not
  implement one and does not claim the property.
- **The signing key.** Held by the operator, written to disk at mode 0600. There is no HSM support
  and no key rotation story yet. An operator who loses the key loses the ability to seal new bundles;
  an operator whose key is stolen has the A3 problem, which is why anchoring matters.
- **Side-effecting tools.** Replay serves recorded results and never re-executes. Fork requires an
  explicit `may_reexecute` annotation before it will call out again.

## Secrets in bundles

`SecretInjected` records a substitution by reference: a logical name, the placeholder the agent held,
the destination host, and optionally a BLAKE3 hash of the real value for equality checks. The value
never enters the log.

This is load-bearing. Bundles are designed to be handed to reviewers and anchored in a public log; a
format that could leak the key it protected would be worse than no format.

## Reporting

The project is pre-release and has no users. Once it does, security reports go to the address in
`CONTRIBUTING.md` rather than to the public issue tracker.
