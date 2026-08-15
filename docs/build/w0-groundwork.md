# W0 — groundwork

**Goal.** Remove every unknown from W2 before W2 starts, so that week is translation rather than
discovery.

W2 and W3 are the two highest-variance weeks and they are consecutive. This phase exists because
finding out that veth does not behave as expected on day 9 of an 8-week schedule is how projects
die. Nothing here produces Go code that ships.

Budget: one weekend.

## Prerequisites

- W1 merged and green.
- A payment method or an Oracle Cloud account for the free tier.

## Tasks

### 1. Provision the Linux box

- [ ] Oracle Cloud Ampere free tier, Mumbai region, Ubuntu 24.04, 4 ARM cores / 24 GB. Permanently
      free, which matches the zero-budget constraint.
- [ ] Fallback if the Ampere quota is unavailable, which is common: Hetzner CX22 x86, Ubuntu 24.04,
      roughly ₹400/month. Do not spend more than an hour fighting Oracle capacity before switching.
- [ ] SSH key auth only, password login disabled.
- [ ] Install: `go` 1.23+, `git`, `tcpdump`, `iproute2`, `curl`, `jq`, `build-essential`.
- [ ] Connect VS Code Remote-SSH so the editing experience is unchanged from local.

**Acceptance.** `go version` on the box, and `ssh <box> 'uname -a'` from Windows without a password.

### 2. Confirm the kernel has what the design needs

```sh
cat /sys/kernel/security/lsm            # must contain "landlock"
uname -r                                # 6.x
zgrep -E 'LANDLOCK|SECCOMP|NET_NS' /proc/config.gz 2>/dev/null || \
  grep -E 'LANDLOCK|SECCOMP|NET_NS' /boot/config-$(uname -r)
```

- [ ] `landlock` appears in the active LSM list.
- [ ] Unprivileged user namespaces are permitted, or note that the launcher will need `CAP_NET_ADMIN`.

**If Landlock is missing from the LSM list**, it usually needs `lsm=...,landlock` on the kernel
command line. Record whatever the fix was in `docs/troubleshooting.md` — it will be the first thing
that bites a contributor.

**Acceptance.** Both checks pass, or their answers are written down.

### 3. Throwaway shell prototype

Not Go. A shell script, thrown away afterwards, that proves the W2 mechanics work on this kernel.

- [ ] Create a network namespace and a veth pair; put one end inside.
- [ ] Confirm a process inside the namespace has **no route** to the internet.
- [ ] Run a TLS-terminating proxy on the host end. `mitmproxy` is fine here — this is a probe, not a
      dependency.
- [ ] Generate a CA, install it in the namespace's trust store, and confirm `curl https://example.com`
      from inside the namespace is intercepted and readable by the proxy.
- [ ] Confirm `curl https://evil.example` fails when the proxy refuses it.
- [ ] Confirm that a process which ignores `HTTPS_PROXY` entirely still cannot reach the network.
      **This is the single most important check in W0** — it is the claim the whole containment story
      rests on, and it is the first thing an interviewer will probe.

Sketch, to adapt rather than copy:

```sh
ip netns add harkns
ip link add veth-h type veth peer name veth-n
ip link set veth-n netns harkns
ip addr add 10.200.1.1/24 dev veth-h && ip link set veth-h up
ip netns exec harkns ip addr add 10.200.1.2/24 dev veth-n
ip netns exec harkns ip link set veth-n up
ip netns exec harkns ip link set lo up
# deliberately no default route
ip netns exec harkns curl -s https://example.com   # must fail
```

- [ ] Write down the exact commands that worked in `docs/build/w2-launcher.md` under "verified
      mechanics", so W2 translates rather than rediscovers.

**Acceptance.** A process inside the namespace can reach an allowlisted host through the proxy and
nothing else, and the transcript is saved.

### 4. Verify the related-work table

`README.md` carries a comparison table marked as a positioning sketch. It ships only once every row
has been checked against the actual project.

- [ ] For each of Pipelock, Clawker, Nono, AgentSight, SandBase, Agent VCR, mcpsnoop, Temporal, E2B:
      open the repository, read the README and enough source to confirm what it does and does not do.
- [ ] Correct or delete any row that does not survive.
- [ ] Record the date checked and the version or commit inspected.
- [ ] Remove the "positioning sketch" caveat once done.

Getting a peer project's capabilities wrong in public is the one unforced error that would genuinely
damage the project's credibility. Omitting the table entirely is better than shipping it unverified.

**Acceptance.** Every row cites a version or commit and a date.

### 5. Decide the name, permanently

`hark` is in every import path, the module name, the binary, the file extension and the docs. It is
already committed. Changing it later is a mechanical but repo-wide rewrite.

- [ ] Confirm `hark`, or change it now before anything else lands.

## Definition of done

- [ ] `ssh <box> 'go version'` works.
- [ ] Landlock confirmed present, or its absence documented with the fix.
- [ ] Namespace transcript saved into the W2 spec.
- [ ] A process ignoring `HTTPS_PROXY` demonstrably cannot reach the network.
- [ ] Related-work table verified, caveat removed.
- [ ] `docs/build-log.md` entry added.
- [ ] Roadmap W0 boxes ticked.

## Expected commits

Two, both docs-only. No Go changes belong in this phase.

```text
docs: record the verified namespace mechanics for W2
docs: verify the related-work comparison against each project
```
