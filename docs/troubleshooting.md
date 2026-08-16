# Troubleshooting

## `hark verify` says TRUNCATED

Expected when a run was killed. The bundle has no footer, so there is no signed root, but every event
that reached disk still verified against the hash chain. Exit code 3 distinguishes this from both
success and corruption. Nothing to fix.

## `hark verify` says BROKEN

The bundle was altered after it was written. The output names the first faulting event and which of
two things happened:

- *payload does not match its leaf hash* — those bytes were edited.
- *chain predecessor mismatch* — the frame is intact but was moved, removed, or spliced in.

The events before the fault are reported separately and are still valid.

## `hark verify` says VERIFIED but I do not trust it

Correct instinct. Without `-key`, the signature is checked against a public key that travelled inside
the bundle it authenticates, which is circular. Pin the key you expect:

```sh
hark verify -key <hex> run.hark
```

Also check the transparency line. `not anchored -- integrity only, no non-equivocation` means nothing
prevents whoever produced the bundle from having produced a different one instead.

## `hark synth -corrupt N` reports an empty payload

Some events encode to an empty CBOR payload when every field is at its zero value. Pick a different
event — `hark inspect` shows the payload sizes.

## Build fails on `lukechampine.com/blake3` or `github.com/fxamacker/cbor/v2`

Both are fetched through the Go module proxy. On a restricted network, set `GOPROXY` appropriately or
vendor them with `go mod vendor`.

## The `run`, `replay`, `fork` and `bisect` commands exit 2

Not implemented yet. W2 through W4 — see [roadmap.md](roadmap.md).

## Landlock is missing from the LSM list

```sh
cat /sys/kernel/security/lsm
```

If `landlock` is absent, filesystem scoping cannot work on that host and `hark run` will refuse
rather than run uncontained.

Two common causes. On a **container-based environment** — a hosted cloud shell, a CI runner, most
managed sandboxes — you are on the provider's kernel and cannot enable it; network namespaces, veth
and seccomp will usually still work, so everything except filesystem scoping remains developable.
On a **real host** it usually needs `lsm=` extended on the kernel command line to include
`landlock`, followed by a reboot.

A hosted shell measured during W0 reported
`capability,lockdown,yama,loadpin,safesetid,apparmor,bpf` — a realistic example of the first case.

## Anything involving netns, Landlock or seccomp

None of it exists yet, and when it does it will be Linux-only. Do not attempt that work under WSL2:
its kernel is Microsoft's, Landlock is typically absent from the active LSM list (check
`/sys/kernel/security/lsm`), and NAT'd virtual-switch networking makes namespace and veth work
non-representative. Use a real Linux box; WSL2 is fine for `go build` and `go test` on the packages
that need no kernel features, which is most of them.
