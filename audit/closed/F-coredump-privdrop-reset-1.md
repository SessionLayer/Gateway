# F-coredump-privdrop-reset-1: privilege drop re-enables coredumps (CWE-528)
- Severity: high
- Status: Verified-Fixed
- Area: hardening

## Risk (redteam, PoC-confirmed on this host)
`hardening::coredump` sets `PR_SET_DUMPABLE=0` early (before bind). But the
privilege drop's `setuid` makes the kernel **reset the dumpable flag** to
`/proc/sys/fs/suid_dumpable` (documented `commit_creds()` behaviour on any
euid/egid change). The code never re-asserted it → post-privdrop the process was
**dumpable again**. And pipe `core_pattern` handlers (systemd-coredump / apport —
the modern-systemd default) **ignore `RLIMIT_CORE`**, so `RLIMIT_CORE=0` +
`LimitCORE=0` do nothing for them: `PR_SET_DUMPABLE=0` was the only effective gate,
and privdrop threw it away. Reproduced on this host (`suid_dumpable=2`,
`core_pattern=|apport`): a crash while SSH plaintext / the transient inner ECDSA
key is live → a full core piped to disk. This falsified [[F-coredump-1]] and
undermined the coredump-suppression that [[F-innerkey-zeroize-1]] +
[[F-recorder-plaintext-zeroize-1]] cite as their compensating control.

Only bites the **bind-`:22`-then-drop** deployment (systemd/bare-metal). The
non-root container model never calls `setuid`, so it was unaffected — which is why
no E2E caught it (none exercise privdrop; privdrop needs root).

## Resolution (Verified-Fixed)
`privdrop::drop_to` re-asserts `nix::sys::prctl::set_dumpable(false)` immediately
after `setuid`, and **verifies `get_dumpable()? == false` fail-closed** (aborts
startup if the re-assert did not take). Order-flexible w.r.t. seccomp (`prctl` is
allow-listed). The kernel-F-4 canary `coredump-check` now also asserts
`PR_GET_DUMPABLE==0` (not just `RLIMIT_CORE==0`), so the guard is non-vacuous under
a piped `core_pattern`. Belt-and-suspenders documented in `deploy/`/RUNBOOK
(`fs.suid_dumpable=0`, systemd-coredump `Storage=none`), but the in-code re-assert
is the real fix.

## Residual (test)
A regression test that actually runs privdrop needs root (privdrop is root-only),
so the nextest canary cannot drive the setuid path; the **runtime self-verify**
(`get_dumpable()==false` fail-closed inside `drop_to`) is the guard that fires in
production, and the `coredump-check` mode asserts the readback for the no-privdrop
path.
