# F-privdrop-dumpable-window-1: DUMPABLE re-enabled window between setuid and the re-assert
- Severity: low
- Status: Verified-Fixed
- Area: hardening

## Context (S23 red-team panel A7)

`privdrop.rs`: `setuid` resets `PR_SET_DUMPABLE` to `suid_dumpable` (~1); the S21 fix
re-asserted `PR_SET_DUMPABLE=0`, but only AFTER the uid/euid verify + the setuid(0)
reversibility check. In that ~4-syscall window DUMPABLE=1, and pipe `core_pattern`
handlers (systemd-coredump/apport) ignore `RLIMIT_CORE` — so a crash there on a
systemd host could dump a core carrying SSH plaintext / the inner key. Not practically
triggerable (no allocation / attacker input in the window), hence low.

## Root-cause fix

Moved `set_dumpable(false)` to IMMEDIATELY after `setuid(uid)`, before the verify /
reversibility checks — shrinking the dumpable window to a single instruction. The
subsequent reversibility `setuid(0)` fails (no cred change → dumpable stays 0), and
the `get_dumpable()==0` fail-closed readback still confirms the final state.

## Regression test

Race is not deterministically testable; enforced by code-order + the existing
`hardening_e2e.rs` post-privdrop `DUMPABLE=false` assertion + the
`forced_crash_produces_no_core_with_secret` canary (both continue to hold). Comment
invariant documents the ordering requirement.
