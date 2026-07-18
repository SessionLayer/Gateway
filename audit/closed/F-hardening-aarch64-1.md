# F-hardening-aarch64-1: Gateway did not compile on aarch64 (seccomp allow-list) — blocks the aarch64 deliverable
- Severity: high
- Status: Verified-Fixed
- Area: hardening

## Context (S23 red-team panel A7 — aarch64 portability, Part B)

`gateway/src/hardening/seccomp.rs` placed `libc::SYS_sendfile` (:148) and
`libc::SYS_fadvise64` (:185) in the COMMON allow-list. libc 0.2.186 defines those
names only for `x86_64-gnu`, NOT `aarch64-gnu` (the generic arm64 syscalls 71/223
exist but libc doesn't bind them). So `cargo build --target
aarch64-unknown-linux-gnu` fails `E0425`. `mod seccomp` is `cfg(target_os="linux")`,
so this broke EVERY arm64 Gateway build regardless of hardening config — defeating
the session's aarch64 support deliverable. Uncaught because neither Gateway nor
Agent CI has an aarch64/cross target. Secondary: `target_arch()` was defined only
for x86_64/aarch64, so the Gateway also failed to compile on any other Linux arch.

## Root-cause fix

- Moved `SYS_sendfile` + `SYS_fadvise64` into the `#[cfg(target_arch="x86_64")]`
  extend block. The Gateway uses `splice` for the byte bridge (never `sendfile`) and
  issues no `posix_fadvise`, so on aarch64 they are simply unlisted → EPERM under the
  EPERM-default (harmless), and on x86_64 behaviour is unchanged.
- Added a `#[cfg(not(any(x86_64, aarch64)))]` stub `target_arch()` + an `install()`
  early fail-closed bail on unsupported arches (mirrors the Agent's runtime bail), so
  the crate now compiles on any Linux arch and a build for an unsupported arch aborts
  rather than running unfiltered.

## aarch64 support statement (Part B)

- **Agent: SUPPORTED** on aarch64-gnu (arch-parameterized allow-list; every non-gated
  `SYS_*` verified present on aarch64; runtime fail-closed fallback). Pending
  on-hardware validation.
- **Gateway: now compiles + is aarch64-clean** after this fix (all other constants
  verified present; `target_arch()` maps aarch64). Pending on-hardware validation.
- Landlock net-egress needs kernel ≥6.7 on arm64 (same as x86_64).

## Regression test

Recommended CI addition (documented for the operator): `cargo check --target
aarch64-unknown-linux-gnu` in the Gateway + Agent gates (via `cross` or the target +
a cross linker) — catches this and future arch drift. Host is x86_64 so no on-host
arm64 build proof exists; the fix is verified by static analysis of the libc bindings
+ the (green) x86_64 `cargo check --all-targets`.
