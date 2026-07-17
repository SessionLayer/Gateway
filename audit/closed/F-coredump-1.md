# F-coredump-1: process coredumps could snapshot live SSH plaintext / keys
- Severity: medium
- Status: Verified-Fixed
- Area: secret-hygiene

## Risk
The Gateway holds SSH session plaintext and, transiently, the inner private key.
A crash (SIGSEGV/SIGABRT/panic-abort) while a secret is live could snapshot it
into a core file — the systemic exposure the S18 zeroize findings
([[F-innerkey-zeroize-1]], [[F-recorder-plaintext-zeroize-1]], [[F-zeroize-1]])
named "S18 Tier-0 memory hardening" as their compensating control.

## Resolution (Verified-Fixed)
`hardening::coredump::disable` sets two independent controls at startup —
**before any listener binds or any secret is handled**, so it covers the whole
process lifetime and is inherited by every thread:
- `PR_SET_DUMPABLE = 0` (via `nix::sys::prctl::set_dumpable`) — the kernel
  produces no core for the process at all, regardless of `core_pattern` (so even a
  `core_pattern` pipe to systemd-coredump/apport receives nothing — pipe handlers
  ignore `RLIMIT_CORE`, so this is the ONLY effective gate for them), and a non-root
  `ptrace`/`/proc/pid/mem` attach is refused as a bonus. **NB:** `setuid` in the
  privilege drop RESETS this flag (kernel `commit_creds`), so it is **re-asserted +
  verified fail-closed inside `privdrop::drop_to`** after the drop — see
  [[F-coredump-privdrop-reset-1]] (CWE-528); without that re-assert the whole
  guarantee is void on a bind-`:22`-then-drop deployment;
- `RLIMIT_CORE = 0` (via `nix::sys::resource::setrlimit`) — belt-and-suspenders.

Config: `hardening.disable_coredumps`, **default on** (low-risk, directly protects
secrets — unlike the opt-in sandbox steps). Wired first in `main::run`.

## Automated proof
`gateway/tests/hardening_e2e.rs`:
- `coredumps_disabled_rlimit_zero` — after `disable`, `RLIMIT_CORE` reads back 0
  (deterministic).
- `forced_crash_produces_no_core_with_secret` — a canary subprocess writes a unique
  plaintext marker to memory, enables core dumps, applies the real `disable`, then
  crashes; the test asserts SIGABRT death and that no core file carrying the marker
  is produced. A negative control (no `disable`) confirms the grep can catch a leak
  when the host `core_pattern` writes a local file.

## Residual
Swap is a separate exposure the coredump controls do not cover; it is bounded by
the prompt `Zeroizing` scrub of plaintext and mitigated operationally by
disabling/encrypting swap on sensitive fleets (RUNBOOK / `deploy/`).
