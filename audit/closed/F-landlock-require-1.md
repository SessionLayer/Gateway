# F-landlock-require-1: Gateway could not REQUIRE Landlock; silently degraded to no-fs-confinement
- Severity: medium
- Status: Verified-Fixed
- Area: hardening

## Context (S23 red-team panel A7)

The Agent has `--require-full-landlock` to refuse startup unless Landlock is fully
enforced. The Gateway — its own module doc calls it the platform's "largest blast
radius" plaintext-SSH MITM — had no equivalent: on a kernel without Landlock it ran
with NO filesystem confinement and only a warning (`landlock_fs.rs`
`NotEnforced → warn + continue`). seccomp IS fail-closed on the Gateway (apply error
aborts), so this gap was Landlock-specific. The §15 accepted-risk degrade should be
an operator CHOICE for the highest-value component, not forced.

## Root-cause fix

Added `landlock.required: bool` to `LandlockConfig` (default off — best-effort degrade
preserved). When set, `enforce_required(required, ruleset)` bails (fail closed) unless
`RulesetStatus::FullyEnforced`, mirroring the Agent. Factored into a pure helper so the
decision is unit-testable without a Landlock-less kernel.

## Regression test

`landlock_fs.rs::tests::required_fails_closed_unless_fully_enforced` —
`(required=true, NotEnforced|PartiallyEnforced) → Err`; `(true, FullyEnforced) → Ok`;
`(false, *) → Ok`.
