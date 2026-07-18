# F-bridge-output-teardown-1: lock/expiry teardown did not stop node→client OUTPUT for a non-strict (unrecorded) session
- Severity: medium
- Status: Verified-Fixed
- Area: ssh

## Context (S23 red-team panel A1 — Tier-0 MITM)

A lock/expiry teardown (`SessionControl::terminate`) flips the shared
`abort: Arc<AtomicBool>` and spawns the async disconnect. Both bridge directions
must observe the flag before the disconnect lands. The INPUT half checks
`self.session_abort` directly (`handler.rs::data`, the S10 fix). The OUTPUT half
(`bridge.rs::pump_inner_to_outer`) checked only `tap.should_abort()` — but the
non-strict degraded path (`recorder.strict=false` + a recording-setup failure)
substitutes `disabled_recorder()` = `NullSessionRecorder`, whose `should_abort()`
uses the trait default `false`. So for a degraded/unrecorded session the output pump
never saw the lock and kept forwarding in-flight node stdout to the just-locked user
for the whole disconnect-propagation window (widened on the 2-core box).

Defeats §8.4 deny-wins / immediate-teardown + FR-LOCK-1/2. A distinct NEW instance of
the S10 "every read site must observe the SAME predicate" class the S10 fix (input
half) did not cover.

## Root-cause fix

Thread the shared session-abort `Arc<AtomicBool>` into `pump_inner_to_outer` and
check it DIRECTLY (factored into `should_stop(&abort, tap)` = `abort.load() ||
tap.should_abort()`), symmetric with the input path — not dependent on a pluggable
recorder object surfacing the flag. The caller passes `self.session_abort` (set in
`ensure_registered` before any channel bridges).

## Regression test

`bridge.rs::tests::output_pump_stops_on_shared_abort_even_when_tap_never_aborts` — a
tap that always answers `should_abort()==false` (the disabled recorder): with the
shared flag unset the pump flows; once the flag is set (teardown) `should_stop` MUST
return true. Fails pre-fix (tap-only == false → kept forwarding). Plus a strict-tap
control (`output_pump_stops_on_recorder_tap_abort`).
