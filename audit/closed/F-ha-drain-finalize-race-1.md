# F-ha-drain-finalize-race-1 (L4 residual): FinalizeTracker::drain could return before a force-torn-down session registers its finalize
- Severity: low (data-completeness)
- Status: Verified-Fixed
- Area: ha-drain

## Summary

The L4 fix tears remaining sessions down at the drain deadline via `LiveSessionRegistry::terminate_all()`,
then awaits `FinalizeTracker::drain(grace)`. But `terminate_all()` only SPAWNS the async disconnects;
each session's recorder finalize is registered later, in `SshHandler::drop`
(`finalize_tracker.spawn(rec.finalize())`, which does `count.fetch_add(1)`). `FinalizeTracker::drain`
returns immediately when it samples `count == 0` on its first poll. So a session that EXCEEDS the drain
deadline, when no other finalize is in flight, is sampled at `count == 0` BEFORE its own `Drop` spawns
the finalize → the process exits → a truncated / un-finalized WORM object — exactly what L4 was meant
to prevent.

## Location

- `gateway/src/main.rs` — the drain sequence (`terminate_all()` → `finalize_tracker.drain`).
- Root cause: `gateway-core/src/ssh/recorder/mod.rs::FinalizeTracker::drain` (count==0 early return);
  `gateway-core/src/ssh/handler.rs::Drop for SshHandler` (finalize spawned in the Drop BODY).

## Root cause / impact

`FinalizeTracker::drain` early-returns at `count == 0`; the finalize count is only incremented when the
session's `SshHandler` actually drops. Between `terminate_all()` (spawns disconnect) and that drop there
is latency. With no other finalize in flight, `drain` samples zero and returns before the finalize is
registered. No confidentiality/integrity break — only recording completeness for a session that ran past
the drain deadline.

## Remediation — Verified-Fixed

After `terminate_all()`, wait (bounded, `TEARDOWN_SETTLE_BOUND` = 5s, within the drain deadline) for
`live_sessions.len() == 0` BEFORE `finalize_tracker.drain(grace)`. This is race-free by Rust Drop
ordering: `SshHandler::drop` runs its Drop BODY (`finalize_tracker.spawn`, count++) BEFORE its fields
drop — and the `live_guard: Option<SessionGuard>` field's Drop is what deregisters the session
(`len--`). So `len() == 0` guarantees every over-deadline session's finalize has already incremented the
count; `drain` then sees the true count and awaits the actual uploads.

## Test

`gateway/src/main.rs::drain_blocks_until_in_flight_reaches_zero_then_returns_promptly` proves the
bounded wait the fix reuses genuinely blocks until the tracked in-flight count reaches zero and then
returns promptly (not at the deadline). A faithful live-SESSION variant is not feasible as a unit test —
`SessionControl` requires a real `russh::server::Handle`, which only the Docker E2E provides; the
Drop-ordering guarantee the fix rests on is a language guarantee (Drop body before field drops),
documented at the call site.
