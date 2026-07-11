# F-epoch-1: CP-supplied epoch could panic + persist-before-validate crash-loop brick (GW-EPOCH)

- Severity: medium
- Status: Verified-Fixed
- Area: identity

## Summary

`identity.rs::epoch_to_systemtime` computed `UNIX_EPOCH - Duration::from_secs((-epoch) as u64)`.
A CP-supplied `not_before/after_epoch_seconds = i64::MIN` overflows `-(i64::MIN)`
→ **panic** (release too — the process runs with `overflow-checks = true`). Worse,
`persist_issued` wrote the manifest to disk *before* `from_manifest` converted the
epochs, so a hostile value was persisted and every subsequent restart `load()`
would panic again → a **permanent crash-loop brick** (violates NFR-2, fail-closed).
`signing.rs::epoch_to_systemtime` had the same overflow.

## Fix

- `systemtime_from_epoch` uses **checked** `checked_add`/`checked_sub` and
  `i64::unsigned_abs()` (which handles `i64::MIN` without overflow) → never panics.
- `validated_window(nb, na)` rejects negative epochs (a pre-1970 validity is
  nonsensical for this system and deterministically rejects the `i64::MIN` PoC on
  every platform), overflow, and an inverted window (`not_after < not_before`) →
  `IdentityError::Corrupt`.
- **Persist-AFTER-validate:** `persist_issued` calls `validated_window(...)?`
  **before** `atomic_write`, so a bad response never reaches disk (no crash-loop).
  `from_manifest` also validates on load (a tampered on-disk manifest fails closed).
- `compute_renew_delay` uses `checked_add` for the trigger instant (out-of-range →
  renew-now, never panic).
- `signing.rs::epoch_to_systemtime` uses checked math clamping to `UNIX_EPOCH`
  (these fields are advisory; the OpenSSH cert carries the authoritative window).

## Verification

New unit tests: `persist_rejects_out_of_range_epoch_and_writes_nothing` (i64::MIN
→ Corrupt, nothing on disk), `load_rejects_out_of_range_epoch_without_panicking`
(tampered manifest → Corrupt, no panic), `inverted_validity_window_is_rejected`,
`compute_renew_delay_does_not_panic_on_extreme_window`. Full gate green.
