# F-lock-expiry-overflow-1: integer overflow in lock_active expiry math
- Severity: low
- Status: Verified-Fixed
- Area: ssh-lock

## Observation (T3: security)
`lock_active` computed `expires_at_epoch_seconds + skew_secs`; an adversarial
(CP-supplied) `expires_at` near `i64::MAX` overflows — a debug build panics (the
nextest gate runs debug), a release build wraps negative → the lock reads INACTIVE
= fail-open.

## Fix
Use `expires_at_epoch_seconds.saturating_add(skew_secs)`. Verified by security re-review.
