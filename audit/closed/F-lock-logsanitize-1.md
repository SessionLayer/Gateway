# F-lock-logsanitize-1: unsanitized CP-supplied lock_id in operator logs
- Severity: low
- Status: Verified-Fixed
- Area: logging

## Observation (T3: security)
The lock feed logged `%lock_id` raw, unlike the handler which sanitizes CP-supplied
identifiers — a breached CP could inject control/bidi chars into operator logs.

## Fix
`sanitize()` is now `pub(crate)` and applied to `lock_id` at all sites (lockfeed
Added/Removed + both handler lock logs). Verified by security re-review.
