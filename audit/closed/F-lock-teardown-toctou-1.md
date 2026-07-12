# F-lock-teardown-toctou-1: lock-push racing a channel-open could leave a live locked session
- Severity: medium
- Status: Verified-Fixed
- Area: ssh-lock-teardown

## Observation (T3: redteam + security + reliability + protocol)
The per-channel lock check and live-session registration span two structures updated
in OPPOSITE orders: the handler read `lock_set.matching()` BEFORE `ensure_registered`,
while the feed's `Added` did `apply_added_lock` (registry scan) BEFORE `lock_set.add`.
Interleaving (match-read, scan, register, add) let a session pass its lock check
(lock not yet in the set) and register after the scan (missed by teardown) → a live
bridged channel matching the lock that is never torn down (nothing re-scans a live
session on a healthy feed).

## Fix
Both orderings inverted to close the window: (a) the feed `Added` now `lock_set.add`
BEFORE `apply_added_lock` (add-before-scan); (b) the handler re-checks
`lock_set.matching(&bindings)` AFTER `ensure_registered` (register-before-final-check,
step 1.7). With add<scan and register<recheck, every interleaving is caught by either
the feed's scan (sees the registered session) or the handler's recheck (sees the
added lock). Verified by security + reliability re-review (happens-before walk).
