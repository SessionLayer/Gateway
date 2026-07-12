# F-lockfeed-shutdown-spin-1: dropped shutdown sender could busy-spin the feed task
- Severity: low
- Status: Verified-Fixed
- Area: ssh-lockfeed

## Observation (T3: reliability)
If the shutdown `watch` sender were ever dropped without sending `true`,
`shutdown.changed()` returns Err immediately-forever; the `select!` arms only
returned on `*borrow()==true`, so the loop would busy-spin a core. Not reachable
today (main.rs always sends true; tests keep the sender alive) but fragile.

## Fix
Both `select!` shutdown arms now treat a `changed()` Err as shutdown (`res.is_err()
|| *shutdown.borrow()` → return).
