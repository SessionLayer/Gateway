# F-lock-input-teardown-1: lock teardown did not stop client→node plaintext
- Severity: high
- Status: Verified-Fixed
- Area: ssh-lock-teardown

## Observation (T3: redteam + security + reliability + protocol — 4-way convergence)
`SessionControl::terminate()` flips the shared `abort` flag and spawns an async
`Handle::disconnect()`. The node→client pump honoured it (`should_abort()` =
`torn || abort`), but the client→node input callback `Handler::data` gated on
`rec.is_torn_down()`, which reads ONLY the recorder's strict-mode `torn` flag, not
the shared `abort`. So after a lock/expiry teardown fired (`abort=true, torn=false`)
the client's keystrokes/commands kept being forwarded to the node until the spawned
disconnect landed — a locked attacker could fire-and-forget a command
(`curl … | sh &`, `rm -rf`) at the exact moment of being cut off. Worse on the
non-strict `disabled_recorder()` path (its `should_abort()` is always false).

## Fix
`data()` now returns early if the shared `session_abort` flag is set AND gates the
recorder path on `rec.should_abort()` (was `is_torn_down()`). This covers the strict
recorder (`torn`), the lock/expiry abort (`session_abort`), and the non-strict
recorder (which shares only `session_abort`). Verified by security + redteam re-review.
