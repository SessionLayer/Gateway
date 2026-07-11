# F-cpauth-serial-1: CP connect must not serialize behind one mutex
- Severity: medium
- Status: Verified-Fixed
- Area: reliability

## Risk (T3: reliability reviewer, silent-server repro)
`CpAuthClient::channel()` held the client-wide `tokio::sync::Mutex` guard **across
`factory.connect().await`**. With one shared client, on a CP partition/hang every
connection serialized behind a single full-`connect_timeout` connect, each camping a
Tier-0 slot → accept stall.

## Resolution (Verified-Fixed)
- The connect is now performed **without holding the channel lock**: fast-path
  read under the lock, then `factory.connect().await` outside it, then a
  double-checked insert (another task may have cached one meanwhile). Concurrent
  cold-cache connects proceed in parallel and each is independently bounded by
  `connect_timeout`; they no longer serialize.
- A short **circuit breaker** (`BREAKER_COOLDOWN`, 1s): a failed connect records an
  `Instant`; subsequent `channel()` calls within the cooldown return
  `CpError::CircuitOpen` immediately (fail fast) instead of each attempting a full
  connect — so a known-down CP fails queued calls fast and recovers within ~1s.

## Evidence
`cpauth.rs` (`channel`, `BREAKER_COOLDOWN`). `CircuitOpen`/timeout/transport all
classify as `is_cp_down()` (unit-tested), so a partitioned CP fails closed as
"service temporarily unavailable" rather than stalling accept. The reliability
reviewer re-runs the silent-server repro.
