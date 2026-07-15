# F-renewstorm-1: the renew-ahead floor collapses to zero when the issued certificate is already expired — busy-renew storm survives the S14 fix
- Severity: high
- Status: Verified-Fixed
- Area: renewstorm

## Summary

Session Fourteen ported the S12 Agent "renew-delay floor" to the Gateway to stop the
busy-renew spin. The floor closes the trigger the Agent hit (`base == 0`) but leaves a
second trigger wide open (`remaining == 0`), and the new loop-level regression test does
not exercise it. The result is an unbounded `RenewGatewayIdentity` storm — **reproduced
at 40 generations burned in 2 seconds from a single Gateway.**

## Location

`gateway-core/src/identity.rs:599-601`

```rust
fn floor_after_renew(base: Duration, remaining: Duration) -> Duration {
    base.max(RENEW_MIN_INTERVAL.min(remaining / 2))
}
```

Applied on the loop path at `identity.rs:717-725` (`RenewAhead::run`, `just_renewed`)
and — the same helper — on the S14 agent-transport serverAuth-cert path via
`identity::reissue_delay` (`identity.rs:609-620`), consumed by
`gateway-core/src/agent/server.rs:288-322` (`spawn_server_cert_renewal`).

## Root cause

The `remaining / 2` cap exists so the floor can "never delay past expiry". But when the
certificate the CP just issued is **already expired from the Gateway's clock**,
`remaining == 0`, so the cap is `0`, so the floor is `0`, so the post-renewal delay is
`0` — and the loop renews back-to-back at RPC rate. Nothing self-limits: the RPC keeps
*succeeding*, because the CP validates the Gateway's client certificate against the
**CP's** clock, not the Gateway's.

Reachable when:
- the Gateway's clock is ahead of the CP's by more than the certificate TTL (NTP
  failure, VM snapshot restore, container clock drift) — Design D32 assumes NTP, and the
  CP backdates only ~5 minutes for skew; or
- the CP is misconfigured with a near-zero certificate TTL.

`validated_window()` (`identity.rs:567`) does **not** catch this: it rejects an inverted
window (`not_after < not_before`), but an already-expired-yet-ordered window
(`not_before <= not_after <= now`) passes and is persisted.

The **serverAuth loop is worse**: `spawn_server_cert_renewal` has no backoff on the
success path (`server.rs:304-310`) — on `Ok` it recomputes the delay and immediately
loops — and each iteration additionally generates a fresh P-256 keypair + CSR
(`issue_server_config` -> `generate_keypair_and_csr`).

## Proof of concept

Local, offline, against the real mock CP. Ran as `gateway-core/tests/zz_review_repro_it.rs`
(removed after the run — reproduce by pasting it back).

`MockCp::builder().cert_ttl(Duration::from_secs(0))` makes `MockState::validity_window()`
(`tests/support/mod.rs:707-712`) return `not_before = now-5, not_after = now` — exactly
modelling "the certificate the CP issued is already expired at our clock".

```rust
#[tokio::test]
async fn repro_renew_storm_when_the_issued_cert_is_already_expired() {
    let cp = MockCp::builder().cert_ttl(Duration::from_secs(0)).start().await;
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    let cred = identity::enroll(&store, &params, &cp.bootstrap_anchors(),
                                &cp.mint_enrollment_token(), "gw-storm2").await.unwrap();
    let renew_ahead = identity::RenewAhead::new(store, /* fraction 2/3, jitter 0.1 */ .., cred);
    let loop_task = tokio::spawn(async move {
        renew_ahead.run(Box::pin(std::future::pending::<()>())).await;
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    loop_task.abort();

    let gens = cp.recorded_generation(&gateway_id).unwrap_or(0);
    assert!(gens <= 1, "BUSY-RENEW STORM: the loop burned {gens} generations in 2 seconds");
}
```

Result:

```
REPRO: generations burned in 2s = 40
BUSY-RENEW STORM: the loop burned 40 generations in 2 seconds
```

40 renewals in 2 seconds, bounded only by loop-back RPC latency.

## Why the S14 regression test did not catch it

`gateway-core/tests/identity_it.rs:289`
(`renew_ahead_loop_does_not_spin_when_the_renew_trigger_is_already_past`) **does** drive
the real loop — that part of the fix is right, and it passes. But it uses
`renew_ahead_fraction: 0.0` with a healthy 3600s TTL, which produces `base == 0` with
`remaining == 3600`, the one case the floor handles. It never produces `remaining == 0`.

Worse, the existing unit test **asserts the bug as correct behaviour**:

- `identity.rs:917-919` — `assert_eq!(floor_after_renew(ZERO, ZERO), ZERO)`
- `identity.rs:929-932` — `assert_eq!(reissue_delay(now, now - 10s, now), Duration::ZERO)`

## Impact

One Gateway with a skewed clock issues ~20 `RenewGatewayIdentity`/sec indefinitely. Each
is a CP DB write **and a generation-counter increment**. Per Design §8.2 the generation
counter is the *clone-detection* primitive, so this does not merely add load — it churns
the security state that drives auto-lock. The serverAuth loop concurrently storms
`IssueGatewayServerCertificate` with a P-256 keygen per iteration (CPU). Neither loop
logs anything to explain itself.

## Fix

Give the floor an absolute lower bound the `remaining` cap cannot erase — renewing 5s
later instead of 0s later costs nothing when the certificate is expired either way:

```rust
/// A certificate that is already expired at issue is a clock/TTL fault, not a schedule.
/// Without an absolute guard the `remaining/2` cap collapses the floor to zero exactly
/// in the case the floor exists for.
const RENEW_SPIN_GUARD: Duration = Duration::from_secs(5);

fn floor_after_renew(base: Duration, remaining: Duration) -> Duration {
    base.max(RENEW_MIN_INTERVAL.min(remaining / 2))
        .max(RENEW_SPIN_GUARD)
}
```

Then:
1. In both loops, emit `tracing::error!` when a freshly-adopted certificate has
   `remaining == 0` — today the operator's only signal that their clock is broken is the
   CP falling over. Add a RUNBOOK entry.
2. Add a loop-level test with `cert_ttl(0)` asserting <=1 renewal in 2s (the PoC above,
   inverted).
3. Fix `floor_after_renew_bounds_a_busy_renew_but_never_delays_past_expiry` and
   `reissue_delay_is_always_floored` — their `ZERO` assertions currently encode the bug.

## Resolution — Verified-Fixed

The floor could still collapse when the freshly-issued certificate had **no remaining
window** (`remaining == 0`): the `remaining / 2` cap drove it to zero and the loop renewed
at RPC rate. Rethought rather than patched (`identity.rs`):

- `floor_after_renew` gains an **absolute `RENEW_SPIN_GUARD` (5 s)** the `remaining / 2` cap
  cannot erase — the post-renewal wait can never reach zero.
- New `PostRenew` / `schedule_after_renew`: an already-expired-at-issue certificate is a
  **terminal, loud condition** (`PostRenew::ExpiredAtIssue`), not a schedule. Retrying
  reissues the same expired cert (the skew persists — the RPC keeps *succeeding* against the
  CP's clock) and burns the generation counter, a §8.2 clone-detection **security** primitive.
  Both loops — `RenewAhead::run` and the S14 serverAuth `spawn_server_cert_renewal` — now
  **stop with a `tracing::error!`** requiring operator action (fix NTP / the CP TTL), a
  deliberate `RepairNeeded`-class stop over an unbounded 5 s-spaced retry (a multi-TTL skew is
  not a transient blip; churning the security counter is worse than pausing renewal).
- The two unit tests that **encoded the bug** (`floor_after_renew(ZERO,ZERO)==ZERO`,
  `reissue_delay(..)==ZERO`) are corrected.

**Proving tests:** `identity::tests::floor_after_renew_never_collapses_to_zero`,
`identity::tests::schedule_after_renew_flags_an_already_expired_cert_as_terminal`, and the
**loop-level** `identity_it::renew_ahead_loop_stops_instead_of_storming_on_an_already_expired_issued_cert`
(`cert_ttl(0)`, asserts <=1 renewal in 2 s — was 40). Cross-repo: the Agent's identical S12
helper is dispatched to ag-engineer2 with the same semantics (spin guard + terminal).
