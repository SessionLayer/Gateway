# F-agentlock-1: the agent surface's Lock gate fails OPEN when the lock feed cannot confirm the absence of a lock
- Severity: medium
- Status: Verified-Fixed
- Area: agentlock

## Summary

The agent transport decides "is this peer locked?" with `LockSet::matching()` alone and
**never consults `LockSet::healthy()`**. In every state where the pushed deny-feed
cannot confirm the absence of a lock — before the first snapshot arrives (Gateway boot)
or after the CP stream drops — `matching()` returns `None` and the agent is **admitted**:
it registers, and it is issued and can redeem a single-use dial-back capability.

This contradicts contract §8 ("A Lock is honoured on this surface … a locked agent
identity **cannot register and cannot redeem a dial-back**") and the S10 safety spine
("deny fails closed"). The session path, in the *identical* state, fails closed — the
doctrine is spelled out in this very repo at `gateway-core/src/ssh/handler.rs:827`:

> "when the feed is UNHEALTHY it cannot confirm the absence of a lock, so it refuses
> NEW privileged channel-opens (fail closed)"

The agent surface reaches the opposite conclusion from the same signal.

## Location

- `gateway-core/src/agent/server.rs:458-470` — `refuse_if_locked()`; the gate used at
  registration (`run_control`, :541), on every heartbeat tick (:581), and at dial-back
  redemption (`authorize_dial_back`, :759).
- `gateway-core/src/agent/dial.rs:77-85` — the pre-signal gate in `AgentDial::connect`.

Both call only `lock_set.matching(&LockBindings::for_agent(..))`. Neither calls
`lock_set.healthy()` (`gateway-core/src/ssh/locks.rs:194-200`).

## Root cause / data flow

`LockSet` starts `connected=false, locks={}` (`locks.rs:141-150`). `matching()`
(`locks.rs:204`) is a pure lookup over that map — an **empty set is indistinguishable
from "no lock applies"**. `healthy()` is the signal that distinguishes them, and it is
the signal the agent path drops.

The boot race is structural, not theoretical: in `gateway/src/main.rs:364-372`
`LockFeedClientTask::spawn()` is fire-and-forget, and `start_agent_transport()`
(:383) binds and begins accepting immediately. The agent listener therefore serves
peers while the deny-set is still empty and disconnected.

Reachable states where the gate is blind:
- **Boot race.** Gateway restarts; a locked Agent reconnects (it retries with backoff,
  indefinitely — contract §7) before the first `LockFeed` snapshot lands.
- **Feed down.** The CP stream drops (`mark_disconnected()`, `lockfeed.rs:65`); a lock
  raised at the CP during the outage never arrives.

## Proof of concept

Local, offline, no network. Ran as `gateway-core/tests/zz_redcell_poc.rs` (removed
after the run — reproduce by pasting it back):

```rust
/// The exact predicate `server::refuse_if_locked` evaluates for an agent peer.
fn agent_is_refused(locks: &LockSet) -> bool {
    locks.matching(&LockBindings::for_agent(AGENT, NODE)).is_some()
}

#[tokio::test]
async fn boot_race_admits_a_locked_agent() {
    let locks = Arc::new(LockSet::new(30, 30));
    assert!(!locks.healthy(), "the feed cannot confirm anything yet");
    assert!(!agent_is_refused(&locks), "VULN: refuse_if_locked() admits the agent");
    assert!(dial_back_was_signalled(locks).await,
        "VULN: a single-use dial-back capability is minted and signalled to an agent \
         the Gateway cannot confirm is unlocked");
}

#[tokio::test]
async fn a_dropped_feed_admits_a_locked_agent() {
    let locks = Arc::new(LockSet::new(30, 30));
    locks.replace_snapshot(Vec::new(), 1);
    assert!(locks.healthy());
    locks.mark_disconnected();              // the CP stream died
    assert!(!locks.healthy());
    assert!(!agent_is_refused(&locks), "VULN: admitted while the deny feed is down");
    assert!(dial_back_was_signalled(locks).await, "VULN: dial-back still granted");
}
```

`dial_back_was_signalled()` drives the real `AgentDial::connect()` against a real
`AgentRegistry` and asserts a `DIAL_BACK_REQUEST` carrying a live `SLDB1.` token went
out on the control channel.

Result — all pass, i.e. the fail-open is confirmed in both states:

```
running 4 tests
test boot_race_admits_a_locked_agent ... ok
test a_dropped_feed_admits_a_locked_agent ... ok
test control_a_healthy_feed_with_the_lock_present_does_refuse ... ok
test sanitize_does_not_strip_bidi_overrides ... ok
```

The **control** case is the important one: with a healthy feed carrying the lock, both
gates *do* refuse. The gate logic is correct — it is only blind about its own blindness.

Note that every S14 test constructs a *healthy* set on purpose
(`dial.rs:181-185 healthy_locks()` always calls `replace_snapshot`), so the unhealthy
state is untested. That is why this was not caught.

## Impact

A locked agent identity (in practice: an Agent whose credential S12 clone-detection has
auto-locked) can, inside the window, register as the live owner of its node and serve a
dial-back splice. The node also continues to appear **online** until the next heartbeat
tick re-checks (up to `heartbeat_interval_secs`, default 20s).

Honest bounding of the impact — this is why it is medium, not high:
- **Host verification still holds.** A rogue Agent that splices to an impostor `sshd` is
  caught by the Gateway's no-TOFU host-identity check (`hostverify.rs`, unchanged). It
  cannot reach an SSH session it is not entitled to; it can only *carry ciphertext* for
  one it could not have carried had the lock been known.
- **The CP is a second gate.** S12 clone-detection also sets the node `access_lock`, so
  `Authorize` would deny the session and no token would be minted at all — unless the
  lock is scoped to the *agent identity* only.

What is unambiguously broken is the normative invariant: the contract states the lock is
enforced at registration and at every dial-back, and in a reachable, structurally-induced
window it is not. A deny feed that is down must not read as "nothing is denied".

## Remediation

Make the agent gate fail closed on an unconfirmable deny-set, exactly as the session path
does. In `refuse_if_locked` (`server.rs:458`) and the `AgentDial::connect` gate
(`dial.rs:77`):

```rust
fn refuse_if_locked(inner: &Inner, peer: &AgentPeer) -> Result<(), ConnError> {
    // Deny fails closed: an unhealthy feed cannot confirm the ABSENCE of a lock, so it
    // is not evidence that the peer is unlocked (S10 spine; cf. handler.rs:827).
    if !inner.deps.lock_set.healthy() {
        tracing::warn!(agent_id = %sanitize(&peer.agent_id), "lock feed unhealthy; refusing the agent (fail closed)");
        return Err(ConnError::Locked);
    }
    let bindings = LockBindings::for_agent(&peer.agent_id, &peer.node_name);
    ...
}
```

Sequencing matters, so pick the placement deliberately:

- **Dial-back redemption (`authorize_dial_back`, server.rs:759) — gate unconditionally.**
  This is where the capability is actually cashed; refusing here is cheap (the session
  fails to the normal §7.1 "node offline" outcome) and closes the exploitable half.
- **Registration (`run_control`, server.rs:541) — gate too, but note the availability
  cost:** a Gateway whose lock feed is down will refuse *all* agent registrations, so the
  whole agent fleet goes offline while the CP stream is down. That is the correct
  deny-wins tradeoff and it matches "an `OUTBOUND_AGENT` node is then simply offline",
  but it should be a conscious decision. The heartbeat re-check (:581) already re-evaluates,
  so a boot-race registration self-heals within one interval once the feed connects —
  gating registration mainly shortens that window.

Minimum fix to close the security hole: gate **redemption** and the **pre-signal check in
`AgentDial::connect`**. Gating registration as well is the stronger, more consistent posture.

Regression test: the PoC above, with the assertions inverted (`assert!(agent_is_refused(..))`
and `assert!(!dial_back_was_signalled(..).await)`) — it fails on the current code and
passes on the fix. Keep the healthy-feed control case so the fix cannot be a blanket deny.

## References

- Contract `agent-gateway-v1.md` §1, §6 check 7, §8 ("A Lock is honoured on this surface").
- Design §8.4 / D26; FR-LOCK-1/2, FR-CHAN-4.
- CWE-636 (Not Failing Securely / "Failing Open"), CWE-754.

## Resolution — Verified-Fixed

Went beyond the finding's minimum, per the lead's ruling — deny fails closed on an
unconfirmable deny-set at **every** check point, and the boot race is made structurally
impossible:

- `server.rs::refuse_if_locked` (registration, heartbeat, dial-back redemption) and
  `dial.rs::AgentDial::connect` (pre-signal) now **refuse when `lock_set.healthy()` is false**
  — an unhealthy feed cannot confirm the ABSENCE of a lock, exactly as the session path
  concludes from the same signal.
- **Readiness gate:** `BoundAgentTransport::run` does not begin accepting until the lock feed
  delivers its first snapshot (`await_lock_feed_ready`) — a locked agent reconnecting during
  boot is not even handshaked. A feed that never connects means no agent nodes are served
  (they are "offline", §7.1) — the documented, deliberate deny-wins trade.

**Proving tests:** `dial::tests::an_unhealthy_lock_feed_refuses_to_signal_and_mints_no_token`
and `a_dropped_lock_feed_refuses_to_signal`; `agent_transport_it::the_transport_does_not_serve_agents_until_the_lock_feed_is_ready`
and `a_dropped_lock_feed_refuses_new_registration_and_dial_back_redemption`. The existing
healthy-feed tests are the control (the fix is not a blanket deny). The unhealthy-feed harness
variant `Harness::start_unready` is added so this state is no longer untested.
