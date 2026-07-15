# F-agentcancel-1: `DIAL_BACK_RESULT` fast-fail cancels a pending dial-back without checking it belongs to the sending agent
- Severity: info
- Status: Verified-Fixed
- Area: agentcancel

## Summary

When an Agent sends `DIAL_BACK_RESULT` with `accepted = false`, the control loop calls
`PendingDialBacks::fail_request(&result.request_id)` with the **peer-supplied**
`request_id` and no check that the named pending dial-back was issued to *this* agent or
*this* node:

`gateway-core/src/agent/server.rs:624-633`
```rust
MsgType::DialBackResult => {
    let result = wire::as_dial_back_result(&frame)?;
    if !result.accepted {
        tracing::info!(node = %sanitize(&peer.node_name), error = result.error, "agent refused a dial-back (fast-fail)");
        inner.deps.pending.fail_request(&result.request_id);   // <- unbound
    }
}
```

`fail_request` (`token.rs:321-332`) resolves `request_id -> jti` across the **whole**
pending map — it is not scoped to the peer — and abandons the entry, which drops the
oneshot sender and immediately fails the waiting connector
(`dial.rs:130` → `NodeConnectError::AgentRefused` → §7.1 "node offline").

So a malicious Agent that knows another session's `request_id` can cancel that session's
dial-back, denying service to an unrelated user/node.

## Why this is info, not a real vulnerability

`request_id` is 96 bits from `OsRng` (`dial.rs:142-147`) and is disclosed **only** to the
owning agent, inside `DIAL_BACK_REQUEST` on that agent's own TLS connection. There is no
oracle that leaks it and no feasible brute force (2^96, and each guess needs a distinct
control-channel frame). A malicious agent can therefore only cancel dial-backs it was
already entitled to refuse.

It is filed because the *authorization* is carried entirely by the unguessability of the
identifier rather than by a check — a capability-by-obscurity pattern that becomes a real
bug the moment `request_id` is shortened, made sequential, logged, or reused for
correlation across components.

## Remediation

Scope the cancellation to the peer that owns it. Give `PendingDialBacks` a peer-bound
variant and use it from the control loop — the pending entry already stores the binding
(`node_name`, `agent_id`), so the check is free:

```rust
/// Abandon by `request_id`, but ONLY if the entry was issued to this agent/node.
/// A control channel must not be able to cancel another agent's dial-back.
pub fn fail_request_for(&self, request_id: &str, agent_id: &str, node_name: &str) {
    let mut inner = self.inner.lock().unwrap();
    let Some(jti) = inner.by_request.get(request_id).cloned() else { return };
    let owned = inner.by_jti.get(&jti)
        .is_some_and(|e| e.binding.agent_id == agent_id && e.binding.node_name == node_name);
    if !owned {
        return;   // not yours to cancel
    }
    if let Some(entry) = inner.by_jti.remove(&jti) {
        inner.by_request.remove(&entry.request_id);
    }
}
```

Call it as `fail_request_for(&result.request_id, &peer.agent_id, &peer.node_name)`.

Regression test: register two agents, mint a dial-back for node A, and assert agent B's
`DIAL_BACK_RESULT` naming A's `request_id` does **not** abandon it (while A's own does).

## References

- CWE-639 (Authorization Bypass Through User-Controlled Key) — the class, not yet the
  exploit.
- Contract `agent-gateway-v1.md` §5 (`DIAL_BACK_RESULT` is a fast-fail for *the* session).

## Resolution — Verified-Fixed

`token.rs`: the production control loop now calls `PendingDialBacks::fail_request_for(request_id,
agent_id, node_name)`, which abandons a pending dial-back **only if its signed binding names the
reporting agent's own `{agent_id, node_name}`**. An agent that learned another session's
`request_id` can no longer cancel it. The unscoped `fail_request` is retained `#[cfg(test)]`
only.

**Proving test:** `token::tests::fail_request_for_only_cancels_the_reporting_agents_own_dial_back`
(a stranger, and a right-agent/wrong-node, are both refused; the true owner succeeds).
