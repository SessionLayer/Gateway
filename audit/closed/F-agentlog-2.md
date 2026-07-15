# F-agentlog-2: the agent fast-fail log line does not sanitize peer-supplied text at all
- Severity: low
- Status: Verified-Fixed
- Area: agentlog

## Summary

`DialBackResult.error` — a free-text string straight off the wire from the Agent — is
logged **raw**, with no `sanitize()` call. Every other peer-supplied field on this
surface is sanitized, including the directly analogous `WireError.message` fifteen lines
below.

Distinct from **F-agentlog-1**, which is about `sanitize()` being *incomplete* (Cc but
not Cf). This call site does not call it at all, so even C0 controls — newlines, ANSI
CSI — pass straight through.

## Location

`gateway-core/src/agent/server.rs:630`

```rust
MsgType::DialBackResult => {
    let result = wire::as_dial_back_result(&frame)?;
    if !result.accepted {
        tracing::info!(node = %sanitize(&peer.node_name), error = result.error,   // <- raw
                       "agent refused a dial-back (fast-fail)");
```

Contrast `server.rs:645`, the correct pattern:

```rust
MsgType::Error => {
    let err = wire::as_wire_error(&frame)?;
    tracing::info!(agent_id = %sanitize(&peer.agent_id), code = err.code,
                   message = %sanitize(&err.message), "agent reported a wire error");
```

## Impact

Wire contract §8 is explicit: *"Peer-supplied error text is untrusted: log it escaped."*
A compromised or merely buggy Agent can inject newlines and ANSI escape sequences into
the Gateway's operator log — log forging (fabricating a plausible extra log line) and
terminal-escape injection into an operator's `journalctl`/`less`. The Agent is a lower
trust tier than the Gateway by construction, so its text is exactly the input this rule
exists for.

Rated low because the reachable payload is bounded (an Agent must first hold a valid,
unlocked mTLS identity and a live control channel) and the impact is on log integrity,
not on the session path.

## Fix

```rust
error = %sanitize(&result.error),
```

…and fix `sanitize()` itself per F-agentlog-1 (strip Cf/bidi, not just Cc), so the two
fixes compose. A `#[test]` asserting that no `tracing` call on this surface takes a
peer-supplied `String` without `sanitize` would be nice but is hard to express; instead,
add the fast-fail case to the existing `peer_error_text_is_sanitized_before_logging` test
(`server.rs:923`).

## Resolution — Verified-Fixed (with a correction)

Correction to the finding's premise: `DialBackResult.error` is the **enum** `DialBackErrorCode`
(generated as `i32`), not a free-text string, so the specific newline/ANSI injection it
describes was not actually reachable via that field — the raw value logged was an integer.

The §8 principle is nevertheless applied: `server.rs` now renders the fast-fail error as its
**typed enum variant** (`DialBackErrorCode::try_from(..)`, a closed set), so no raw wire value
transits the line, and `node` remains sanitized. No peer-supplied *text* is logged on this
line. (The genuinely attacker-authored `WireError.message` was already sanitized; F-agentlog-1
hardened that `sanitize`.)

**Proving:** covered by the fast-fail path in the dial/transport suites; the enum rendering is
type-checked (only `DialBackErrorCode` values are representable).
