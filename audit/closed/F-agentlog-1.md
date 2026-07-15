# F-agentlog-1: `sanitize()` strips Cc but not Cf — peer text can still spoof an operator log line; token is Debug-reachable
- Severity: low
- Status: Verified-Fixed
- Area: agentlog

## Summary

Two distinct, cheap-to-fix log/leak hygiene gaps on the agent surface.

### (a) `sanitize()` misses Unicode Cf / separators

`gateway-core/src/agent/server.rs:856-861`:

```rust
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(256).collect::<String>()
}
```

`char::is_control()` is **Unicode category Cc only** (C0/C1). It does not strip:
- `U+202E` RIGHT-TO-LEFT OVERRIDE and the other bidi controls (category Cf) — reorders
  the rendered log line, so an attacker can make a log entry read as something else;
- `U+200B` ZERO WIDTH SPACE and friends (Cf) — defeats grep/alerting on operator logs;
- `U+2028`/`U+2029` LINE/PARAGRAPH SEPARATOR (Zl/Zp) — treated as line breaks by several
  JSON/log pipelines, which is the log-injection primitive the filter exists to stop.

The one genuinely attacker-authored string on this surface is `WireError.message` from the
Agent, logged at `server.rs:645`. A compromised Agent controls it verbatim.

PoC (passes on current code, i.e. the filter is bypassed):

```rust
#[test]
fn sanitize_does_not_strip_bidi_overrides() {
    let sanitize = |s: &str| -> String { s.chars().filter(|c| !c.is_control()).take(256).collect() };
    let out = sanitize("ok\u{202e}dezirohtuanu\u{200b}");
    assert!(out.contains('\u{202e}'), "VULN: RIGHT-TO-LEFT OVERRIDE survives sanitize()");
    assert!(out.contains('\u{200b}'), "VULN: zero-width space survives");
}
```

Also note `gateway-core/src/agent/dial.rs:79-83` logs `node_name` and `lock_id` **without**
`sanitize()`. Both are CP-sourced rather than peer-sourced, so this is consistency /
defence-in-depth rather than a live injection — but it should match the server-side
treatment.

**Fix.** Filter on category, not just `is_control()`, and prefer an allow-list:

```rust
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
                                                    | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}'
                                                    | '\u{feff}'))
        .take(256)
        .collect()
}
```
(or, tighter: keep only `c.is_ascii_graphic() || c == ' '`, since `agent_id`/`node_name`/
`lock_id` are CP-stamped identifiers and a wire diagnostic has no business carrying
anything else). Apply it to the `dial.rs` sites too.

### (b) The live dial-back token is reachable through `Debug`

`DialBackRequest` is prost-generated and derives `Debug`, including its `token: String`
field. `ControlOut` wraps it and **also derives `Debug`**
(`gateway-core/src/agent/registry.rs:18-24`), as do `ControlHandle` and `AgentRegistry`.

No current code path formats them — I grepped; there is no `?out` / `{req:?}` in
non-test code, so **this is latent, not a live leak**. But it means a single future
`tracing::debug!(?out, ..)` in the control loop silently dumps a live single-use
capability into the operator log, and the contract is explicit that the token is "never
logged, never persisted, and never echoed" (§6).

This is the same hazard S9 already closed for `SessionGrant` with a hand-written redacting
`Debug` (there is even a test for it: `session_grant_debug_redacts_token`).

**Fix.** Hand-write `Debug` for `ControlOut` so the token cannot transit it:

```rust
impl std::fmt::Debug for ControlOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The dial-back token is a capability: it goes on the wire and nowhere else.
            Self::DialBack(req) => f.debug_struct("DialBack")
                .field("request_id", &req.request_id)
                .field("node_name", &req.node_name)
                .field("token", &"<redacted>")
                .finish(),
            Self::Superseded => f.write_str("Superseded"),
        }
    }
}
```

Regression test: mirror `session_grant_debug_redacts_token` —
`assert!(!format!("{:?}", ControlOut::DialBack(..)).contains("SLDB1"))`.

## Impact

(a) Operator-log spoofing / alert evasion by a compromised Agent. No effect on
authorization. (b) No current leak; removes a foot-gun that would leak a live capability.

## References

- Contract `agent-gateway-v1.md` §6 ("never logged, never persisted, never echoed"), §8
  (non-disclosure: "Peer-supplied error text is untrusted: log it escaped").
- CWE-117 (Improper Output Neutralization for Logs), CWE-532 (Insertion of Sensitive
  Information into Log File).

## Resolution — Verified-Fixed

Both halves fixed:

- (a) `server.rs::sanitize` now strips the Unicode classes `char::is_control()` misses —
  bidi controls (Cf, incl. U+202E), zero-width/format characters (defeat grep), line/paragraph
  separators (Zl/Zp, new-line forging), and the BOM — via `is_log_unsafe`. Ordinary non-ASCII
  text is preserved (it is a log guard, not an ASCII filter).
- (b) `registry.rs::ControlOut` gets a **hand-written redacting `Debug`** so the dial-back
  token cannot transit `Debug`, mirroring S9's `SessionGrant`.

**Proving tests:** `server::tests::peer_error_text_is_sanitized_before_logging` (RTL override,
zero-width, BOM, line/para separators stripped; accented text kept) and
`registry::tests::control_out_debug_redacts_the_dial_back_token`.
