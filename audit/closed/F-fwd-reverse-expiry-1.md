# F-fwd-reverse-expiry-1: reverse-forward / X11 channels not time-boxed by grant_expiry
- Severity: medium
- Status: Verified-Fixed
- Area: authz

## Summary (T5: redteam-auditor)
The Session 29 `ReverseDispatcher` (node-initiated `forwarded-tcpip` / `x11`
channels for `ssh -R` / `-X`) gated each open on the per-direction capability,
the shared abort flag, and the (connect-time) lock-set — but NOT on the signed
`grant_expiry`. The local-forward path enforces `grant_is_expired` in
`local_recheck_value` step (b); the reverse path did not. In the default
`RunToTtl` mid-session-expiry mode `arm_expiry` installs no teardown and never
sets `session_abort`, so after the signed grant expired a still-bound `-R`
listener (or X11) on the node kept producing reverse channels that the Gateway
relayed to the client — the grant time-box was silently not enforced on this
surface (asymmetry with the "no new privileged channel-open after grant_expiry"
invariant, Part F / §8.4).

## Fix
`ReverseDispatcher` now carries the session's `grant_expiry` as a shared
`Arc<AtomicI64>` (updated in place by `ensure_registered` and by the
`local_recheck_value` re-authorize path, so an extended/shortened grant
propagates) plus the conservative skew, and `handle_open` refuses any reverse
open once `grant_is_expired(now, grant_expiry, skew)` — the same time-box the
local path applies. Hard Locks still tear the whole session (incl. reverse
tunnels) down via the shared `session_abort`; this closes the RunToTtl gap.
`forward.rs` `handle_open`; `handler.rs` `ensure_inner`/`ensure_registered`/
`local_recheck_value`.
