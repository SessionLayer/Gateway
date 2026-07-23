# F-fwd-reverse-txgate-1: inner leg accepted reverse opens even with no reverse capability
- Severity: low
- Status: Verified-Fixed
- Area: reliability

## Summary (T5: reliability-engineer)
`ensure_inner` always handed the inner leg `Some(reverse_tx)`, so `InnerHandler`
`reply.accept()`-ed and enqueued EVERY node-initiated reverse open regardless of
grant; the capability check happened later in the dispatcher and dropped it. A
compromised node could force unbounded accept→enqueue→drop cycles on a session
granted no `-R`/X11.

## Fix
`ensure_inner` now passes `reverse_tx = None` when the grant carries neither
`port_forward_remote` nor `x11`, and spawns no dispatcher; the inner handler then
REJECTS reverse opens at the source (`reverse_tx` is `None`). `handler.rs`
`ensure_inner`.
