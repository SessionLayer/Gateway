# F-fwd-reverse-hol-block-1: reverse dispatcher could head-of-line-block the inner leg
- Severity: high
- Status: Verified-Fixed
- Area: reliability

## Summary (T5: reliability-engineer)
`ReverseDispatcher::run` processes node-initiated reverse opens serially and
awaited the OUTER channel open (`channel_open_forwarded_tcpip`/`channel_open_x11`)
with no timeout. An unresponsive/malicious real SSH client (TCP backpressure)
could hang that await, stalling the dispatcher loop; the `mpsc::channel(32)`
would then fill and `InnerHandler::server_channel_open_{forwarded_tcpip,x11}`
would block on `tx.send(...).await`. Those callbacks run on the inner russh
client's run loop, so blocking them stalls delivery for EVERY inner channel —
including the interactive session — not just forwards.

## Fix
Two changes: (1) the inner-leg reverse callbacks now `try_send` (never `.await`)
— a full queue sheds the reverse open (the accepted inner channel drops/closes)
instead of blocking the inner run loop; (2) the dispatcher wraps the outer
reverse-channel open in `tokio::time::timeout(op_timeout, …)` so a stalled
client cannot hang the loop. `innerleg.rs` `InnerHandler`; `forward.rs`
`ReverseDispatcher::handle_open`.
