# F-fwd-x11-late-ack-1: a late x11-req (after session start) was falsely ack'd but never relayed
- Severity: low
- Status: Verified-Fixed
- Area: protocol

## Summary (T5: protocol-expert)
`x11_request` replied `channel_success` whenever the `x11` capability was granted,
even if the inner session channel for that ChannelId had already started (shell/
exec already running), in which case the stashed params are never relayed to the
node. OpenSSH always sends x11-req pre-shell so this never triggers in practice,
but a non-conforming client got a false ack instead of an honest refusal.

## Fix
`x11_request` now checks whether the session channel already exists
(`self.writers.contains_key(&channel)`) and, if so, sends `channel_failure`
instead of stashing+acking — an honest "cannot be relayed" rather than a silent
no-op. handler.rs.
