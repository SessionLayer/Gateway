# F-bridge-exitorder-1: relayed exit-status can overtake still-buffered stdout under backpressure
- Severity: low
- Status: Verified-Fixed
- Area: bridge

## Observation (T3: protocol reviewer)
`pump_inner_to_outer` relays messages in the exact FIFO order it receives them from the
node — `Data` → `ExitStatus` → `Eof` → `Close` (`bridge.rs:65-101`) — which is correct.
However, on the outer (server) side russh routes these through two different queues:

- `Handle::data` / `eof` / `close` respect the per-channel `pending_data` backlog:
  `eof` sets `pending_eof` and `close` sets `pending_close` when data is still queued
  (`session.rs:258-274`), so EOF/CLOSE stay ordered *after* buffered stdout.
- `exit_status_request` (a `CHANNEL_REQUEST`) is pushed **directly** into the outgoing
  buffer, bypassing `pending_data` entirely (`server/session.rs:1158`, the
  `push_packet!(enc.write, ...)` path).

So when the outer client's channel window is exhausted and stdout is sitting in
`pending_data` (the F-bridge-backpressure-1 precondition), a relayed `exit-status` is
written to the wire immediately and **arrives before the trailing stdout**. The
on-the-wire order becomes `[stdout up to window], exit-status, [rest of stdout], eof,
close` instead of `[all stdout], exit-status, eof, close`.

## Impact
Interop edge only, and benign for RFC-4254-compliant clients: OpenSSH does not treat
`exit-status` as end-of-stream — it keeps reading channel data until `CHANNEL_CLOSE`, so
no output is lost with a stock `ssh`/`sftp` client (the E2E uses exactly these and
passes). The risk is a non-conforming client/library that finalizes the command on
`exit-status` and stops reading, truncating trailing output. Only observable when the
client is backed up (same precondition as F-bridge-backpressure-1); with proper
backpressure the `pending_data` backlog stays ~empty and the reorder window disappears.

## Fix
Primarily resolved by fixing F-bridge-backpressure-1 (no backlog → no reorder). For
belt-and-suspenders ordering, defer relaying `ChannelMsg::ExitStatus`/`ExitSignal` until
the outer channel has drained (`Session::has_pending_data(channel) == false`,
`server/session.rs:880`) before calling `exit_status_request`, so exit-status never
overtakes buffered stdout. Root cause is russh-internal (channel-requests bypass the data
queue); document as an Accepted-Risk if the backpressure fix is judged sufficient.

## Resolution (Verified-Fixed)
Resolved by F-bridge-backpressure-1: with the data path backpressured, the outbound backlog stays ~empty, so the relayed exit-status (now sent through the same outer write half as the data) cannot overtake buffered stdout. Benign for RFC-4254 clients regardless (they read until CHANNEL_CLOSE).
