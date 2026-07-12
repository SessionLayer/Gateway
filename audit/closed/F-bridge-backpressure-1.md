# F-bridge-backpressure-1: node→client bridge direction has no end-to-end flow control (unbounded buffering)
- Severity: medium
- Status: Verified-Fixed
- Area: bridge

## Observation (T3: protocol reviewer)
The byte bridge is asymmetric with respect to backpressure:

- **outer→inner (client → node): correct.** `SshHandler::data` writes via the inner
  `ChannelWriteHalf::data(...).await` (`handler.rs:890`). russh's write half blocks on
  the node's channel window (`channels/mod.rs` `data_bytes` waits on the shared
  `WindowSizeRef` notifier). Because the outer `data` callback runs on russh's server
  session task, awaiting there stops draining the outer socket, so a slow node
  backpressures the client. Good.

- **inner→outer (node → client): NOT flow-controlled.** `pump_inner_to_outer`
  (`bridge.rs:59`) reads the node's output with `inner.wait().await` and relays it with
  `handle.data(outer, data).await` (`bridge.rs:69`). Two russh internals defeat
  end-to-end backpressure:
  1. The **inner (client) receive window is auto-replenished on packet receipt**, not on
     consumption: on every `CHANNEL_DATA` the client calls `adjust_window_size(..)` and
     emits `CHANNEL_WINDOW_ADJUST` back up to `config.window_size`
     (`client/encrypted.rs:453-464`, `session.rs:285`). The node is therefore never
     throttled by how fast the pump/outer client consume.
  2. The **outer (server) side buffers overflow without bound.** `Handle::data` enqueues
     to a bounded (`event_buffer_size = 10`) mpsc, but the session run loop drains it into
     `ChannelParams.pending_data` — a `std::collections::VecDeque` with **no cap**
     (`session.rs:596-598`, `lib_inner.rs:508`). Once the outer client's channel window is
     exhausted, `data_with_writer` pushes every subsequent chunk straight to
     `pending_data`, `self.write` stays empty, the socket flush is a no-op, the mpsc keeps
     draining, and `handle.data(...).await` in the pump **never blocks**.

Net: a fast node + a slow/stalled outer client (the client simply stops reading its
socket) makes the Gateway accumulate node output without bound in `pending_data`. A
single authorized session running high-rate output (`cat /dev/zero`, `yes`, `tar c /`,
a large SFTP GET) while not draining the client socket grows Gateway process memory
until OOM. Because the Gateway is the shared **Tier-0 data plane**, that OOM takes down
**every co-tenant session** on the instance — a multi-tenant availability failure
reachable by one low-privilege authenticated user.

This is exactly the "can a fast side overrun a slow side?" question: outer→inner is
safe, inner→outer is not. It also leaves this session's own stated requirement unmet —
SESSION.md §8 lists "bridge buffer sizes / backpressure policy" as an open value to set,
and §1.2 / the guardrails require bounding buffers for Tier-0. The 2 MiB inner
`window_bytes` and the depth-10 outer mpsc do **not** bound total memory; `pending_data`
does the actual buffering and is unbounded.

## Impact
Authenticated-user, single-session memory-exhaustion DoS of the Tier-0 Gateway with a
cross-tenant blast radius (OOM kills all sessions on the instance). No plaintext leak;
availability only. (Consider escalating to high if multi-tenant availability is a hard
NFR — filed medium because it requires an authorized session and the underlying
unbounded queue is a russh behavior the bridge must compensate for.)

## Fix (at the bridge — do not weaken host-verify/cert paths)
Bound the in-flight node→client bytes so the pump stops reading the inner channel when
the outer client is not draining, re-coupling the node's send rate to the client's
receive rate. Options, in order of preference:
- Add a per-channel byte budget (e.g. a `tokio::sync::Semaphore` sized to ~the outer
  window / a fixed cap). Acquire N permits before `handle.data(outer, chunk)`; release
  them when the client's window reopens. russh exposes the drain point via
  `Session::has_pending_data(channel)` (`server/session.rs:880`) — poll/await it (or the
  outer channel's window) before pulling the next inner chunk.
- Or drive the outer direction through the **outer** `Channel`/`ChannelWriteHalf` (the
  handler currently drops `_channel` in `channel_open_session`) and gate the pump on its
  writable window, mirroring the correct outer→inner path.
- At minimum, cap total buffered bytes per channel and pause `inner.wait()` (stop
  replenishing / stop reading) once the cap is hit, so TCP backpressure reaches the node.

Add a regression test: authorized session, node emits a large stream, outer client reads
slowly/not at all → assert Gateway RSS / buffered bytes stay bounded (and the node stalls
rather than the Gateway growing).

## Resolution (Verified-Fixed)
node→client now drives the **outer channel's write half** (`data_bytes`/`extended_data`), which blocks on the client's channel window — the node is throttled to the client's receive rate (backpressure reaches the node via the bounded inner receiver → un-replenished inner window). Replaces the unbounded `Handle::data` buffering. The outer→inner direction was already correctly backpressured. Full E2E re-verified green after the change.
