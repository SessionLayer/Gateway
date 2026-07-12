# F-channelcap-1: no per-connection channel cap — unbounded pump tasks / node channels / window buffers
- Severity: medium
- Status: Verified-Fixed
- Area: reliability

## Risk (T3: reliability reviewer)
A single authorized connection can open an unbounded number of session channels.
`channel_open_session` always `reply.accept()`s (handler.rs:804-812) and each
subsequent shell/exec/subsystem request drives `start_channel`, which per channel:

- spawns a **detached** `pump_inner_to_outer` task (`tokio::spawn`, handler.rs:500)
  with no handle retained and no cap;
- opens a channel on the **node** (1:1 amplification, innerleg.rs:157);
- inserts into the `writers`/`pty` maps (handler.rs:499, 827) — unbounded;
- reserves up to `window_bytes` (**default 2 MiB**, config.rs:141) of flow-control
  buffer per direction when the far side is slow.

russh does not bound the channel count (server `Config` has `channel_buffer_size`
but no max-open-channels; russh-0.62.2). There is no counter in `SshHandler`. So
`N` channels ⇒ `N` tasks + `N` node channels + up to `N × ~4 MiB` buffered — a
single session (or a compromised-but-enrolled account) can OOM the gateway or
exhaust node channels, restarting the gateway and dropping every other user on it.

This is distinct from the S10 **concurrent-session policy limit** (FR-SESS-3,
per-user, CP-backed) that §1.2 defers: this is a **local Tier-0 resource bound**
("one connection cannot open 10 000 channels"), which §8 asks this session to set
("bound buffers/…").

Secondary: because pump tasks are detached and only terminate when the inner
channel closes (bridge.rs:65-101), a channel the client closes but whose node side
never sends `Close` leaves its pump parked in `inner.wait().await` for the whole
connection lifetime (the shared inner client's idle timer keeps resetting on other
channels' traffic). Many such channels accumulate leaked-until-disconnect tasks.

## Fix
- Add a per-connection open-channel cap (e.g. `max_channels_per_connection`,
  fail-closed default ~16-32). Refuse `channel_open_session` past the cap with
  `ChannelOpenFailure` / reject the shell/exec request with a §7.1 generic denial,
  and log `outcome="channel_cap"`.
- Track spawned pump `JoinHandle`s (or a channel→AbortHandle map) so channels are
  torn down deterministically on connection end / outer channel close rather than
  relying solely on inner-close propagation; abort on `channel_close`.
- Document the cap alongside the other §8 open values.

## Verification (suggested)
A client opening `cap + 1` channels is refused on the last; opening then closing
`M` channels leaves zero live pump tasks after the outer channels close (no
leak-until-disconnect).

## Resolution (Verified-Fixed)
Added `inner.max_channels_per_connection` (default 16); `channel_open_session` rejects past the cap (`outcome=channel_cap`). Per-channel pump `JoinHandle`s are tracked and **aborted** on `channel_close` and in the handler `Drop` — deterministic teardown, no leak-until-disconnect.
