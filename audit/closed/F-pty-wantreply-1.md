# F-pty-wantreply-1: inner pty-req uses want_reply=false, so a node PTY-allocation failure is silently swallowed
- Severity: low
- Status: Accepted-Risk
- Area: pty

## Observation (T3: protocol reviewer)
The outer leg acks the client's `pty-req` immediately in `pty_request`
(`handler.rs:838`, `session.channel_success(channel)`), stashes the params, and later
replays them to the node in `InnerClient::open_channel` with **want_reply=false**:
`channel.request_pty(false, term, col, row, pix_w, pix_h, &modes)` (`innerleg.rs:163`),
then `request_shell(false)` / `exec(false, …)` / `request_subsystem(false, …)`
(`innerleg.rs:169-171`).

Ordering and parameter replay are correct: `channel_open_session` → `request_pty` →
shell/exec is the required RFC-4254 §6.2 sequence, and `term`, dimensions, and the
encoded terminal `modes` are all carried over verbatim, as is `window-change`
(`handler.rs:930`, want_reply=false is mandated for window-change by §6.7 — russh
enforces it). So the **PTY replay itself is protocol-correct**.

The gap is only in failure signalling for `pty-req`. With want_reply=false the node
never sends `CHANNEL_SUCCESS`/`CHANNEL_FAILURE` for the PTY request, so if the node
cannot allocate a PTY (PTY exhaustion, a `ForceCommand`/restricted shell, `PermitTTY no`)
the Gateway does not learn of it — yet it has already told the client the PTY was
allocated. The interactive session then proceeds believing it has a TTY while the node
has none (no job control, broken echo/line discipline). For `shell`/`exec`/`subsystem`
want_reply=false is fine: the Gateway already committed `channel_success` to the client,
and a genuine start failure surfaces as the node closing the channel, which the bridge
relays.

## Impact
Interactive-UX degradation on the (uncommon) node-side PTY-allocation failure; no
security impact and no effect on non-PTY (`exec`) or SFTP sessions. The deliberate
want_reply=false choice (SESSION.md §8) trades this signal for one fewer round-trip.

## Fix
Either (a) request the inner PTY with **want_reply=true** and await the result before
requesting shell/exec — on failure emit a clear channel outcome (or proceed without a
PTY and tell the client) — accepting one extra RTT on interactive opens; or
(b) keep want_reply=false and record this as an Accepted-Risk with the rationale, as was
done for F-cert-local-validation-1. No change needed for exec/shell/subsystem.

## Disposition (Accepted-Risk)
`want_reply=false` on the inner pty-req is the deliberate §8 trade-off (one fewer round-trip). The gap is UX-only on the uncommon node-side PTY-allocation failure (PTY exhaustion / `PermitTTY no`) — no security impact, no effect on exec/SFTP, and a genuine start failure still surfaces as the node closing the channel. Switching pty-req to want_reply=true and awaiting the reply before bridging is a clean follow-up.
