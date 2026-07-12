# F-drain-1: no graceful drain of in-flight bridged sessions; SIGTERM not handled
- Severity: low
- Status: Accepted-Risk
- Area: reliability

## Risk (T3: reliability reviewer)
The accept loop's shutdown branch simply returns (ssh/mod.rs:107-110); the detached
per-connection tasks (ssh/mod.rs:121) are not tracked, drained, or force-closed.
The shutdown future is wired only to **SIGINT/Ctrl-C** (`tokio::signal::ctrl_c`,
main.rs:255-258, 326-328). Two consequences now that the inner leg carries real
user traffic:

- On **SIGTERM** — the signal `docker stop` / Kubernetes termination actually sends
  — no handler is installed, so the Rust default disposition terminates the process
  immediately: every live bridged SSH session is severed mid-stream with no
  cleanup, no `outcome=` record, and no bounded grace.
- On **SIGINT**, the accept loop stops accepting but performs no bounded drain of
  in-flight sessions and no force-close-after-window; behavior depends on whether
  `main` then exits under the still-running connection tasks.

Before S8 there was nothing to drain (the leg stopped at a stub); S8 is the first
session where an ungraceful stop drops live traffic, so this becomes materially
relevant here.

## Fix
- Handle **SIGTERM** as well as SIGINT (`tokio::signal::unix::signal(SignalKind::terminate())`).
- On shutdown: stop accepting, then drain in-flight connections within a bounded
  window (broadcast/`CancellationToken` the connection tasks watch), emit an
  `outcome=` record per severed/drained session, and force-close after the window.
- Document the drain window as a §8 open value and reference it in the deploy
  runbook (preStop hook / stop-grace-period ≥ drain window).

## Verification (suggested)
With one active bridged session, a SIGTERM triggers a bounded drain (session
completes or is force-closed within the window) rather than an immediate hard exit.

## Disposition (Accepted-Risk)
On shutdown the Gateway stops accepting and in-flight bridged sessions drop (their pump tasks abort on handler `Drop`) — inherent to a terminating proxy without session migration. Graceful drain + connection preservation across a Gateway restart is **HA (Session Fourteen)**; a signal-triggered drain window is a clean follow-up at the `run()` shutdown future. No security impact (fail-safe: sessions end, they are not leaked).
