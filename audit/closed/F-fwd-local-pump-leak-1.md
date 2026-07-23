# F-fwd-local-pump-leak-1: local-forward pump handles accumulated unbounded over a long session
- Severity: medium
- Status: Verified-Fixed
- Area: reliability

## Summary (T5: reliability-engineer, independent re-review)
`local_forward_pumps` was a push-only `Vec<JoinHandle<()>>` drained only at
connection Drop — no per-channel removal when an individual `-L` forward closed.
The concurrency cap held (`active_tunnels` was decremented correctly), so not a
capability/security bug, but a long-lived session with a busy `-L` proxying many
short-lived connections (DB/HTTP) accumulated one dead `JoinHandle` per
connection, unbounded, for the life of the SSH connection. Shell/exec/sftp pumps
and the reverse dispatcher both already reaped; local-forward was the one path
missing it. Invisible to the E2E suite (every forward test opens exactly one
`-L` connection).

## Fix
`local_forward_pumps` is now a `tokio::task::JoinSet<()>`; finished bridges are
reaped (`while try_join_next().is_some() {}`) on every new
`channel_open_direct_tcpip`, mirroring the reverse dispatcher's pattern
(`forward.rs` `ReverseDispatcher::run`). Drop-time `abort_all()` keeps
deterministic teardown. `handler.rs`.
