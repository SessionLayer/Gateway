# F-fwd-reverse-stale-bindings-1: reverse dispatcher lock-matched against a frozen bindings clone
- Severity: low
- Status: Verified-Fixed
- Area: redteam

## Summary (T5: redteam-auditor)
`ReverseDispatcher.bindings` was an owned `LockBindings` clone frozen at
inner-leg establishment. The re-auth path live-updates the session's bindings via
`SessionControl::update_bindings` (a node relabel can drift `node_labels` /
`allowed_logins` mid-session), and the dispatcher already shared
`grant_expiry`/`lock_set`/`abort` as live handles (F-fwd-reverse-expiry-1) — but
not `bindings`, an incomplete version of that same fix. A lock targeting the
NEW facet (e.g. `env=prod` after a dev→prod relabel) correctly refused new MAIN
channels but not new `forwarded-tcpip`/x11 REVERSE channels, which were gated on
the stale clone. Only label/login drift is affected (identity/group/node_id/
principal cannot drift mid-session).

## Fix
`SessionControl::shared_bindings()` exposes the live `Arc<Mutex<LockBindings>>`;
the dispatcher now holds that (not a clone) and lock-matches against it per
reverse open, guard scoped so it is never held across an await. locks.rs /
forward.rs / handler.rs. Verified by mechanism-sharing: the dispatcher now reads
the same `Arc<Mutex<LockBindings>>` the re-auth path writes and the registry's
`matches()` reads, so the existing lock/teardown suites cover the shared
mechanism; no new E2E (a relabel-mid-session harness — CP stub re-issuing a
drifted signed context mid-session — is future-session work, same note as
F-fwd-unsolicited-reverse-1).
