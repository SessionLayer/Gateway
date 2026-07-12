# F-lock-reauth-drift-1: live-session teardown matched stale bindings after a re-authorize
- Severity: medium
- Status: Verified-Fixed
- Area: ssh-lock-teardown

## Observation (T3: protocol reviewer)
`ensure_registered` registered the `SessionControl` with the FIRST authorize's
bindings, once. When `decision_ttl` elapsed, `local_recheck` re-ran `decide()` and
replaced `self.authz` (new bindings), but the registered control kept the original
bindings. If a lock-relevant facet drifted on re-auth (node_labels via a relabel, or
allowed_logins via a policy change), a lock targeting only the NEW facet was caught
for new channel-opens (local_recheck) but MISSED by `apply_added_lock`/`reconcile`,
so the live shell ran to grant_expiry — defeating FR-LOCK-1 for drifted sessions.

## Fix
`SessionControl.bindings` is now `Arc<Mutex<LockBindings>>` (shared across the
registry + handler clones) with `update_bindings()`; on a successful re-authorize
`local_recheck` refreshes the registered control's bindings, so a lock on a drifted
facet still tears the live session down.
