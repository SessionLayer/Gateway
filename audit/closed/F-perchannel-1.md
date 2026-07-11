# F-perchannel-1: one connect-time decision per connection (per-channel = S10)
- Severity: low
- Status: Accepted-Risk
- Area: authz

## Observation
The outer leg makes exactly one `Authorize` decision per connection, on the first
`shell`/`exec`/`subsystem` request (guarded by `SshHandler::decided`), then closes
cleanly at the `NodeConnector` seam. A second channel-open on the same connection
(e.g. `ControlMaster` multiplexing) is not independently re-evaluated.

## Why this is accepted (scope)
Per-channel-open re-evaluation, the lock-push deny-list, and the mid-connection
kill switch are **Session Ten** (Design §6.3, FR-CHAN-1..4); the connect-time
single decision here is exactly the S7 contract ("one connect-time decision only").
Because Session Seven stops at the inner-leg seam and closes the session after the
first decision, no long-lived multiplexed session exists yet for a second channel
to attach to. Session Ten attaches the cached-context per-channel checks (see
F-ctxsig-1) to the `SessionGrant`/`DecisionContext` seam.
