# F-fwd-tunnel-abort-1: tunnel byte pumps were detached; Drop/abort did not stop them
- Severity: low
- Status: Verified-Fixed
- Area: reliability

## Summary (T5: reliability-engineer)
`tunnel_bridge_task` spawned the two directional `pump_tunnel` halves as detached
tasks and returned only a coordinator handle. Aborting the coordinator (on Drop /
dispatcher teardown) did not cancel the pumps — they ran until transport close —
so the "aborted on Drop, no leak-until-disconnect" claim was overstated for
tunnels.

## Fix
`tunnel_bridge_task` now runs both pumps as futures INSIDE one task via
`tokio::select!` (not detached). Aborting the returned handle cancels both pump
futures at once, so teardown is deterministic. `forward.rs` `tunnel_bridge_task`.
