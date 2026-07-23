# F-fwd-listener-count-1: spurious cancel-tcpip-forward could under-count the listener cap
- Severity: low
- Status: Verified-Fixed
- Area: reliability

## Summary (T5: reliability-engineer)
The remote-forward listener cap used a monotone `usize` decremented on ANY node
`Ok` to `cancel-tcpip-forward`, with no check that a matching `tcpip_forward` was
counted. A client binding one listener then cancelling arbitrary/duplicate
addresses the node happened to `Ok` could floor the counter while real listeners
remained, under-enforcing the cap (up to ~2x). Node-side listeners, so bounded
impact.

## Fix
Listeners are tracked as a `HashSet<(bind_address, bound_port)>`; the cap is the
set length, and `cancel-tcpip-forward` removes only a real match — a spurious or
duplicate cancel cannot under-count. `handler.rs` `tcpip_forward` /
`cancel_tcpip_forward`.
