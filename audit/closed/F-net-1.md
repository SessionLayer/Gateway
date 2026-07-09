# F-net-1: negotiate() had no connect/RPC timeout — unresponsive peer could hang the caller
- Severity: low
- Status: Verified-Fixed
- Area: net

**Issue.** `gateway_core::handshake::negotiate` performed `Endpoint::connect()`
and `Negotiate` with no deadline. A peer that completes the TCP handshake then
stalls (HTTP/2 preface or response) would hang the caller indefinitely. Low in
Session One (only the dev `handshake-smoke` binary calls it, over plaintext
localhost), but this is the reusable library seam that a real Gateway
startup/reconnect path (S4+) will depend on — where an unbounded call is a DoS.

**Fix.** Added `DEFAULT_CONNECT_TIMEOUT` (5s) and `DEFAULT_RPC_TIMEOUT` (10s).
`negotiate` now delegates to `negotiate_with_timeouts`, which wraps the whole
attempt in a `tokio::time::timeout` (overall wall-clock bound covering connect +
HTTP/2 handshake + RPC) with the `Endpoint` `connect_timeout`/`timeout` as
defense-in-depth, and a new `HandshakeError::Timeout` variant.

**Verification.** New unit test `negotiation_times_out_against_a_silent_peer`
drives an accept-but-silent listener and asserts the call returns a bounded
error (Timeout/Connect/Rpc) well within a 4s outer bound — it does not hang.
