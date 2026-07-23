# F-fwd-reverse-accept-before-gate-1: reverse channel accepted on the inner leg before the outer gate
- Severity: info
- Status: Accepted-Risk
- Area: protocol

## Summary (T5: protocol-expert, INFO-2)
`InnerHandler::server_channel_open_{forwarded_tcpip,x11}` calls `reply.accept()`
toward the NODE whenever a reverse sink exists, then the `ReverseDispatcher`
re-checks capability + lock + expiry before opening the outer channel to the
client. So a compromised node can cause a transient inner-leg accept+close for a
reverse channel that is ultimately refused.

## Why accepted
Net behaviour is fail-closed toward the CLIENT: an ungranted/locked/expired
reverse channel is accepted on the inner leg then immediately dropped/closed and
NEVER reaches the client. The inner-leg accept is a node-facing confirmation only
(no data crosses to the client). Post-fix, the inner leg is given no reverse sink
at all unless a reverse capability is granted ([[F-fwd-reverse-txgate-1]]), so
the transient accept only occurs for a session that DID hold the capability at
connect time — the residual is a bounded accept+close, no client-visible or RFC
impact.
