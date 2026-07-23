# F-fwd-x11-optimistic-ack-1: x11-req is ACKed to the client before the node accepts it
- Severity: info
- Status: Accepted-Risk
- Area: protocol

## Summary (T5: protocol-expert, INFO-1)
`x11_request` sends `channel_success` to the client on capability grant, before
the inner session channel exists and before the node has accepted the relayed
`x11-req` (sent with `want_reply=false`). If the node later refuses X11, the
client was already told success; X apps then fail to tunnel while the shell
continues.

## Why accepted
This is inherent to the request ordering — the outer `x11-req` necessarily
precedes the shell request that triggers the inner-channel open, so the Gateway
cannot wait for the node's verdict before answering the client. It matches stock
OpenSSH's best-effort X11 behaviour (the client continues regardless) and is not
an interop break. The capability GATE is exact (ungranted → `channel_failure`);
only the granted-but-node-refuses case is optimistic, and it degrades safely
(shell unaffected, X apps just can't connect).
