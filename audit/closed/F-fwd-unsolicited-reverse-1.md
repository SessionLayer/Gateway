# F-fwd-unsolicited-reverse-1: node-initiated reverse opens gated on capability, not on an actual request (RFC 4254 §7.2/§6.3.2)
- Severity: medium
- Status: Verified-Fixed
- Area: protocol / redteam

## Summary (T5: protocol-expert, independent review)
RFC 4254 §7.2 and §6.3.2 require an implementation to reject a
`forwarded-tcpip`/`x11` channel-open unless it previously requested that specific
forwarding. On the inner leg the Gateway IS the requesting client, so the MUST
binds it directly. As written, `InnerHandler::server_channel_open_forwarded_tcpip`
/ `_x11` accepted whenever `reverse_tx` was `Some` — i.e. whenever the grant
carried `port_forward_remote`/`x11` at all, NOT whenever a `tcpip-forward` /
`x11-req` was actually issued on this connection. A broad role grant plus a plain
`ssh user@node` (no `-R`, no `-X`) left the Gateway accepting and relaying a
COMPROMISED NODE's unsolicited reverse opens — violating the Gateway's own stated
invariant (the "even a compromised node cannot push an unsolicited ..." comment
was aspirational, not enforced). Stock OpenSSH clients self-protect, so practical
impact against a real client is probe/noise, but the platform must enforce its own
MUST.

## Fix
Added a per-connection request registry `ReverseAllowed` (innerleg.rs), shared
between `InnerClient` and its `InnerHandler`:
- `remote_forward()` registers the bound port (a fixed port is pre-registered
  before the request so a connection racing REQUEST_SUCCESS is not falsely
  refused; a port-0 dynamic bind registers the node-chosen port on reply);
  `cancel_remote_forward()` deregisters on success. Ports are reference-counted so
  two binds sharing a port number survive one cancel.
- `open_channel()` sets the x11-requested flag only when it actually relays an
  x11-req to the node.
- Both reverse accepts now REJECT at the inner-leg accept (drop `reply`, never
  accept-then-drop) unless the port is bound / x11 was requested — matched by PORT
  for forwarded-tcpip, as OpenSSH's own client does (the reported connected-address
  can legitimately differ from the requested bind string). Capability + lock +
  expiry + cap-slot gates in `ReverseDispatcher` remain as defense in depth.

Unit-tested (`innerleg::tests`): nothing admitted before a request; only the
requested port admits; cancel closes the gate; a shared port number survives one
cancel; a spurious extra cancel is a no-op (no underflow).

## Verification gap (noted, not blocking)
No E2E with a genuinely malicious node opening an unsolicited reverse channel
(the harness node is a stock sshd, which never does this). The gate logic is
unit-covered; an adversarial-node E2E is a candidate for a future session.
