# F-fwd-globalreq-wantreply-1: vendored russh replied to tcpip-forward global requests even when want_reply=FALSE
- Severity: low
- Status: Verified-Fixed
- Area: protocol

## Summary (T5: protocol-expert)
`third_party/russh/src/server/encrypted.rs` sent REQUEST_SUCCESS/REQUEST_FAILURE
for `tcpip-forward` and `cancel-tcpip-forward` unconditionally; RFC 4254 §4 says a
reply is sent only if want_reply=TRUE. Harmless against OpenSSH in normal use, but
a client pipelining a want_reply=0 request before a want_reply=1 one could get
reply-attribution confusion.

## Fix
In-tree russh patch (same precedent as the ProxyJump host-cert patch): both
global-request arms now emit a reply only when `self.common.wants_reply`. Marked
`[SessionLayer patch]`. The port-0 dynamic-port echo remains gated on
want_reply as before.
