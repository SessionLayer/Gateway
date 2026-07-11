# F-proxy-parser-1: PROXY v2 parser is bounded and fail-closed
- Severity: high
- Status: Verified-Fixed
- Area: proxy

## Risk
The PROXY v2 header is attacker-influenced wire data on the accept path. A parser
that trusts the declared length, mis-validates the signature/version, or accepts a
header from a non-LB peer would allow source-IP spoofing (FR-AUTH-14) — the exact
failure that leaves 2.3M internet SSH servers spoofable (Design §15).

## Resolution (Verified-Fixed)
`ssh/proxy.rs` hand-rolls a small parser that: validates the fixed 12-byte
signature, requires version nibble `2`, accepts only LOCAL/PROXY commands, caps
the declared address block at `MAX_ADDR_LEN` (1024) before any allocation, and
`read_exact`s exactly the header (early EOF → `Truncated`). It extracts only the
source address; LOCAL / UNSPEC / non-IP families fall back to the TCP peer.

Trust is fail-closed **both ways** (`resolve_source_ip`): PROXY off when no LB
CIDR is configured; when configured, a header is required from an LB peer
(missing/malformed → reject) and **any** connection from a non-LB peer is rejected
without reading (a header from it would be a spoof). The pre-banner read is bounded
by `handshake_timeout_secs`.

## Evidence
- Exhaustive unit tests (`ssh::proxy::tests`): valid v4/v6, bad signature, wrong
  version, bad command, oversized length, truncated block, UNSPEC/LOCAL fallback.
- Deterministic matrix `tests/proxy_it.rs`: trusted-LB accepted; spoofed-from-non-LB
  dropped; missing-from-LB dropped; outside-gate dropped **pre-banner**.
