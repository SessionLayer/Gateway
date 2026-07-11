# F-proxy-maxaddr-1: PROXY v2 address-block cap (MAX_ADDR_LEN = 1024)
- Severity: info
- Status: Accepted-Risk
- Area: proxy

## Observation (T3: protocol reviewer)
The PROXY v2 parser caps the declared address-block length at `MAX_ADDR_LEN = 1024`
bytes and rejects anything larger (`ProxyError::TooLong`) before allocating.

## Why this is by design (accepted)
This is an intentional Tier-0 accept-path bound, well above any real load-balancer
header: the IPv4 address block is 12 bytes, IPv6 is 36, and PROXY-v2 TLV extensions
(AWS/GCP/Azure LBs) are comfortably under 1024. Capping before allocation prevents a
spoofed/oversized length (a u16, up to 65535) from driving a per-connection
allocation on the accept path. A legitimate LB is never affected; if a future
deployment needs larger TLVs the constant is a one-line change. Exhaustively
unit-tested (`ssh::proxy::tests`), including the oversized-length rejection.
