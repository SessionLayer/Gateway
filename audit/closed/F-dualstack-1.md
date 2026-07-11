# F-dualstack-1: canonicalize the source IP before gate / LB-trust / CP
- Severity: low
- Status: Verified-Fixed
- Area: security

## Risk (T3: security reviewer)
On a dual-stack listener a v4 client arrives as an IPv4-mapped IPv6 address
(`::ffff:a.b.c.d`). Without canonicalization it would silently miss v4 CIDRs — the
global gate, the LB-trust check, and the `source_ip` sent to the CP (source-CIDR
conditions) would all misbehave (fails closed, but the operator's rules silently do
not apply).

## Resolution (Verified-Fixed)
`handle_connection` canonicalizes with `IpAddr::to_canonical()` at both derivation
points: the immediate TCP peer (before the LB-trust check inside `resolve_source_ip`)
and the resolved real client IP returned from PROXY resolution (before the global
gate and before it is used as the CP `source_ip`). So a v4-mapped v6 address is
matched against v4 CIDRs as intended, and the CP receives the canonical form.

## Evidence
`ssh/mod.rs` (`handle_connection`). CIDR family-isolation is unit-tested in
`netmatch::tests`; canonicalization ensures the correct family reaches it.
