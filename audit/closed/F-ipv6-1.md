# F-ipv6-1: host_from_endpoint mishandled bracketed IPv6 literals (GW-IPV6)

- Severity: low
- Status: Verified-Fixed
- Area: config

## Summary

`main.rs::host_from_endpoint` derived the server name (SNI / SAN) by splitting on
the last `:`. For a bracketed IPv6 endpoint like `https://[::1]:9443` this
produced `[::1]` (or split inside the address), breaking verification against a
legitimate IPv6 CP endpoint. (It failed closed rather than mis-verifying, but a
valid IPv6 CP would be unreachable.)

## Fix

`host_from_endpoint` now detects a leading `[` and takes the host between the
brackets (`[::1]` / `[::1]:9443` → `::1`), falling back to the last-`:` split for
regular `host[:port]`.

## Verification

New cases in `host_is_extracted_from_endpoint`: `[::1]:9443`, `[::1]`,
`[2001:db8::5]:9443`, plus the existing DNS/IPv4 cases. Full gate green.
