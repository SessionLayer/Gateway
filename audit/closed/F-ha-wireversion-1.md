# F-ha-wireversion-1 (F5): no gate test pinned the wire protocol max / its decoupling from gRPC
- Severity: medium
- Status: Verified-Fixed
- Area: versioning

## Summary

The Gateway is the side that regressed in S14 (F-wireversion-1: it advertised wire 1.1 by reusing
the gRPC constant). Only a buried unit test guarded the wire/gRPC decoupling; there was no
dedicated gate test that would fail loudly if someone re-coupled them.

## Location

- `gateway-core/tests/version.rs` (new), `gateway-core/src/agent/mod.rs`

## Remediation — Verified-Fixed

Added `tests/version.rs` (mirroring `Agent/tests/version.rs`) asserting
`wire_component_info().protocol_max == (1,0)`, `WIRE_PROTOCOL_MIN == WIRE_PROTOCOL_MAX == (1,0)`,
and — the load-bearing check — `WIRE_PROTOCOL_MAX < version::PROTOCOL_MAX (== (1,1))`, so recoupling
the wire version to the gRPC version fails the gate.
