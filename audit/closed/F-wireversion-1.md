# F-wireversion-1: the agent-wire preface reused the CP<->GW gRPC version constant (advertised wire 1.1)
- Severity: high
- Status: Verified-Fixed
- Area: wireversion

## Risk

The Agent <-> Gateway **wire** protocol is a distinct protocol from the CP <-> Gateway gRPC
plane (contract §1), pinned at **1.0** by contract §3. The Gateway's `HELLO_ACK` preface,
`VERSION_REJECT`, and `negotiate()` reused `crate::version::{component_info, PROTOCOL_MIN,
PROTOCOL_MAX}` — the **gRPC** constants, already at **1.1** — so the Gateway advertised and
would negotiate a wire minor (1.1) that does not exist. Present §3 violation, masked only by
`resolve_common_version` happening to pick a low common value today. It would surface the
moment the two planes' versions diverged further, and it offered Agents a phantom wire
version. Found by the protocol-wire cross-repo review.

## Fix (Verified-Fixed)

- `agent/mod.rs`: dedicated `WIRE_PROTOCOL_MIN`/`WIRE_PROTOCOL_MAX` = `(1,0)` and
  `wire_component_info()`, **independent of the gRPC `PROTOCOL_*`** (with a doc-comment
  explaining they must never move in lockstep).
- `server.rs`: `HELLO_ACK`, `VERSION_REJECT`, the pre-negotiation error `VER` byte, and
  `negotiate()` all use the wire constants. `testclient.rs` advertises the wire range too (a
  faithful client must not claim a wire minor that does not exist).

## Verification

`server::tests::negotiation_uses_the_wire_range_not_the_grpc_range` asserts a peer offering
`[1.0, 1.1]` resolves to **1.0** (never 1.1) and that `WIRE_PROTOCOL_MAX (1,0) <
version::PROTOCOL_MAX (1,1)`; `no_common_version_fails_closed` asserts a 1.1-only peer is
rejected, never silently downgraded. ag-engineer2 decouples the Agent side (F-wireversion-2).
