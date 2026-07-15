# F-ha-session-uuid-1: outer-leg session_id is un-dashed hex, not a canonical UUID → CP denies every connect
- Severity: high (build-breaking / all connects fail closed against the real CP)
- Status: Verified-Fixed
- Area: ha-authz / outer-leg

## Summary

`new_session_id()` emitted 16 CSPRNG bytes as a 32-char un-dashed hex string
(e.g. `6fb81c4214c2b05a31fb634ca79f6e50`), which the Gateway sends verbatim in
`AuthorizeRequest.session_id`. The contract (`authz.proto:100`) declares
`session_id` a **UUID**, and the real CP does `parseUuid(request.getSessionId())`
in `AuthorizationService`. `UUID.fromString` rejects the un-dashed form → null →
`ConnectAuthorizationService.denyMissingInput` → generic deny
(`{"note":"missing_input","reason":"EVALUATION_ERROR"}` in `runtime.audit_event`;
the SSH user sees the coarse "access denied by policy"). This denied **every**
connect — single-instance and HA alike — independent of node/identity/policy.

Masked in all prior suites because the per-repo MockCp double accepted the
`session_id` string without parsing it as a UUID; only the real-jar cross-repo
`ha-e2e.sh` (Part H) exercised the real `parseUuid`, so this surfaced there — the
4th real production bug the two-binary E2E caught (after config-wiring,
per-endpoint SAN, CSR CN).

## Location

- `gateway-core/src/ssh/handler.rs` `new_session_id()`

## Remediation — Verified-Fixed

- `new_session_id()` now emits a canonical RFC 4122 **v4** UUID (dashed 8-4-4-4-12,
  version nibble + variant bits set) over the same `OsRng` CSPRNG — dependency-free
  (no `uuid` crate, keeping the supply-chain surface unchanged). `session_id` is
  used locally only as an opaque map key (`locks.rs`) and cert key-id prefix
  (`signing.rs`), so the format change is safe everywhere.
- Regression unit test `session_id_is_a_canonical_uuid` asserts the canonical
  shape (group lengths, lowercase hex, version `4`, variant `8|9|a|b`, freshness)
  so this cannot regress into a form `UUID.fromString` would reject.
- Verified against the real `controlplane-0.1.0.jar` in `scripts/ha-e2e.sh`: the
  connect now passes `parseUuid` and reaches the policy decision.
