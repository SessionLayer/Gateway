# F-nondisclosure-1: pre-authorization errors reveal no existence
- Severity: high
- Status: Verified-Fixed
- Area: taxonomy

## Risk
A pre-authorization SSH-surface error that differs by whether an identity, node,
or rule exists is an enumeration oracle (FR-AUTH-16/18, §7.1). Locks/revocations
must be indistinguishable from an ordinary authorization denial.

## Resolution (Verified-Fixed)
`ssh/outcome.rs` centralizes every user-facing outcome. All pre-authorization
failures — RBAC deny, unknown node, malformed/second-separator target, the
credential-principal reducer, and (at the CP) locks — collapse to the single
generic `"access denied by policy"`. The specific reason is written only to the
structured decision log at the call site (sanitized), never to the user. The
device-flow denial is likewise the generic SSH auth failure.

## Evidence
- `ssh::outcome::tests::denial_is_generic_and_leaks_nothing` greps the message for
  identity/node/rule/lock tokens.
- `tests/outer_leg_it.rs`: an authorized-but-denied node and an **unknown** node
  both yield the identical `"access denied by policy"`, and the unknown-node case
  asserts the node name never appears in the client output.
