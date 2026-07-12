# F-capgate-unspec-1: capability gate does not explicitly reject CAPABILITY_UNSPECIFIED (0)
- Severity: low
- Status: Verified-Fixed
- Area: authz

## Summary (T3: redteam-auditor)
The channel-open gate admits a channel iff its required capability is a member of
the CP-supplied `capabilities` set (`handler.rs:462`,
`authz.capabilities.contains(&(capability as i32))`). An unknown subsystem maps to
`Capability::Unspecified` (proto value `0`, `required_capability`
`handler.rs:973`) as the intended "never granted" sentinel. But nothing prevents a
`0` from appearing in the granted set: if a CP `DecisionContext.capabilities`
(`authz.proto:212`, `repeated Capability`) ever contains `CAPABILITY_UNSPECIFIED`,
then `contains(&0)` is true and **any unknown subsystem** the client names is
admitted and bridged to the node.

## Root cause / data flow
`granted_capabilities` (`handler.rs:989-994`) passes the CP list through unchanged
(only substituting the shell+exec default when the list is *empty*). The sentinel
`Unspecified` is enforced by absence, not by an explicit deny. A stray `0` — a CP
bug, a proto default that slips into a repeated field, or a future CP that emits an
unset enum — silently widens the gate to arbitrary subsystems. Defense-in-depth: a
sentinel used to mean "deny" should be denied explicitly, independent of the
granted set.

## Impact
Requires CP misbehavior to trigger (the mTLS-authenticated CP is trusted, so this
is not directly attacker-reachable), and the blast radius is limited to arbitrary
*subsystem* channels (shell/exec/scp/sftp remain gated by their specific non-zero
capabilities). Low severity, defense-in-depth.

## Remediation
Reject `Capability::Unspecified` unconditionally in the gate, before the
membership test:

```rust
let capability = required_capability(&kind);
if capability == Capability::Unspecified
    || !authz.capabilities.contains(&(capability as i32)) {
    // refuse (generic denial)
}
```

Equivalently, strip `0` from `granted_capabilities`' output. Add a test asserting an
unknown subsystem is refused even when the granted set literally contains `0`.

## References
FR-AUTHZ-6 (default-deny capabilities); Design §6.1 ("capabilities default-deny,
only RBAC-granted ones added"); CWE-863 (incorrect authorization).

## Resolution (Verified-Fixed)
The acceptable-capability-set gate rejects `Capability::Unspecified` explicitly, and an unknown subsystem has an EMPTY acceptable set → always refused regardless of the granted set. Regression test asserts refusal even against a set literally containing 0.
