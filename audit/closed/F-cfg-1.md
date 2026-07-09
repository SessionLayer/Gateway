# F-cfg-1: GatewayConfig silently ignored unknown fields (fail-open config)
- Severity: low
- Status: Verified-Fixed
- Area: cfg

**Issue.** `GatewayConfig` used `#[serde(default)]` without
`deny_unknown_fields`, so a misspelled or unrecognised key (potentially a
security-relevant setting) was silently dropped and the default kept — a
fail-open configuration behavior, contrary to the deny-fails-closed spine.

**Fix.** Added `#[serde(deny_unknown_fields)]` alongside `#[serde(default)]`
(they compose: missing keys still default, unknown keys now error).

**Verification.** Unit test `unknown_key_fails_closed` asserts that
`{"io_back_end":"uring"}` fails to deserialize.
