# F-cpdown-taxonomy-1: CP-down during resolution surfaces service-unavailable
- Severity: medium
- Status: Verified-Fixed
- Area: taxonomy

## Risk (T3: reliability reviewer, §7.1/Part F conformance)
The "service temporarily unavailable" outcome only fired on the `Authorize` path.
A fully-down CP makes the dominant pin/cert/OTP resolution path degrade to a plain
"Permission denied" — masking a CP outage as an auth failure and diverging from
§7.1. (Still fail-closed, but the wrong user-facing outcome.)

## Resolution (Verified-Fixed)
`CpError::is_cp_down()` distinguishes a **transport/timeout/circuit/server-error**
failure (CP down) from an ordinary `Ok(resolved=false)` (degrade to the next
method, which stays correct). On a CP-down during resolution the handler:
- flags `ConnState::cp_unavailable` and logs `outcome=cp_unavailable`
  (`note_cp_down`), and
- surfaces the §7.1 message on the keyboard-interactive path: the OTP/`BeginDeviceFlow`
  CP-down returns `partial_message(SERVICE_UNAVAILABLE)`, and a prior publickey
  CP-down is surfaced at the first KI info-request (`KiState::Start` checks the
  flag). Pure-publickey clients fail closed with `outcome=cp_unavailable` logged and
  a consolidated auth-failed record.
It never silently degrades to the next method on a CP-down, and never fails open.

## Evidence
`tests/outer_leg_it.rs::cp_down_during_resolution_e2e`: with the mock CP's resolve
RPCs returning UNAVAILABLE, a stock `ssh` publickey→keyboard-interactive login gets
`"service temporarily unavailable"` (not a plain auth failure). Classifier
unit-tested in `cpauth::tests`.
