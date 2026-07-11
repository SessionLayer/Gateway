# F-cert-local-validation-1: russh locally checks cert expiry + self-signature
- Severity: low
- Status: Accepted-Risk
- Area: auth

## Observation (T3: protocol reviewer, F-3)
Before invoking `auth_openssh_certificate`, russh 0.62 validates the presented
OpenSSH certificate locally: its validity window (expiry) and its self-consistency /
signature. Only a cert that passes those local checks reaches the Gateway's
`ResolveUserCert` delegation to the CP.

## Why this is accepted (genuinely-unfixable without abandoning russh's cert path)
The Gateway is a thin PEP and delegates the *trust* decision (does the cert chain to
the user-facing CA? is the identity valid?) to the CP — russh does not decide that.
russh's local checks are **fail-closed and only additive** (a locally-invalid cert
is rejected; it never grants). Fully delegating even the expiry/self-signature check
to the CP would mean not using russh's certificate authentication at all.

Documented residuals:
- **No clock-skew tolerance at the cert validity boundary** on the Gateway side
  (the CP's `valid_after` backdating, §2B, still governs the inner-leg cert; the
  outer-leg user cert is checked against the Gateway clock with no skew window). NTP
  is assumed (FR-BOOT-4); a grossly-skewed Gateway clock would reject otherwise-valid
  user certs — an operational fault, not a platform bug.
- A cert russh rejects **locally** never reaches the CP, so it does not appear in the
  CP decision log. The degradation to the next method is generic (no disclosure), so
  this is an auditing gap, not a security one.
