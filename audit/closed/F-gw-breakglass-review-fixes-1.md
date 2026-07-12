# F-gw-breakglass-review-fixes-1: S13 break-glass review batch (G1–G8) fixes
- Severity: medium
- Status: Verified-Fixed
- Area: breakglass

Consolidated ledger for the GW review-panel fix batch. All Verified-Fixed with tests;
full gate green.

- **G1 (grant_expiry==0 fail-closed for break-glass, HIGH-ish for the override path).**
  `local_recheck` (b) now refuses a break-glass channel when the signed `grant_expiry==0`
  (an override MUST be time-boxed); `arm_expiry` tears a break-glass session down as a
  backstop. Test: `break_glass_without_grant_expiry_is_refused` (real node ⇒ true
  discriminator).
- **G2 (reject RunToTtl for break-glass).** `validate_config` fails startup if
  `break_glass.mid_session_expiry == RunToTtl` (a break-glass session must be time-boxed;
  a Lock remains the backstop). Test: `break_glass_run_to_ttl_is_rejected`.
- **G3 (sk-dummy Dockerfile reproducible + verified).** Pinned tarball sha256 (verified
  on build), digest-pinned base image, and an OpenSSH major-line assertion so the sk-api
  ABI cannot silently drift.
- **G4 (non-sk-ecdsa security key non-silent).** `auth_publickey` logs an operator-facing
  warning when a non-sk-ecdsa security key (e.g. sk-ed25519) is offered and routed to the
  pin path; §7.1-safe (no user disclosure). sk-ecdsa-only routing kept (SESSION Part D).
  Runbooked: break-glass keys MUST be sk-ecdsa.
- **G5 (break-glass-code method-label parity).** `try_break_glass_code` records
  `record_method("breakglass-code")` on the attempt so a failed offline-code login appears
  in the auth-failed record (parity with `publickey-breakglass`).
- **G6 (unhealthy-feed refusal tested).** `break_glass_refused_when_lock_feed_unhealthy`
  (mock `set_lock_feed_down`) covers the fail-closed branch.
- **G7 (observability).** warn-log when a locally-break-glass auth gets a non-BREAKGLASS
  access_model back (token mis-binding / contract drift); `break_glass=` field added to the
  `recording_unavailable` refusal and the `authorization_denied` operator logs.
- **G8 (comment accuracy).** Handler comments corrected to say russh verifies POSSESSION
  only (not user-presence); point to the deployment requirement +
  [[F-gw-breakglass-userpresence-1]].

Related: re-auth posture + D6 (earlier review round), F1/F2 (proof-of-possession +
signed-context enforcement). See also the Accepted-Risk ledger:
[[F-gw-breakglass-userpresence-1]], [[F-gw-breakglass-secret-zeroize-1]],
[[F-gw-breakglass-accepted-notes-1]].
