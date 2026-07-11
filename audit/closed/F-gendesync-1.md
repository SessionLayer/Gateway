# F-gendesync-1: renew-ahead infinite-retry on terminal rejections + cross-repo generation desync (GW-GEN-DESYNC)

- Severity: low
- Status: Accepted-Risk
- Area: identity

## Summary

Two related concerns:

1. **Infinite retry (fixed).** The renew-ahead loop retried *every* non-mismatch
   error as transient — including rejections the CP will keep returning (locked
   identity, unknown/rotated client cert, a stale generation the CP has already
   advanced past). That would spin forever.
2. **Cross-repo desync (accepted residual).** If the CP commits generation `N+1`
   but the Gateway fails to persist before adopting (e.g. crash in the window),
   the two can disagree; the Gateway then presents generation `N` and the CP
   rejects renewal. Full idempotent-renew / self-heal needs the S10/S12
   lock-lifecycle machinery, out of scope for S4.

## Fix (item 1) + why the residual is Accepted-Risk (item 2)

- `is_repair_needed` classifies `Rpc` errors with gRPC code `FailedPrecondition`
  / `Unauthenticated` / `PermissionDenied` as **repair-needed**: the loop logs a
  distinct alert and **stops** (like the generation-mismatch security event),
  rather than infinite-retrying. Only genuinely transient errors (Unavailable,
  connect/TLS, I/O) are retried with bounded backoff.
- The desync residual is **bounded and fails closed**: the Gateway lands in a
  *stopped + flagged* state, keeping its old credential (never a silent
  downgrade, never an unauthenticated path). Recovery is operator/automated
  **re-enrollment** — the same token-join re-provision path §8.1 already
  prescribes for token-join agents ("operator re-provision, made painless by
  API-driven token issuance"). It is not silently unsafe; the self-healing
  variant is deferred to S10/S12 by design.

## Verification

New unit test `repair_needed_classifies_terminal_rejections`; new integration
test `renew_ahead_stops_on_repair_needed_rejection` (a locked identity stops the
loop rather than spinning, generation unchanged). Full gate green.
