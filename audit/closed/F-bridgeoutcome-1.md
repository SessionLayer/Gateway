# F-bridgeoutcome-1: inner-leg success milestones omit the consistent outcome= field
- Severity: low
- Status: Verified-Fixed
- Area: observability

## Risk (T3: reliability reviewer)
F-observability-outcome-1 established that every §7.1 row carries a structured
`outcome=` field (incl. `authenticated`/`auth_succeeded`/`authorized` on the
success path). The two **terminal inner-leg success** milestones added this session
do **not** carry it:

- `handler.rs:672` — "inner leg established; node host identity verified (no TOFU)"
  (has `host_verified=`, `node_id=`, `key_id=`, but no `outcome=`).
- `handler.rs:506` — "inner leg bridged; session flowing" (no `outcome=`).

Every inner-leg *failure* path is tagged (`node_unreachable`,
`host_verification_failed`, `cp_unavailable`), so a dashboard/alert that counts
`outcome=` cannot compute an inner-leg **success ratio** or "sessions bridged"
rate — the numerator is invisible. Alerting on "host-verify failures rose" works;
"bridged rate dropped to zero" does not.

## Fix
Add `outcome = "inner_established"` at handler.rs:672 and `outcome = "bridged"` at
handler.rs:506 (no secrets/plaintext — same fields as today). Keeps the SSH surface
fully countable from the `outcome=` cardinality, per the F-observability-outcome-1
convention.

## Verification
Grep the inner-leg log sites: every terminal state (success and failure) carries an
`outcome=` label.

## Resolution (Verified-Fixed)
Added consistent `outcome=` fields on the inner-leg success milestones (`outcome=host_verified` on establish, `outcome=bridged` on the bridge hand-off), matching the §7.1 taxonomy convention.
