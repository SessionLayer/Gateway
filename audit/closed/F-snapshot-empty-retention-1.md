# F-snapshot-empty-retention-1: a reconnect empty-snapshot shrinks the deny-set (datastore-substitution edge)
- Severity: medium
- Status: Accepted-Risk
- Area: ssh-lockfeed

## Observation (T3: security)
On reconnect the snapshot REPLACES the deny-set wholesale (`replace_snapshot`). If a
successful-but-EMPTY snapshot arrives (rather than a stream error), the Gateway drops
previously-pushed locks — a potential fail-open that appears to contradict the §8.4
"denies under total datastore loss" invariant.

## Disposition — Accepted-Risk (justified; S14 hand-off)
The stated §8.4 invariant HOLDS: a **total datastore loss** makes the CP's
`access_lock.findAll()` R2DBC query ERROR → the CP's snapshot Mono errors → StreamLocks
errors → the Gateway's stream errors → `mark_disconnected()` retains the set (never
cleared; proven by `locks::tests::lockset_snapshot_add_remove_and_match`). The residual
here is the DISTINCT, weaker scenario of the CP **successfully** reading a
substituted/rolled-back EMPTY datastore and reporting zero locks — a total-CP-state
corruption/DR event (it also drops all grants, identities, and RBAC policy), NOT
attacker-triggerable (the feed is mTLS-gateway-authenticated), and NOT resolvable
Gateway-alone (the Gateway cannot distinguish authoritative-empty from wrong-DB-empty
from the data). The clean fix is a contract-level datastore-authority signal on
`LockSnapshot` (or feed-epoch-regression distrust), which belongs to **Session 14**
(cross-Gateway / HA lock consistency — explicitly out of S10 scope). Compensating
controls today: total loss is retained (above); an operator DR runbook restores the
authoritative store; per-session local expiry + `decision_ttl` re-eval bound exposure.
