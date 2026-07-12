# F-teardown-reason-leak-1: mid-session teardown revealed its cause to the SSH user (§7.1)
- Severity: low
- Status: Verified-Fixed
- Area: non-disclosure

## Observation (T3: redteam)
`SessionControl::terminate(reason)` forwarded the reason into `SSH_MSG_DISCONNECT`
("session locked" vs "grant expired"), which OpenSSH prints — so an actively-locked
attacker could tell they were deliberately locked (incident response in progress) vs
a routine TTL expiry, contradicting §7.1's same-generic-denial contract.

## Fix
`terminate()` now disconnects with a single fixed generic message
(`"session closed by policy"`) for ALL policy teardowns (lock and expiry); the
specific cause stays in the operator log only.
