# F-gw-breakglass-accepted-notes-1: break-glass accepted-risk notes (metrics / fan-out / attestation / disambiguation / feed-unhealthy)
- Severity: low
- Status: Accepted-Risk
- Area: breakglass

Consolidated ledger for the low/info break-glass review items the panel judged CORRECT
or explicitly deferred (do NOT "fix" — documented + runbooked):

## Feed-unhealthy break-glass refusal is CORRECT (reliability F2, info)
A break-glass session refuses NEW privileged channels when the lock feed is unhealthy
(`handler.rs` local_recheck (a), tested by `break_glass_refused_when_lock_feed_unhealthy`).
This is the §8.4 safety spine: deny fails closed. The CP already enforced the Lock at
Authorize; a Lock arriving in the Authorize→first-channel window under feed-loss must
still win, so the Gateway cannot serve a break-glass channel it cannot confirm is
un-locked. Bounded + self-heals in 0.5–10s on feed reconnect. The "permit the first
channel" refinement is REJECTED (it would weaken §8.4). Runbooked.

## No break-glass metrics (reliability F3, low)
The platform has no metrics infrastructure yet (an S8/S10 deferral). Break-glass counters
(activations, forced-strict teardowns, feed-unhealthy refusals) are prioritized when
metrics land in S14. Operator visibility today is via the structured `tracing` fields
(`break_glass=true`, `reason=...`) added in G7.

## CP-RPC 2× fan-out per sk auth attempt (redteam/security F2, low)
An offered sk-ecdsa key drives up to two CP RPCs (resolve_break_glass_key, then
resolve_pin on fall-through) per `auth_publickey`. Bounded by `max_auth_attempts`
(the S7 per-connection cap counts once per callback), so the amplification is fixed and
small. Accepted.

## No FIDO2 attestation policy (divergence BG-4, low)
The Gateway cannot verify FIDO2 authenticator attestation at runtime (russh exposes only
the public key). Attestation-based provisioning policy (require a specific authenticator
AAGUID) is a future CP-side enrollment concern, not a Gateway data-plane control.

## Implicit break-glass disambiguation (divergence BG-5, low)
Break-glass vs. normal auth is disambiguated by the CREDENTIAL (a registered break-glass
sk-ecdsa key / offline code), not an explicit user gesture — arguably better for an
emergency path (no extra step under duress). Do NOT dual-register one key as both a pin
and a break-glass credential (a routine login would fire alert+forced-strict). A CP-side
dual-registration guard is noted as a future enhancement; runbooked as a deployment rule.
