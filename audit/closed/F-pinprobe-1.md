# F-pinprobe-1: pins are resolved only on proven key possession
- Severity: medium
- Status: Verified-Fixed
- Area: auth

## Risk
Resolving a pin (or user cert) in the pre-signature `auth_publickey_offered`
callback would let an unauthenticated attacker probe which public keys are pinned
without holding the corresponding private key — a pin-existence oracle — and would
spend a CP round-trip per offered key.

## Resolution (Verified-Fixed)
`auth_publickey_offered` returns `Auth::Accept` unconditionally (request the
signature) and performs **no** CP call. The pin lookup (`ResolvePin`) happens only
in `auth_publickey`, which russh invokes **after** verifying the client's signature
(proof of possession). Certificate trust is likewise resolved only in
`auth_openssh_certificate` (post-signature). russh's `max_auth_attempts` bounds the
number of proven-possession resolutions per connection. A non-resolving credential
returns `reject_and_degrade` (proceed to the next key/method), disclosing nothing.

## Evidence
- `tests/outer_leg_it.rs`: an unpinned key fails auth with a standard
  `"Permission denied"`; a pinned key resolves and authorizes; degradation from an
  unpinned key to keyboard-interactive OTP succeeds.
