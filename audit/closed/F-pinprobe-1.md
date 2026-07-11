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
(proof of possession) — so a pin is never probed without the private key.
Certificate trust is likewise resolved only in `auth_openssh_certificate`
(post-signature). A non-resolving credential returns `reject_and_degrade` (proceed
to the next key/method), disclosing nothing.

**Correction (T3 review):** russh 0.62 does **not** enforce its own
`max_auth_attempts` (it increments a counter but never compares it), so that is
not what bounds the number of resolutions. The bound is now an **app-level
per-connection cap** (`SshServerConfig::max_auth_attempts`, default 6): each
pin/cert/OTP resolution increments `SshHandler::auth_attempts`, and once the cap is
exceeded the connection is hard-rejected (an empty proceed-methods set) **before**
any further CP call — see F-preauth-grace-1.

## Evidence
- `tests/outer_leg_it.rs`: an unpinned key fails auth with a standard
  `"Permission denied"`; a pinned key resolves and authorizes; degradation from an
  unpinned key to keyboard-interactive OTP succeeds.
