# F-gw-breakglass-userpresence-1: FIDO2 user-presence (touch) not asserted server-side for break-glass
- Severity: high
- Status: Accepted-Risk
- Area: breakglass

## Observation (BG-1, redteam/security/reliability/divergence review)
The break-glass sk-ecdsa auth path relies on russh to verify the FIDO assertion before
`SshHandler::auth_publickey` runs. russh 0.62 verifies **possession** (the ECDSA
signature over `sha256(application)||flags||counter||sha256(request)`, via
`ssh_key::public::SkEcdsaSha2NistP256::verify`) but does NOT enforce the **user-presence
(UP / touch)** bit: it verifies the signature over whatever flags the authenticator
asserted, so a `no-touch-required` key (or a silent/compromised SK middleware) yields a
valid UP=0 signature that a DEFAULT OpenSSH server would reject (`sshkey_check_sigtype` /
`required_flags`) but the Gateway accepts. The CP cannot detect no-touch from the public
key (the flag lives in the per-assertion signature, not the key).

## Investigation — is there a russh 0.62 hook to enforce UP? (real effort)
No usable seam exists:
- The `Handler` trait's `auth_publickey(&mut self, user, public_key: &ssh_key::PublicKey)`
  and `auth_publickey_offered` receive ONLY the public key — never the signature or the
  sk flags. The doc states it is "called after the signature has been verified"
  (`russh-0.62.2/src/server/mod.rs:270,276`).
- The signature is decoded and consumed INTERNALLY: `server/encrypted.rs:752` decodes
  `sig`, `:774` calls `Verifier::verify(&pubkey, &buf, &sig)`, and `:779` calls
  `handler.auth_publickey(user, key)` on success — the `sig` (with its flags byte) is
  dropped before the callback.
- The server `Config` struct (`server/mod.rs:65-99`) has NO field for required sk flags,
  user-presence, user-verification, or a custom publickey verifier. The only `Verify`
  trait (`keys/key.rs:34`) is `#[doc(hidden)]` and used internally, not a server seam.

Enforcing UP would require forking/patching russh's `encrypted.rs` to inspect the sk
signature flags byte and reject UP=0 for break-glass — out of reasonable scope for this
session. Filed as Accepted-Risk rather than Verified-Fixed: the proto/comment
documentation does NOT enforce touch at runtime.

## Compensating controls (all present + tested)
Break-glass is not a bare auth grant — every use carries defense-in-depth that makes a
missing UP assertion low-consequence in practice:
- **High-priority alert on every break-glass authentication** (CP-side, ON USE at
  Authorize) + **breakglass_activation** record → mandatory post-hoc review.
- **FORCED strict recording**: a break-glass session that cannot be recorded is torn
  down (`session_is_break_glass()` OR the signed `access_model=BREAKGLASS`; tested by
  `break_glass_forces_strict_refused_when_recording_unavailable`).
- **Lock-beatable + time-boxed**: a Lock still denies (deny wins), and a break-glass
  ALLOW without a `grant_expiry` is refused (G1), so an override session is bounded.
- **Possession is still mandatory**: the FIDO private key must sign (a listable public
  key alone is useless — `sk_ecdsa_fido2_break_glass_session_e2e` negative case: a
  registered key with no valid assertion → rejected, 0 activations).

## Deployment requirement (runbook)
Break-glass FIDO2 keys MUST be provisioned **touch-required** (`ssh-keygen -t ecdsa-sk`
WITHOUT `-O no-touch-required`); never register a `no-touch-required` key as a
break-glass credential. The primary FIDO2 E2E now enrolls a touch-required key (sk-dummy
auto-asserts UP=1 for the virtual authenticator), modelling correct deployment.

## Upstream
File a russh feature request: expose the sk assertion flags (or a `required_flags`
server-config knob) to the publickey auth path so a server can require user-presence /
user-verification, mirroring OpenSSH `PubkeyAuthOptions verify-required` / `touch-required`.
Revisit this finding when russh exposes such a hook.
