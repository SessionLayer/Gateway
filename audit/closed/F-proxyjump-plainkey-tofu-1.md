# F-proxyjump-plainkey-tofu-1: ProxyJump advertises the plain host-key algo alongside the host-cert algo (client-side TOFU residual)
- Severity: low
- Status: Accepted-Risk
- Area: ssh

## Context (S23 red-team panel A5)

On the ProxyJump host-cert path the Gateway's outer listener advertises the host-CA
CERT algorithms first, then the PLAIN host-key algorithms for the same key
(`proxyjump.rs` `RusshConfig{keys, host_certificates}`; vendored
`russh/src/negotiation.rs`). A client that installed the `@cert-authority` line orders
cert-algos first and negotiates the cert (no TOFU, as designed). A client WITHOUT the
line negotiates the plain algorithm and silently TOFU-accepts the Gateway's own host
key — so the §11 "cryptographically explicit consensual MITM, no TOFU" guarantee is
client-configuration-dependent, not server-enforced.

## Why Accepted-Risk (inherent to SSH)

A server cannot force a client to verify host keys, and russh requires the underlying
key in `config.keys` to sign the KEX exchange hash even on the cert path — so the plain
algorithm is unavoidably advertised. Design §11 already states the precondition ("user
installs one `@cert-authority *` line"). Not a Gateway defect and not server-fixable.
Mitigation is operator onboarding (verify the line is installed); an optional deeper
russh patch could suppress the plain-key advertise on the ProxyJump listener so an
unconfigured client hard-fails instead of TOFU-ing — recorded as a possible future
hardening, not required.
