# Key Vault double (`tests/fullstack/keyvault/`)

`KeyVaultDouble.java` is a standalone, dependency-free HTTPS double of the Azure Key
Vault key/crypto REST surface, used only by `tests/fullstack/run.sh` — it exists to
prove one claim: *sessions work when the CA lives in Key Vault*. It runs as a separate
process — the JDK's single-file source launcher, `java KeyVaultDouble.java --keystore
... --storepass ... --hostname ... --key-name ... --request-log ...` — because the
full-stack harness runs the real Control Plane as a packaged jar in its own process; the
vault has to be reachable over a real socket, not an in-JVM fake. It prints a loud
startup banner identifying itself as a test double, since it will sit in this repo
alongside real code forever and should never be mistaken for a production endpoint.

## Prerequisites (beyond `keytool`)

`ensure_keyvault_hostname` in `run.sh` needs `127.0.0.1 sl.vault.azure.net` (or whatever
`KEYVAULT_HOSTNAME` is set to) mapped in `/etc/hosts`, and adds it with `sudo -n` if it
is not already there. **This needs passwordless sudo** on whatever box runs the harness
(true on this development machine and on GitHub-hosted runners; not necessarily true
everywhere). If it cannot be added, the run dies naming exactly that, rather than
silently falling back to serving the double on an IP address — see below for why an IP
cannot work at all.

Concurrent runs on the same box are safe: `run.sh` reference-counts the mapping (a
per-PID marker under a lock) rather than tracking "did I add it" as a single boolean, so
one run finishing does not tear the mapping out from under a peer still using it. The same
concern applies to the harness's own `WORKDIR`: it is PID-suffixed by default, so one
run's `preflight` cannot delete a peer's still-in-flight logs; set `SL_FS_WORKDIR`
explicitly to opt back into a fixed, shared path.

## It issues the real challenge — and that forces a real hostname

This double DOES issue the real Key Vault `WWW-Authenticate` challenge; it is not
optional. The SDK's challenge-based authentication policy sends the very first request
to any endpoint with **no** `Authorization` header and a deliberately **empty body** — an
unauthenticated endpoint must never see the real payload — and only replays the real
request, with a bearer token, once a 401 has told it which tenant and resource to get a
token for. A double that skipped the challenge and just answered 200 would therefore only
ever see that empty probe and never the real one; every response it produced (JWK,
signature) would be for a request the SDK never actually intended to send. This double
issues the same challenge `ControlPlane`'s own unit-test double
(`KeyVaultRestDouble`) does, and the same values: `authorization="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000"`,
`resource="https://vault.azure.net"`.

That resource value is why the double cannot be served from `127.0.0.1`. The SDK's
challenge policy verifies the challenge names a resource whose host is a parent of — or
equal to — the host the request was actually sent to, before it will attach a token to
anything. `sl.vault.azure.net` is a subdomain of `vault.azure.net`, so it passes; an IP
literal has no parent domain at all and can never pass, for any resource value. Hence
`ensure_keyvault_hostname`/`--hostname`, and the TLS certificate's CN/SAN naming that same
host (`build_keyvault_trust_material` in `run.sh`) — a cert for `127.0.0.1` alone would
fail hostname verification against a request for `https://sl.vault.azure.net:<port>`.

## Credential acquisition: App Service managed identity

Issuing the challenge means the Control Plane's `TokenCredential` now has to actually
produce a token — the double never validates what it receives, but something has to hand
the SDK *a* bearer value to attach, and this harness has no real Entra tenant to get one
from. The double therefore also serves the App Service managed-identity protocol
(`handleMsiToken`, a second listener — see below), and the Control Plane is launched with
`--sessionlayer.ca.azure.credential=managed-identity` plus `IDENTITY_ENDPOINT`/
`IDENTITY_HEADER` pointed at it. This was chosen deliberately over the alternatives:

- It is a genuinely **different code path** from the tenant/authority-validated OAuth2
  flow the other credential kinds use — confirmed by decompiling `azure-identity` and
  `msal4j`, not assumed. `ManagedIdentityCredentialBuilder` reaches msal4j's
  `AppServiceManagedIdentitySource`, which does a plain `GET` with an `X-IDENTITY-HEADER`
  and never touches an authority host at all, so there is no msal4j authority-validation
  surprise waiting once a real CP jar is in hand.
- It needs **no Control Plane production-code change**: `managed_identity` is already a
  supported value of `AzureKeyVaultProperties.Credential`.
- It is **the credential documented as the production recommendation** (a user-assigned
  managed identity via Workload Identity Federation — no secret to leak or rotate), so
  this leg exercises the real shape a production deployment would use, not a test-only
  shortcut.

Verified against the exact code path — `new ManagedIdentityCredentialBuilder().build()`,
the same one `AzureKeyVaultSignerFactory.buildCredential`'s `MANAGED_IDENTITY` branch
takes, not inferred from `DefaultAzureCredential`'s broader chain — with the real CP
classpath (`azure-identity` 1.18.4, `azure-security-keyvault-keys` 4.11.1, `msal4j`
1.23.1, the JDK HTTP client). One real transcript, in order:

```
GET  /keys/{name}/{version}?api-version=2025-07-01                                  bearer=false
GET  /msi/token?api-version=2019-08-01&resource=https%3A%2F%2Fvault.azure.net        bearer=false
GET  /keys/{name}/{version}?api-version=2025-07-01                                   bearer=true
GET  /keys/{name}/{version}?api-version=2025-07-01                                   bearer=true
POST /keys/{name}/{version}/sign?api-version=2025-07-01                              bearer=true  -> SIGN_LEN=64, VERIFIES=true
POST /keys/{name}/{version}/sign?api-version=2025-07-01                              bearer=true  -> SECOND_SIGN_OK
```

The two authenticated `GET`s are `KeyClient.getKey` (adoption) and `CryptographyClient`'s
own internal key lookup before it will sign; the token endpoint is hit **exactly once**
across all of that — the credential caches and reuses the token, it does not fetch one
per operation. `assert_keyvault_credential_flow` in `run.sh` pins both the "first request
is unauthenticated" and "exactly one token fetch" properties.

**Both of those checks were wrong the first time they ran against a real jar**, and the
bug in each was the same shape: `start_keyvault_double`'s own readiness `curl` also
touches `/keys/...` and `/msi/token` (bare, no query string, `User-Agent: curl/...`), and
neither check excluded it. The token-count check simply over-counted — it failed loudly,
2 instead of 1, easy to notice. The "first request is unauthenticated" check was worse:
it read `head -1` of the log, which is the harness's *own* probe, not the Control Plane's
— and since both happen to be `bearer=false`, **it had been passing the whole time, for
the wrong reason.** The conclusion survived (the CP's real first request genuinely is
unauthenticated) but that was luck, not evidence; a different SDK behaviour would have
sailed through undetected. Fixed by filtering to lines carrying the SDK's own
`User-Agent: azsdk-...` and, for the token count, requiring the `?api-version=...` query
string only the SDK sends. Caught by re-reading the actual preserved log a real run
produced, not by reasoning about what the log ought to contain.

### The `/msi/token` endpoint is plain HTTP, on purpose, and never challenged

`handleMsiToken` runs on a second, separate `HttpServer` (never `HttpsServer`, never
routed through `dispatch`) so it is structurally impossible for it to end up behind the
vault's own challenge — a credential would need a token in order to fetch a token, which
has no recovery. Plain HTTP is the faithful choice, not a shortcut: real Azure App
Service's own equivalent endpoint is plain HTTP to a loopback address. It answers
unconditionally with an unvalidated fake token; nothing downstream checks the value,
matching "any token satisfies the double" for the vault side too.

## The two load-bearing conversions

- **JWK coordinates are fixed-width 32-byte unsigned big-endian.**
  `BigInteger.toByteArray()` is signed and minimal — 33 bytes when the high bit is set,
  short when there are leading zero bytes — either of which decodes to the wrong EC
  point if copied verbatim. `coordinate()` right-aligns into a fixed 32-byte buffer.
- **The JDK signs DER; Key Vault returns P1363 `r‖s`.** `derToP1363()` converts. Returning
  DER here would be the exact bug the Control Plane's `EcdsaSignatures.fromP1363`
  normalization exists to catch, so this conversion is what makes the double faithful
  rather than merely functional.

Both were verified with a standalone signature-verification round-trip (JWK → EC public
key → verify the double's own P1363 output) before this double was wired into `run.sh`.

## The fault-mode toggle (D-2, `assert_keyvault_wrong_key_rejected`, a permanent scenario)

`GET /_test/fault-mode?mode=wrong_key|none` is not part of the Key Vault REST API — it
is this double's only admin surface, deliberately exempt from the challenge above (the
harness drives it directly with `curl`, not through the SDK). `run.sh`'s
`assert_keyvault_wrong_key_rejected` calls it directly, on every run, proving the Control
Plane's D-2 guard (every signature is verified locally against the pinned public key
before being trusted) holds at the real network/JVM boundary, not only in a CP unit
test — it is not a one-off manual exercise or a claim resting on a transcript captured
once. In `wrong_key` mode, `POST .../sign` signs with an unrelated keypair generated at
startup instead of the real CA key, while `GET .../{version}` keeps reporting the real
CA key's coordinates honestly — the fault this double injects is a vault that signs with
the wrong key while still describing itself correctly, which is the failure shape D-2
exists to catch. The scenario restores `mode=none` and asserts a normal session succeeds
immediately after — without that, "the session failed" cannot be told apart from "the
fault-mode toggle broke the double". The restore is unconditional (checked in
`cleanup()`, not only at the end of the happy path): a `die()` partway through this
scenario must not leave the double faulted for whatever inspects or reuses it next.

In this scenario, unlike `assert_keyvault_fail_closed`, the session genuinely fails *and*
the vault genuinely gets called (it signs — just with the wrong key), so the cp.log grep
for the D-2 signature-verification-failure message is **load-bearing, not corroborating**:
nothing else here distinguishes "D-2 caught it" from "the session failed for some
unrelated reason". That string is owned by `ControlPlane`'s `AzureKeyVaultSigner`, and it
is known to drift — a `"(D-2)"` suffix has already been removed from it upstream once —
so if this grep ever starts failing, re-read that class fresh rather than assume the
guard broke.

The toggle is a runtime switch rather than a process restart with a different key
deliberately: the double runs on an OS-assigned ephemeral port, and the Control Plane's
`sessionlayer.ca.azure.vault-uri` / the rotated CA's `keyReference` are both fixed at CP
boot to that one port. Restarting the double to change its key would either have to
rebind the same port (racy) or force a second CP boot; toggling a mode on the same
long-lived process avoids both.

## What the request log proves, and what it does not

Every request (method, path, whether a bearer token was present, headers, body) is
appended to `--request-log`. Two things make a line's shape less obvious than it looks,
and both have already caused a real bug in this harness (see above and the fault-mode
section): because of the real challenge, every genuine Key-Vault-shaped operation appears
as *at least* two lines (an unauthenticated probe, then the authenticated replay), and
the SDK appends its own `?api-version=...` query string that this harness's own `curl`
based readiness probes and admin calls do not. Any check reading this log has to decide,
explicitly, which lines are the Control Plane's and which are the harness's own plumbing
— `bearer=true`, a `?` in the path, or the SDK's `User-Agent: azsdk-...` prefix, depending
on what's being checked — rather than assume the log contains only what the CP produced.

The harness greps this log for: an authenticated `GET /keys/{name}/{version}` at CA
adoption (proof the Control Plane actually read the key from "the vault" rather than
trusting a locally-cached assumption), an authenticated `POST .../sign` count before/after
a session (proof a session's certificate was actually signed there, and — stopping the
double — proof a failed session's sign attempt genuinely never reached it), and exactly
one SDK-originated `GET /msi/token` across the whole run (proof the credential caches its
token rather than fetching one per operation). It does **not** prove API-version
compatibility beyond "any value is accepted", which is intentionally permissive, and it
is **not** how "was a certificate issued" is checked any more — see below.

## How "no certificate was issued" is actually checked — and how it used to be checked wrongly

The harness never puts the actual minted inner-leg certificate on disk to inspect with
`ssh-keygen -L`; there is no existing seam in the Gateway that logs or persists it, and
adding one would be a Gateway code change outside this double's scope. The positive claim
("the session's certificate was signed in Key Vault") is proven by the vault's own sign
count increasing. The negative claim ("no certificate was issued", needed by both
`assert_keyvault_wrong_key_rejected` and `assert_keyvault_fail_closed`) is proven by
`keyvault_certificate_issued_for_session` in `run.sh`: the absence of a `session.sign`
audit event with `outcome: success` for the specific new session, found by diffing
`session_ids()` before/after the attempt.

**The first version of this check asserted "no new recording appeared" instead, and it
was wrong** — found the first time either scenario ran against a real Control Plane jar,
not by review. A recording is created, uploaded and finalized for a session regardless of
whether its inner-leg certificate was ever obtained, because recording is gated on the
*outer*-leg connection succeeding, not on cert issuance; the Gateway's own log for a
correctly-rejected wrong-key attempt still shows `recording finalized ... byte_len=217`.
"No new recording" therefore proved nothing about certificate issuance — it happened to
look right in a design review, but the first real run showed it asserting a real security
control (D-2) had failed when it had, in fact, fired exactly as intended.

One more thing this surfaced, reported and being fixed on the Control Plane side rather
than here: a rejected sign today leaves **no `session.sign` audit event at all**, success
or denied — `SessionCertificateService`'s error handling has explicit paths only for
`GatewayRequestException`/`NoSignerAvailable`, and an unmapped exception like a Key Vault
signature-verification failure propagates without ever being audited. On a platform whose
audit trail is a stated property, a CA signing failure that leaves no trace of itself is a
real gap, not a rounding error. `keyvault_certificate_issued_for_session` checks for the
absence of a **success** event specifically, not the absence of any event, so it keeps
working once that gap is closed and a denied event starts appearing where today there is
nothing.

## Running it standalone

```bash
keytool -genkeypair -alias kv -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA \
  -keystore kv.p12 -storetype PKCS12 -storepass changeit -keypass changeit \
  -dname CN=sl.vault.azure.net -ext "san=dns:sl.vault.azure.net,ip:127.0.0.1" -validity 3650

# needs 127.0.0.1 sl.vault.azure.net in /etc/hosts first
java KeyVaultDouble.java --keystore kv.p12 --storepass changeit --hostname sl.vault.azure.net \
  --key-name session-ca --request-log requests.log

# unauthenticated -> 401 + challenge:
curl -sk -i https://sl.vault.azure.net:<port>/keys/session-ca/0123456789abcdef0123456789abcdef
# authenticated (any bearer value; the double never validates it) -> 200:
curl -sk -H 'Authorization: Bearer x' https://sl.vault.azure.net:<port>/keys/session-ca/0123456789abcdef0123456789abcdef

# the managed-identity token endpoint (plain HTTP, never challenged):
curl "http://127.0.0.1:<msi-port>/msi/token?api-version=2019-08-01&resource=https%3A%2F%2Fvault.azure.net"
```

prints `KEYVAULT_URL=`, `KEY_ID=`, `MSI_ENDPOINT=`, and `PUBKEY_SPKI_B64=` on stdout and
then serves until killed. `run.sh`'s `start_keyvault_double`/`build_keyvault_trust_material`
do the `/etc/hosts` mapping, the keystore generation, and the truststore merge (copying the
JDK's own `cacerts` rather than replacing it, so the Control Plane's other outbound HTTPS
trust is untouched), and scrape the three `KEY=value` lines from the double's own log
file the same way `start_cp` scrapes the bootstrap credential from `cp.log`.
