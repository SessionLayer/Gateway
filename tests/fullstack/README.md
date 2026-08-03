# Full-stack cross-repo E2E (`tests/fullstack/`)

The **only** test that runs the real Control Plane jar, the real Gateway binary, a
real node (Debian-13 OpenSSH), and a real stock `ssh` client **together**, driving a
session through the **real CP `Authorize` decision**. Every per-repo Docker E2E uses
a `MockCp`; this one does not — so it is the only place the actual CP authorization,
session-cert signing, and recording paths are exercised end to end.

It is also the platform's **first-install acceptance test**: the whole install is
performed over the REST API with the database made unreachable, and the run ends by
decrypting the session's recording with a private key the Control Plane never saw.

It lives inside the Gateway repo (committed) so it can run in CI.
`.github/workflows/fullstack-e2e.yml` checks out CP + Agent + Gateway, builds the CP
boot jar and the Agent binary, and invokes `run.sh` with the env interface below.

## External env interface (what CI sets)

| var | required | meaning |
|-----|----------|---------|
| `CP_JAR` | **yes** | path to the real `controlplane-*.jar` boot jar |
| `AGENT_BIN` | for `TOPOLOGY=agent\|all` | path to the real `sessionlayer-agent` executable |
| `GATEWAY_BIN` | no | prebuilt gateway binary; if unset, `run.sh` runs `cargo build -p gateway` |
| `TOPOLOGY` | no | `core` (default) · `agent` · `all` |

Everything else — infra (Postgres + MinIO via `infra-compose.yml`), the node/client
container images (`tests/fixtures/{sshd,ssh-client}`), CP launch, provisioning, and the
real Gateway/Agent launch — the harness stands up itself.

Ports default **high** and are all env-overridable, so a run coexists with a developer's
already-running parent dev stack: `FS_PG_PORT` (55432), `FS_MINIO_PORT` (59000),
`FS_CP_MTLS_PORT` (19443), `FS_CP_REST_PORT` (18080), `FS_GW_SSH_PORT` (12201),
`FS_KMS_PORT` (14566). Scratch
lives in `SL_FS_WORKDIR` (`/tmp/sl-fullstack`) — a fixed, shared path, so a second run's
`preflight` (`rm -rf "$WORKDIR"`) can delete a prior run's logs on a box where more than
one of these runs. `cleanup` therefore copies `cp.log`, `gateway.log` and the Key Vault
double's `requests.log` out to `SL_FS_EVIDENCE_DIR` (`/tmp/sl-fullstack-evidence` by
default) **before** anything else, into a `<timestamp>-<pid>` subdirectory unique to that
run regardless of overrides — unconditionally, on every exit, success or failure, since a
failed run is exactly the one whose evidence is most worth keeping. `KEEP_UP=1` leaves
everything running for inspection too.

Three knobs shape the run rather than the ports: `BOOTSTRAP_USER` names the escape-hatch
operator (its password is generated per run and never leaves the harness);
`GW_MAX_DECISION_TTL_SECS` (8) caps the Control Plane's `decision_ttl` on the Gateway so
scenario 6a can cross the re-`Authorize` boundary inside a test run; and
`FS_REVALIDATE_WAIT_SECS` (the cap plus five) is how long scenario 6a holds the connection
open before opening its second channel. The wait is deliberately separate from the cap:
raising the cap above the wait, changing nothing else, must make that scenario fail with
exactly one decision, and an assertion that cannot be made to fail is indistinguishable
from one that never runs.

## Run it

The CP jar starves easily on a small box, so hold the shared build lock for the whole
live run — a concurrent `cargo`/`mvn` gate has been observed starving the CP JVM into
false gRPC `Cancelled` results:

```bash
CP_JAR=/path/controlplane-0.1.0.jar \
  flock /tmp/sl-build.lock bash tests/fullstack/run.sh
```

Beyond `docker`/`openssl`/`ssh-keygen`/`curl`/`python3`/`java` (all checked by
`preflight`), the Key Vault CA leg (row 13) needs `keytool` (bundled with the JDK) and
**passwordless `sudo`**: `ensure_keyvault_hostname` maps `127.0.0.1 sl.vault.azure.net`
in `/etc/hosts` if it is not already there, because the Key Vault double's TLS
certificate and the real SDK's challenge-resource check both require it to be served
from a hostname, never an IP — see `keyvault/README.md`. If `sudo -n` fails, the run
dies naming that reason rather than silently degrading.

The AWS KMS leg (row 14) needs no host tooling at all beyond `docker`: it runs
`localstack/localstack:4` with `SERVICES=kms` and drives it with the `awslocal` bundled
inside that image, so neither an AWS CLI nor an AWS account is involved. Set `KMS_IMAGE`
to pin a different tag.

## The first install, and what the no-database guard actually proves

Every step of the install is an API call. In order:

| Step | Call |
|---|---|
| Bootstrap the first admin | the printed credential, scraped from `cp.log`, surrendered to `POST /v1/bootstrap/claim` naming the Basic escape-hatch username as the subject |
| Hand over to a machine identity | `POST /v1/service-accounts`, `POST /v1/service-accounts/{id}/credentials`, `POST /v1/role-bindings`, then `POST /v1/oauth2/token` |
| Export the trust material | `GET /v1/cas/mtls/trust-anchor` and `GET /v1/cas/session/public-key` |
| Provision the recording key + WORM default | `PUT /v1/operator-settings/recording-customer-key`, `PUT /v1/operator-settings` |
| Grant access | `POST /v1/rules`, `POST /v1/pins` |
| Admit the Gateway | `GET /v1/gateways?name=…` (+ `DELETE /v1/gateways/{id}` if the name is held), then `POST /v1/gateway-enrollment-tokens` |
| Register the node | `POST /v1/nodes` (agentless, dial address + `pinnedHostKey`; the CP creates the pinned host anchor, so no TOFU) |
| Retrieve the recording | `GET /v1/recordings`, `POST /v1/recordings/{id}/export` |

**The first credential.** Something has to be first. Deployment configuration arms the
HTTP Basic escape hatch (`sessionlayer.rest-security.basic-auth.*`, CIDR-scoped to
127.0.0.1); the Control Plane prints a one-time bootstrap credential to its log on a first
boot; the claim binds `platform-admin` to whichever subject it names, and the escape-hatch
username is that subject, so the Basic caller resolves every permission. The escape hatch
is then used only to create a real machine identity, and everything after that runs on a
client-credentials bearer. The harness computes the bcrypt hash with the Control Plane's
own `spring-security-crypto`, lifted out of `CP_JAR`, so no static credential lives here
and no bcrypt tool is needed on the runner.

**The guard.** `psql`, `pg_dump`, `pg_restore` and `pg_isready` are shadowed by `exit 97`
stubs for the entire run. The phases that are pure REST additionally shadow `docker`,
because this harness reaches Postgres as `docker compose exec postgres psql` — a host-PATH
stub can never intercept that, which is why the previous, narrower shim could not have
failed. And `db_fixture`, the one function that talks to the database, refuses outright
while any operator step is open: a shell function bypasses `PATH` entirely, so neither
stub would have caught it.

Each of those three routes fails differently, so one of them passing says nothing about
the others. All three have been put back inside a guarded step and watched to kill a real
run — the host binary, the container route, and the shell function — and the guards have
been checked to lift correctly afterwards too, since one that never released `docker`
would break teardown. Neither half is worth assuming.

Two details that are subtler than they look:

- **Node `TrustedUserCAKeys` is the SESSION CA, not the mTLS CA.** The inner-leg user
  certificate is signed by `ca_kind='session'`, so that is the key a node must trust. The
  export returns it as a ready-to-paste OpenSSH line, and the harness checks that
  `ssh-keygen -l` agrees with the fingerprint the API served.
- **Recording is mandatory and fails closed** without a customer key, so a Control Plane
  with none refuses every session — which is what made this the step that used to force an
  operator to hold a database credential. The MinIO WORM store needs only
  `SESSIONLAYER_RECORDING_WORM_ENDPOINT`; the CP auto-creates the object-lock bucket.

## What still uses the database

One function, outside the guarded region, and it is an assertion rather than a step:
`assert_recording_store_integrity`. It reads `content_digest`, which has no API projection
by design — internal tamper-evidence, not something an operator acts on — and it runs
`mc stat` against the object store, because the object lock is a property of the store
rather than of the Control Plane's metadata, so no endpoint could report it. Both reasons
are recorded at the call site.

Freeing a Gateway name before re-enrolment used to be the harness's other database call.
It is now `GET /v1/gateways?name=…` followed by `DELETE /v1/gateways/{id}?force=true`,
inside the guarded flow like every other operator step — which is also the recovery path
the disaster-recovery guide describes.

## Scenario matrix — live here vs referenced per-repo

A scenario is listed **LIVE** only if this run actually asserts it; otherwise the
real-binary coverage that does prove it is named. Honest env scope is the point: a row
claimed here that `run.sh` does not assert would be worse than no table at all.

| # | scenario | status |
|---|----------|--------|
| 0 | **First install with no database credential**: bootstrap claim → machine identity → trust anchor + session CA → recording key + WORM ratchet → rule + pin → Gateway token → node registration, every step over REST with `psql`, `docker` and `db_fixture` all refusing | **LIVE (core)** |
| 1 | **CORE**: `ssh deploy%web-01@gw` runs on the real node through the real CP `Authorize` | **LIVE (core)** |
| 2 | **Recording export + decrypt-proof**: the recording is retrieved through `POST /v1/recordings/{id}/export`, is opaque SLREC1 of the recorded size with no plaintext, ECIES-opens with the customer private key to the original session (marker present), and its hash-chain recomputes to the finalized head; the stored object is COMPLIANCE-locked and matches the recorded `content_digest` | **LIVE (core)** |
| 3 | **Audit dimensions**: the connect/authorize event is searchable by each of source_ip / access_model / capability / node_label / correlation_id, and one correlationId returns the connect→recording chain | **LIVE (core)** |
| 4 | **Bridge multi-host inner-cert** regression guard: node on a distinct SNAT IP → the session succeeds, which it cannot if the inner cert carries a client-IP `source-address` pin | **LIVE (`TOPOLOGY=all` / `FS_NODE_NETMODE=bridge`)** |
| 5 | **Deny-path** fail-closed (deny-wins): an ungranted login is refused by the real CP (§7.1 generic) | **LIVE (core)** |
| 6 | **CP-down** fail-closed (NFR-2): the real CP is killed → a new session fails closed, never fail-open | **LIVE (core)** |
| 6a | **FR-CHAN-2 per-channel re-`Authorize`**: a ControlMaster channel opened past `decision_ttl` succeeds **and** a second `authz.decision` is recorded against the same session id | **LIVE (core)** |
| 7 | **Outbound-agent** connector: a node reached via the real Agent (dial-out WSS → dial-back splice) | referenced: `agent_e2e.rs` + `splice_e2e.rs` (real Agent binaries); full-stack flow scaffolded (`tests/fullstack/agent-node/` + `gateway-agent.json.tmpl` + `AGENT_BIN`), not yet a live assertion |
| 8 | Lock mid-session teardown of a live recorded session | referenced: `recorder_it.rs` (real binaries, both strict + best_effort) |
| 9 | JIT self-approval refused | referenced: `breakglass_it.rs` / CP JIT ITs |
| 10 | Break-glass can't override a Lock / FIDO2 | referenced: `breakglass_it.rs` (real `sk-dummy`) |
| 11 | HA owner-kill fail-closed (NFR-1) | referenced: `ha_e2e.rs` + `ha_instance_kill_it.rs` |
| 12 | Wrong host key rejected (no TOFU) | referenced: `hostverify` + `inner_leg_it.rs` |
| 13 | **Key Vault CA backend**: before rotation, the vault double receives zero requests despite the Control Plane booting fully configured for it (D-4's "configuring changes nothing until rotated", asserted, not just observed). The session CA is then rotated onto an Azure-Key-Vault-backed key over REST (no database credential; `POST /v1/cas/{id}/rotate`), authenticated via the App Service managed-identity credential (a real challenge/token round trip, verified to fetch the token exactly once), the CP is proven to be publishing the vault's own public key, trust is redistributed to the node, and a real session's certificate is signed there (the vault double's sign count increases). A session while the vault is signing with the WRONG key is refused and issues no certificate (D-2, checked via the absence of a successful `session.sign` audit event for that session — not "no recording appeared", which is created regardless of inner-leg outcome and was this scenario's own bug the first time it ran for real), and a normal session succeeds again immediately after restoring the double — a permanent scenario on every run, not a one-off manual exercise. With the vault stopped a new session fails closed by the same certificate-issuance check, with the vault's sign count staying flat as a second, independent signal — not by parsing the issued certificate (no seam puts one on disk without a Gateway code change) — and never falls back to `local` (D-4) | **LIVE (core)** — see the CI note below |

| 14 | **AWS KMS CA backend**: the Control Plane refuses to start at all with a plaintext `endpoint-override` and no `allow-insecure-endpoint` (the real jar, booted once for that alone). Before rotation, KMS serves zero calls beyond the harness's own, despite the Control Plane booting fully configured for it. The session CA — by then on Key Vault — is rotated **on again** to a KMS-held key over REST with no database credential, the Control Plane is proven to publish the key KMS itself generated, trust is redistributed, and a real session's inner-leg certificate is signed there (KMS's own request log records the `Sign`; it recorded none before). With the KMS container stopped, a new session fails closed and issues no certificate, KMS's sign count staying flat as a second, independent signal — then KMS is restarted, a fresh key adopted and a normal session run, so "it failed" is distinguishable from "the harness broke" | **LIVE (core)** |

Do not claim a row is LIVE unless `run.sh` asserts it.

### The Key Vault CA leg (row 13) depends on the Control Plane it is run against

Row 13 exercises `--sessionlayer.ca.azure.*`, the Azure Key Vault CA backend.
`.github/workflows/fullstack-e2e.yml` builds the CP jar from `ControlPlane`'s
`main` branch, so this leg requires that the checked-out Control Plane carries
the `azure_keyvault` backend; against a Control Plane checkout that predates
it, point `CP_JAR` at a jar that includes it instead. Every other row is
unaffected: the Key Vault properties are passed to `start_cp` unconditionally,
but a Control Plane without the feature simply ignores an unbound property,
and the first session in row 1 still runs on the `local` backend regardless.

The double now issues Key Vault's real `WWW-Authenticate` challenge, so the Control Plane
needs a `TokenCredential` that can actually obtain a token in a harness with no real
Entra tenant. Resolved: `--sessionlayer.ca.azure.credential=managed-identity` against the
double's own App Service managed-identity endpoint — no Control Plane code change, and
the credential documented as the production recommendation. See `keyvault/README.md` for
the verified transcript.

### The AWS KMS CA leg (row 14) runs against LocalStack, not a double

There is no hand-written KMS double in this repo. `localstack/localstack:4` performs real
P-256 key generation and real ECDSA signing over the real AWS protocol, so the leg
exercises the Control Plane's genuine SDK path — request signing, endpoint resolution, the
credential chain, the DER `SEQUENCE{r,s}` response — rather than a double of our own
interface. The key is created with the `awslocal` inside the container, and the ARN and
SPKI it reports are what every later assertion is judged against.

Three things about this leg are easy to get wrong:

- **The counter is LocalStack's request log**, read with `docker logs` and matched as
  `AWS kms.Sign => 200`. The `=> 200` is load-bearing: a refused `Sign` logs the same
  operation name with a 4xx, and counting it would read as a signature that never
  happened. `docker logs` keeps serving a **stopped** container's output, which is what
  makes the counter usable in the fail-closed scenario. `start_kms_localstack` reads the
  baseline through the same polling helper the assertions use, so a run where the log line
  stops matching dies there naming it, instead of every later check silently counting zero.
- **The port is fixed** (`FS_KMS_PORT`), unlike the Key Vault double's OS-assigned one.
  The Control Plane's `endpoint-override` is bound at boot, and the fail-closed scenario
  restarts the container — which is exactly when docker hands a `0` host port a different
  number.
- **Recovery is a second adoption, not a restart.** LocalStack community holds its keys in
  memory, so a restarted container has lost the CA key; `restore_kms_and_run_a_session`
  therefore creates a fresh key, rotates onto it and runs a real session, reusing the same
  functions the first adoption used. That is also what the loss of a real KMS key would
  force an operator to do.

The rotation is deliberately sequenced **after** the Key Vault leg rather than instead of
it: the session CA is already on Key Vault when this starts, so it is a
key-service-to-key-service rotation and no signature in it can be served by a
database-held private key. `assert_keyvault_fail_closed` has also stopped the vault double
by then, so a session that runs at all here cannot have been vault-signed either.

## Cross-repo defects only this harness can surface

Finding a real cross-repo bug the per-repo `MockCp` suites structurally cannot is the whole
point of running the real binaries together. Two are permanently guarded here.

### The inner-leg certificate must carry no client-IP `source-address`

The inner-leg session certificate is presented **by the Gateway** to the node, and the
Gateway dials the node with a plain `TcpStream::connect` (`gateway-core/src/ssh/connector.rs`,
no source preservation). So a `source-address` critical option pinned to the outer client's
IP is checked by the node's `sshd` against the **Gateway's** peer address, not the client's.
The two coincide only in a single-host all-loopback topology. Anywhere else — any real
multi-host or NAT deployment, and any docker bridge port-map where the node sees the SNAT
`172.17.0.1` — the node rejects an otherwise-valid, CA-trusted certificate with
`Authentication tried for deploy with valid certificate but not from a permitted source
address … Refused by certificate options`, and the Gateway surfaces the generic "node
offline".

The Control Plane therefore **omits** `source-address` on that certificate. What binds it
is stronger and does not depend on topology: it is session-bound, short-TTL, single-use,
node-host-verified, and its key never leaves the Gateway (D2). Source-IP enforcement lives
on the outer leg and in `Authorize` (Design §5.6), where the address is the client's. The
Control Plane's unit guard is `SessionSigningIT.mintedInnerCertOmitsSourceAddress`. This is
a deliberate deviation from the letter of Design §3.3 ("source-address pinned"), which is
unimplementable as written.

`FS_NODE_NETMODE=bridge` is the live guard: it runs the node on a docker port-map so its
`sshd` observes a distinct IP from the client. Every per-repo real-node test passes with a
client-IP pin in place, because `MockCp` omits the option entirely; and even here the
default `FS_NODE_NETMODE=loopback` would match `127.0.0.1` and pass. Only the bridge
variant fails.

### The per-channel re-`Authorize` (FR-CHAN-2)

A re-`Authorize` runs with the **same** `session_id`, so it collides with the row the first
`Authorize` wrote. A Control Plane that inserts rather than refreshing that row rolls back
the whole allow transaction and surfaces a plain DENY, breaking every multiplexed channel —
a second shell, `scp`/`sftp`, ControlMaster reuse — on any connection older than
`decision_ttl`. `MockCp` has no `ssh_session` table and cannot exhibit it, and a one-shot
`ssh <cmd>` opens its only channel immediately and never crosses the boundary. Scenario 6a
is the only place the composition is exercised: it lowers `ssh.reeval.max_decision_ttl_secs`,
opens a ControlMaster, waits past the cap, and opens a second channel — asserting both that
it runs **and** that the Control Plane recorded a second `authz.decision` for that session
id, because success alone is also what a re-validate that never ran looks like.
