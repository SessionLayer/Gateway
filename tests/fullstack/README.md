# Full-stack cross-repo E2E (`tests/fullstack/`)

The **only** test that runs the real Control Plane jar, the real Gateway binary, a
real node (Debian-13 OpenSSH), and a real stock `ssh` client **together**, driving a
session through the **real CP `Authorize` decision**. Every per-repo Docker E2E uses
a `MockCp`; this one does not — so it is the only place the actual CP authorization,
session-cert signing, and recording paths are exercised end to end.

It lives inside the Gateway repo (committed) so it can run in CI. The lead's cross-repo
workflow checks out CP + Agent + Gateway, builds the CP boot jar and the Agent binary,
and invokes `run.sh` with the env interface below.

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
`FS_CP_MTLS_PORT` (19443), `FS_CP_REST_PORT` (18080), `FS_GW_SSH_PORT` (12201). Scratch
lives in `SL_FS_WORKDIR` (`/tmp/sl-fullstack`); `KEEP_UP=1` leaves everything running for
inspection.

## Run it

The CP jar starves easily on a small box, so hold the shared build lock for the whole
live run (the S15 lesson — a concurrent `cargo`/`mvn` gate can starve the CP JVM into
false gRPC `Cancelled`):

```bash
CP_JAR=/path/controlplane-0.1.0.jar \
  flock /tmp/sl-build.lock bash tests/fullstack/run.sh
```

## What it provisions (and why by SQL)

There is still no CP dev-seed / admin API for most trust + inventory, so `seed_cp()`
reproduces the proven `scripts/ha-e2e.sh` bootstrap over SQL against the compose
Postgres: the internal **mTLS CA** (gateway trust anchor), a gateway enrollment token, a
`dp_rule` allow, the client **pin**, and the recording **customer key**. Two things are
subtler than ha-e2e.sh:

- **Node `TrustedUserCAKeys` = the SESSION CA, not the mTLS CA.** The inner-leg user cert
  is signed by `ca_kind='session'`; that CA's key is stored as a DER SPKI EC P-256 public
  key, converted to an OpenSSH line with `ssh-keygen -i -m PKCS8`.
- **Recording is mandatory and fails closed** without a customer key, so the harness seeds
  `operator_settings.recording_customer_public_key` (EC P-256 SPKI) up front — otherwise
  no session can start at all. The MinIO WORM store needs only
  `SESSIONLAYER_RECORDING_WORM_ENDPOINT`; the CP auto-creates the object-lock bucket.

The node is registered agentless via the **S16 REST API** (`POST /v1/nodes` with the dial
address + `pinnedHostKey`), which also proves that admin surface end-to-end; the CP creates
the node (`connector_kind='agentless'`, `status=active`) and the pinned host anchor (no TOFU).
Admin REST calls (`/v1/nodes`, `/v1/join-tokens`, `/v1/audit-events`) authenticate with a CP
**machine bearer** minted from the public `POST /v1/oauth2/token` (client-credentials) for a
SQL-seeded service account granted `audit:read`/`node:enroll` — no browser/OIDC needed. The
OAuth2 request and response are snake_case (`grant_type`/`access_token`).

## Scenario matrix — live here vs referenced per-repo

This mirrors the honest env-scope posture of the S15 HA RESULT: a scenario is only listed
**LIVE** if this full-stack run actually asserts it; otherwise the real-binary coverage
that does prove it is named.

| # | scenario | status |
|---|----------|--------|
| 1 | **CORE**: `ssh deploy%web-01@gw` runs on the real node through the real CP `Authorize` | **LIVE (core)** |
| 2 | **Recording integrity**: finalized SLREC1 WORM object, COMPLIANCE-locked, opaque (no plaintext), size+digest match | **LIVE (core)** |
| 3 | **Audit dimensions** (Part B): the connect/authorize event is searchable by each of source_ip / access_model / capability / node_label / correlation_id, and one correlationId returns the connect→recording chain | **LIVE (core)** |
| 4 | **Outbound-agent** connector: a second node reached via the real Agent (dial-out WSS → dial-back splice) | _pending (`TOPOLOGY=agent`)_ |
| 5 | JIT self-approval refused | referenced: `breakglass_it.rs` / CP JIT ITs |
| 6 | Lock mid-session teardown of a live recorded session | referenced: `recorder_it.rs` (real binaries) |
| 7 | HA owner-kill fail-closed (NFR-1) | referenced: `scripts/ha-e2e.sh` + `ha_e2e.rs` |
| 8 | CP-down fail-closed (NFR-2) | referenced: outer-leg fail-closed ITs |
| 9 | Wrong host key rejected (no TOFU) | referenced: `hostverify` + `inner_leg_it.rs` |

This table is the source of truth for the RESULT write-up; do not claim a row is LIVE
unless `run.sh` asserts it.

## Cross-repo findings surfaced

Finding a real cross-repo bug that the per-repo MockCp suites cannot is the whole point
of this harness (the S14/S15 lesson). Surfaced so far:

### F-inner-cert-source-address-1 (owner: ControlPlane-API) — HIGH

The real CP mints the **inner-leg session certificate** with a `source-address` critical
option pinned to the **outer client's** source IP (`AuthorizeRequest.source_ip`, via
`SessionSigningToken.sourceAddress()` → `CertificateProfiles.innerLegSessionCert`,
`ca/cert/CertificateProfiles.java:63`). But that cert is presented **by the Gateway** to
the node, and the Gateway dials the node with a plain `TcpStream::connect`
(`gateway-core/src/ssh/connector.rs:186`, no source preservation) — so the node's sshd
checks `source-address` against the **Gateway's** peer IP, not the client's. They only
coincide in a single-host all-loopback topology (client, Gateway, node all `127.0.0.1`).
In any multi-host / NAT deployment (and on a docker bridge port-map, where the node sees
the SNAT `172.17.0.1`) the node **rejects the otherwise-valid, CA-trusted cert** with
`Authentication tried for deploy with valid certificate but not from a permitted source
address … Refused by certificate options`, and the Gateway surfaces the generic "node
offline". Every per-repo real-node test (`docker_e2e.rs`, `recorder_it.rs`, …) passed
because **MockCp omits `source-address`**, so the real CP's value had never been checked
against a real node until this harness.

Reproduced end-to-end: seed everything, register the node on a **bridge** port-map, and
the inner leg fails with the sshd message above; move the node to `--network host` (all
loopback) and the same session succeeds. `run.sh` therefore defaults to the node on the host
network (`FS_NODE_NETMODE=loopback`) so client=Gateway=node=`127.0.0.1` and the pin is
satisfiable — this both makes the headline path green AND is the minimal reproduction of the
constraint. **Verified-Fixed proof:** once the CP omits `source-address` on the inner cert,
re-run with `FS_NODE_NETMODE=bridge` (node on a docker port-map → it observes the SNAT
`172.17.0.1`, a distinct IP from the client) and the session must now succeed — proving the
multi-host case (this run FAILS against the pre-fix CP, which is the finding).

Proposed fix (CP team's call): the inner (node-facing) cert should not pin
`source-address` to the client IP the node can never observe — either omit it on the inner
cert (it is already session-bound, short-TTL, node-host-verified, and the key never leaves
the Gateway), or pin it to the Gateway's egress identity. The outer-leg credential
`source-address` (pin/OTP/cert, Design §5) is unaffected. Until fixed, agentless nodes are
only reachable where they observe the client's exact source IP.
