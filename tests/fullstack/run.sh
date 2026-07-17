#!/usr/bin/env bash
#
# Full-stack cross-repo E2E — the REAL CP jar + REAL Gateway binary + REAL node +
# REAL stock ssh client, together, driven through the REAL CP Authorize decision.
# This is the proof the per-repo Docker suites (all MockCp) structurally cannot give.
#
# It lives INSIDE the Gateway repo (committed) so it runs in CI: the lead's cross-repo
# workflow checks out CP + Agent + Gateway, builds the CP boot jar and the Agent
# binary, and invokes this script with a clean env interface (see README.md):
#
#   CP_JAR       (required)  path to the real controlplane-*.jar
#   AGENT_BIN    (optional)  path to the real sessionlayer-agent binary (agent topology)
#   GATEWAY_BIN  (optional)  path to the built gateway binary (else this builds it)
#   TOPOLOGY     (optional)  core | agent | all   (default: core)
#
# Topology (CORE, the default): single-instance CP + agentless Gateway + one node
# container (Debian-13 sshd trusting the CP SESSION CA via TrustedUserCAKeys) + a
# stock-ssh client container. Everything else (CP mTLS, node dial address, pinned
# host key, dp_rule allow, client pin, the recording customer key) is provisioned
# by seed_cp() — SQL against the compose Postgres, the proven ha-e2e.sh recipe —
# because the CP still exposes no dev-seed for most of it.
#
# The CP + Gateway run as HOST processes (like ha-e2e.sh); the node + infra run in
# containers with mapped ports. The Gateway dials the node at 127.0.0.1:<node_port>;
# the client container (--network host) dials the Gateway at 127.0.0.1:<gw_ssh_port>.
#
# Ports default HIGH and ENV-overridable so a run coexists with a developer's parent
# dev stack. Cross-repo, so NOT part of `cargo nextest` — run it (under the build
# lock on a small box) via: flock /tmp/sl-build.lock bash tests/fullstack/run.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GW_REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── knobs (all ENV-overridable) ──────────────────────────────────────────────
TOPOLOGY="${TOPOLOGY:-core}"
FS_PG_PORT="${FS_PG_PORT:-55432}"
FS_MINIO_PORT="${FS_MINIO_PORT:-59000}"
FS_MINIO_CONSOLE_PORT="${FS_MINIO_CONSOLE_PORT:-59001}"
FS_CP_MTLS_PORT="${FS_CP_MTLS_PORT:-19443}"
FS_CP_REST_PORT="${FS_CP_REST_PORT:-18080}"
FS_GW_SSH_PORT="${FS_GW_SSH_PORT:-12201}"
WORKDIR="${SL_FS_WORKDIR:-/tmp/sl-fullstack}"
WAIT_SECS="${WAIT_SECS:-300}"   # CP-boot healthz wait; generous for shared-box CPU starvation
GW_NAME="${GW_NAME:-gw-fullstack}"
NODE_NAME="${NODE_NAME:-web-01}"
NODE_LOGIN="${NODE_LOGIN:-deploy}"
FS_NODE_PORT="${FS_NODE_PORT:-12222}"   # node sshd port (host network; see start_node WHY)
# loopback (default): node on --network host, all-loopback (satisfies the pre-fix inner-cert
# source-address pin). bridge: node on a docker port-map so it sees a DISTINCT SNAT IP — the
# multi-host proof for F-inner-cert-source-address-1 once the CP omits inner-cert source-address.
# Node netmode: honor an explicit FS_NODE_NETMODE; otherwise TOPOLOGY=all defaults to the BRIDGE
# (multi-host, distinct-SNAT-IP) variant — the permanent F-inner-cert-source-address-1 regression
# guard — and every other topology to loopback.
FS_NODE_NETMODE="${FS_NODE_NETMODE:-}"
if [[ -z "$FS_NODE_NETMODE" ]]; then
  [[ "$TOPOLOGY" == all ]] && FS_NODE_NETMODE=bridge || FS_NODE_NETMODE=loopback
fi
DENY_LOGIN="${DENY_LOGIN:-dba}"          # a node login the CP never grants (deny-path negative)
DECRYPT_BIN="${DECRYPT_BIN:-$GW_REPO/target/debug/examples/decrypt_recording}"  # SEC-LOW-1/2 prover
CLIENT_IDENTITY="${CLIENT_IDENTITY:-fullstack-user}"
MARKER="FULLSTACK_OK_$$"
KEEP_UP="${KEEP_UP:-}"

MINIO_ENDPOINT="http://127.0.0.1:${FS_MINIO_PORT}"
WORM_BUCKET="sessionlayer-recordings"
MINIO_USER="sessionlayer"
MINIO_PASS="sessionlayer-dev-secret"

CP_REST="http://localhost:${FS_CP_REST_PORT}"
ADMIN_ID="e2e-admin"                                  # machine service account for the admin REST API
ADMIN_SECRET="fs-admin-$$-$(date +%s)"                # client_secret (dev-only, per-run)

NODE_IMAGE="sessionlayer-gw-fullstack-node:s20"
CLIENT_IMAGE="sessionlayer-gw-fullstack-client:s20"
MINIO_IMAGE="minio/minio:RELEASE.2025-04-08T15-41-24Z"
NODE_CONTAINER="sl-fs-node"

COMPOSE=(docker compose -f "$SCRIPT_DIR/infra-compose.yml")
export FS_PG_PORT FS_MINIO_PORT FS_MINIO_CONSOLE_PORT   # consumed by infra-compose.yml

# ── logging ──────────────────────────────────────────────────────────────────
log()  { printf '\033[36m[fs-e2e]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[fs-e2e] OK:\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[fs-e2e] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

PIDS=()
cleanup() {
  local rc=$?
  if [[ -n "$KEEP_UP" ]]; then
    log "KEEP_UP set — leaving CP/Gateway/infra/node up for inspection (rc=$rc)"
    return
  fi
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  docker rm -f "$NODE_CONTAINER" >/dev/null 2>&1 || true
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

PSQL() { "${COMPOSE[@]}" exec -T postgres psql -U sessionlayer -d sessionlayer -v ON_ERROR_STOP=1 "$@"; }
sl_sha() { printf %s "$1" | sha256sum | cut -d' ' -f1; }   # SingleUseTokens.hash = lowercase-hex SHA-256

# ── preflight: inputs + toolchain, no side effects ───────────────────────────
preflight() {
  command -v docker  >/dev/null || die "docker is required"
  command -v openssl >/dev/null || die "openssl is required"
  command -v ssh-keygen >/dev/null || die "ssh-keygen is required"
  [[ -n "${CP_JAR:-}" ]] || die "CP_JAR must point at the real controlplane boot jar"
  [[ -f "$CP_JAR" ]]     || die "CP_JAR does not exist: $CP_JAR"
  case "$TOPOLOGY" in
    core|all) : ;;  # live: loopback (core) / bridge multi-host guard (all)
    agent)
      # The outbound-agent connector is proven per-repo with REAL Agent binaries in
      # gateway-core/tests/agent_e2e.rs + splice_e2e.rs (dial-out WSS + dial-back splice to the
      # node's own 127.0.0.1:22). The full-stack agent flow (real-CP OUTBOUND_AGENT Authorize +
      # presence + real agent enroll) is scaffolded here — tests/fullstack/agent-node/ +
      # config/gateway-agent.json.tmpl + AGENT_BIN — but is NOT yet wired as a live assertion.
      die "TOPOLOGY=agent is scaffolded, not live — the outbound-agent path is proven per-repo (agent_e2e.rs/splice_e2e.rs, real binaries); see README 'Scenario matrix'. Use core|all." ;;
    *) die "unknown TOPOLOGY '$TOPOLOGY' (core|all)" ;;
  esac
  rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"
  ok "preflight: CP_JAR=$CP_JAR TOPOLOGY=$TOPOLOGY workdir=$WORKDIR"
}

# ── build the Gateway binary (unless supplied) + the node/client fixture images ─
build_artifacts() {
  if [[ -z "${GATEWAY_BIN:-}" ]]; then
    log "building the Gateway binary (cargo build -p gateway)"
    ( cd "$GW_REPO" && CARGO_INCREMENTAL=0 cargo build -p gateway >/dev/null 2>&1 ) \
      || die "gateway build failed (run 'cargo build -p gateway' to see why)"
    GATEWAY_BIN="$GW_REPO/target/debug/gateway"
  fi
  [[ -x "$GATEWAY_BIN" ]] || die "GATEWAY_BIN not executable: $GATEWAY_BIN"

  # The recording decrypt-prover (SEC-LOW-1/2): reuses the production seal:: code to ECIES-open
  # the WORM object with the customer PRIVATE key. Built from the workspace unless supplied.
  if [[ ! -x "$DECRYPT_BIN" ]]; then
    log "building the recording decrypt-prover (cargo build -p gateway-core --example decrypt_recording)"
    ( cd "$GW_REPO" && CARGO_INCREMENTAL=0 cargo build -p gateway-core --example decrypt_recording >/dev/null 2>&1 ) \
      || die "decrypt_recording example build failed (run 'cargo build -p gateway-core --example decrypt_recording')"
  fi
  [[ -x "$DECRYPT_BIN" ]] || die "DECRYPT_BIN not executable: $DECRYPT_BIN"

  # Build the fixture images. The ssh-client image compiles OpenSSH (minutes), so
  # reuse an already-built image on a re-run unless FS_FORCE_BUILD is set. CI starts
  # clean (no image) and builds once.
  build_image_once "$NODE_IMAGE"   "$GW_REPO/tests/fixtures/sshd"       "node"
  build_image_once "$CLIENT_IMAGE" "$GW_REPO/tests/fixtures/ssh-client" "ssh-client"
  ok "gateway=$GATEWAY_BIN; node+client images ready"
}

build_image_once() {  # $1=tag $2=context $3=label
  if [[ -z "${FS_FORCE_BUILD:-}" ]] && docker image inspect "$1" >/dev/null 2>&1; then
    log "reusing existing $3 image ($1); set FS_FORCE_BUILD=1 to rebuild"
    return
  fi
  log "building the $3 fixture image ($1)"
  docker build -q -t "$1" "$2" >/dev/null || die "$3 image build failed"
}

start_infra() {
  log "starting infra (Postgres :$FS_PG_PORT + MinIO :$FS_MINIO_PORT)"
  "${COMPOSE[@]}" up -d --wait || die "infra failed to become healthy"
  ok "infra healthy"
}

start_cp() {
  log "starting the real Control Plane jar (mTLS :$FS_CP_MTLS_PORT, REST :$FS_CP_REST_PORT)"
  SESSIONLAYER_CA_LOCAL_ALLOW_DEV_KEK=true \
  SESSIONLAYER_MTLS_SERVER_PORT="$FS_CP_MTLS_PORT" \
  SERVER_PORT="$FS_CP_REST_PORT" \
  SESSIONLAYER_RECORDING_WORM_ENDPOINT="$MINIO_ENDPOINT" \
  SPRING_R2DBC_URL="r2dbc:postgresql://localhost:${FS_PG_PORT}/sessionlayer" \
  SPRING_R2DBC_USERNAME="sessionlayer" SPRING_R2DBC_PASSWORD="sessionlayer" \
  SPRING_FLYWAY_URL="jdbc:postgresql://localhost:${FS_PG_PORT}/sessionlayer" \
  SPRING_FLYWAY_USER="sessionlayer" SPRING_FLYWAY_PASSWORD="sessionlayer" \
    java -jar "$CP_JAR" > "$WORKDIR/cp.log" 2>&1 &
  CP_PID=$!; PIDS+=("$CP_PID")   # CP_PID: the NFR-2 CP-down case kills it explicitly
  local deadline=$((SECONDS + WAIT_SECS))
  until curl -sf "http://localhost:${FS_CP_REST_PORT}/v1/healthz" >/dev/null 2>&1; do
    kill -0 "${PIDS[-1]}" 2>/dev/null || { tail -60 "$WORKDIR/cp.log" >&2; die "CP process exited during startup"; }
    [[ $SECONDS -lt $deadline ]] || { tail -60 "$WORKDIR/cp.log" >&2; die "CP never became healthy"; }
    sleep 2
  done
  ok "Control Plane healthy (log: $WORKDIR/cp.log)"
}

# Extract a CA public key / cert as PEM/OpenSSH from the CP's key store.
extract_ca_pem() {   # $1=ca_kind  -> writes a PEM cert to stdout (mtls path)
  PSQL -tAc "SELECT encode(k.ca_certificate,'base64') FROM runtime.ca_key_material k
             JOIN config.ca_config c ON c.id=k.ca_config_id WHERE c.ca_kind='$1'" \
    | tr -d '\r\n' | { echo '-----BEGIN CERTIFICATE-----'; fold -w64; echo; echo '-----END CERTIFICATE-----'; }
}

# /v1/healthz goes green while the CP's cold-start CA + operator_settings
# provisioning (an ApplicationRunner) may still be running — seeding then reads
# empty CA rows. Gate on the rows actually existing before touching them.
wait_for_provisioning() {
  log "waiting for CP cold-start provisioning (CAs + operator_settings)"
  local deadline=$((SECONDS + 180)) n=""
  until n="$(PSQL -tAc "SELECT
       (SELECT count(*) FROM runtime.ca_key_material k JOIN config.ca_config c ON c.id=k.ca_config_id WHERE c.ca_kind='mtls' AND k.ca_certificate IS NOT NULL)
     + (SELECT count(*) FROM runtime.ca_key_material k JOIN config.ca_config c ON c.id=k.ca_config_id WHERE c.ca_kind='session' AND c.rotation_state='active' AND k.public_key IS NOT NULL)
     + (SELECT count(*) FROM config.operator_settings WHERE singleton=true)" 2>/dev/null)"; [[ "${n// /}" == "3" ]]; do
    [[ $SECONDS -lt $deadline ]] || die "CP cold-start provisioning incomplete (got '$n', expected 3: mtls-cert + session-key + operator_settings)"
    sleep 2
  done
  ok "CP cold-start provisioning complete"
}

seed_cp() {
  local D="$WORKDIR"
  wait_for_provisioning

  log "seed 1/7: internal mTLS CA -> $D/ca.pem (gateway trust anchor)"
  extract_ca_pem mtls > "$D/ca.pem"
  openssl x509 -in "$D/ca.pem" -noout -subject >/dev/null || die "mTLS CA extract failed"

  log "seed 2/7: SESSION CA -> node TrustedUserCAKeys line (ca_kind='session', DER SPKI -> OpenSSH)"
  PSQL -tAc "SELECT encode(k.public_key,'base64') FROM runtime.ca_key_material k
             JOIN config.ca_config c ON c.id=k.ca_config_id
             WHERE c.ca_kind='session' AND c.rotation_state='active'" \
    | tr -d '\r\n' | { echo '-----BEGIN PUBLIC KEY-----'; fold -w64; echo; echo '-----END PUBLIC KEY-----'; } > "$D/session_ca_pub.pem"
  ssh-keygen -i -m PKCS8 -f "$D/session_ca_pub.pem" > "$D/session_ca.line" \
    || die "could not convert the session CA SPKI to an OpenSSH TrustedUserCAKeys line"
  SESSION_CA_LINE="$(cat "$D/session_ca.line")"
  grep -qE '^(ssh-ed25519|ecdsa-sha2)' "$D/session_ca.line" || die "session CA line malformed: $SESSION_CA_LINE"

  log "seed 3/7: gateway enrollment token ($GW_NAME, single-use, SHA-256-hex)"
  PSQL -c "DELETE FROM runtime.gateway_identity WHERE name='$GW_NAME';" >/dev/null || true
  GW_ENROLL_TOKEN="gwfs-$(head -c16 /dev/urandom | xxd -p)"
  PSQL <<SQL
INSERT INTO runtime.gateway_enrollment_token(id,token_hash,gateway_name,single_use,expires_at,created_by)
VALUES (gen_random_uuid(),'$(sl_sha "$GW_ENROLL_TOKEN")','$GW_NAME',true,now()+interval '2 hours','fullstack-e2e');
SQL

  log "seed 4/7: data-plane grant (allow $CLIENT_IDENTITY -> $NODE_LOGIN on any node)"
  PSQL <<SQL
INSERT INTO config.dp_rule(id,name,identity_selector,node_label_selector,principals,ttl_seconds,capabilities,effect,origin)
VALUES (gen_random_uuid(),'fullstack-allow','{"identities":["$CLIENT_IDENTITY"]}'::jsonb,'{}'::jsonb,
        ARRAY['$NODE_LOGIN'],3600,ARRAY['shell','exec'],'allow','api') ON CONFLICT (name) DO NOTHING;
SQL

  log "seed 5/7: client SSH key + pin (fingerprint SHA256:… -> $CLIENT_IDENTITY)"
  rm -f "$D/client_key" "$D/client_key.pub"; ssh-keygen -t ed25519 -N '' -f "$D/client_key" -q
  local fp; fp="$(ssh-keygen -lf "$D/client_key.pub" | awk '{print $2}')"
  PSQL <<SQL
INSERT INTO runtime.pin(id,fingerprint,identity,principals,expires_at)
VALUES (gen_random_uuid(),'$fp','$CLIENT_IDENTITY',ARRAY['$NODE_LOGIN'],now()+interval '2 hours')
ON CONFLICT (fingerprint, identity) DO NOTHING;
SQL

  log "seed 6/7: recording customer key (EC P-256 SPKI -> operator_settings; private half kept locally)"
  openssl ecparam -name prime256v1 -genkey -noout -out "$D/customer_key.pem" 2>/dev/null
  openssl ec -in "$D/customer_key.pem" -pubout -outform DER 2>/dev/null | base64 -w0 > "$D/customer_pub.b64"
  # Also force COMPLIANCE object-lock (the real CP defaults to governance) so the WORM
  # object is immutable-even-to-root, matching the S9 design intent + recorder_it.rs.
  PSQL -c "UPDATE config.operator_settings
           SET recording_customer_public_key = decode('$(cat "$D/customer_pub.b64")','base64'),
               recording_key_seal_algorithm = 'ecies_p256',
               default_worm_mode = 'compliance'
           WHERE singleton = true;" >/dev/null
  local ck; ck="$(PSQL -tAc "SELECT length(recording_customer_public_key) FROM config.operator_settings WHERE singleton=true")"
  [[ "${ck:-0}" -gt 0 ]] || die "customer recording key was not stored"

  log "seed 7/7: admin machine service account (client_secret) + platform role (audit:read, node:enroll)"
  # No REST to provision a service account, so seed it (mirrors AbstractConfigApiIT.tokenWith):
  # secret_hash = lowercase-hex SHA-256 of the client_secret (Secrets.sha256Hex).
  local sh; sh="$(sl_sha "$ADMIN_SECRET")"
  PSQL <<SQL
INSERT INTO config.service_account(id,name,description,auth_method,origin)
VALUES (gen_random_uuid(),'$ADMIN_ID','fullstack e2e admin','client_secret','default') ON CONFLICT (name) DO NOTHING;
INSERT INTO runtime.service_account_credential(id,service_account_id,service_account_name,credential_type,secret_hash,status,issued_at)
SELECT gen_random_uuid(), sa.id, sa.name, 'client_secret','$sh','active',now() FROM config.service_account sa WHERE sa.name='$ADMIN_ID'
  AND NOT EXISTS (SELECT 1 FROM runtime.service_account_credential c WHERE c.service_account_name='$ADMIN_ID');
INSERT INTO config.platform_role(id,name,permissions,description,origin)
VALUES (gen_random_uuid(),'e2e-superadmin',ARRAY['audit:read','node:enroll','lock:write','lock:read']::text[],'e2e','default') ON CONFLICT (name) DO NOTHING;
INSERT INTO config.role_binding(id,role_id,subject_kind,subject,origin)
SELECT gen_random_uuid(), r.id,'user','$ADMIN_ID','default' FROM config.platform_role r WHERE r.name='e2e-superadmin'
ON CONFLICT DO NOTHING;
SQL

  export GW_ENROLL_TOKEN SESSION_CA_LINE
  ok "seed_cp done (mTLS CA + session CA + gw token + dp_rule + pin + customer key + admin SA)"
}

# Mint a CP machine bearer via the public /v1/oauth2/token (client-credentials). The token +
# body are OAuth2 snake_case; the CP self-signs (RS256) + self-verifies (key regenerated per
# boot, so re-mint after any CP restart). Sets $ADMIN_TOKEN.
mint_admin_token() {
  local resp; resp="$(curl -s "$CP_REST/v1/oauth2/token" -H 'Content-Type: application/json' \
    -d "{\"grant_type\":\"client_credentials\",\"client_id\":\"$ADMIN_ID\",\"client_secret\":\"$ADMIN_SECRET\"}")"
  ADMIN_TOKEN="$(printf %s "$resp" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)"
  [[ -n "$ADMIN_TOKEN" ]] || die "could not mint admin machine token (oauth2/token): $resp"
  ok "admin machine bearer minted (client-credentials)"
}

# Generate the node's host key, start the node container with it + the session-CA
# TrustedUserCAKeys, and pin that exact host key in inventory (no TOFU).
start_node() {
  local D="$WORKDIR"
  log "generating the node host key (pinned; no TOFU)"
  rm -f "$D/node_host_key" "$D/node_host_key.pub"
  ssh-keygen -t ed25519 -N '' -f "$D/node_host_key" -q
  NODE_HOSTKEY_LINE="$(awk '{print $1" "$2}' "$D/node_host_key.pub")"     # 'ssh-ed25519 AAAA...' (no comment)
  NODE_HOSTKEY_FP="$(ssh-keygen -lf "$D/node_host_key.pub" | awk '{print $2}')"

  # Node network mode (FS_NODE_NETMODE), and why it matters:
  #   loopback (default): node on --network host, so the Gateway (a host process, plain
  #     TcpStream::connect) reaches its sshd on 127.0.0.1:<port> and the registered dial address
  #     is 127.0.0.1:<port>. Simple single-host connectivity — no docker port-map / SNAT in the
  #     byte path.
  #   bridge: node on a docker port-map, so its sshd sees the inner connection from the docker
  #     SNAT (172.17.0.1) — a DISTINCT IP from the client's 127.0.0.1. This is BOTH the multi-host
  #     proof AND the regression guard for F-inner-cert-source-address-1: the CP now OMITS
  #     source-address on the inner-leg session cert (FIXED in CP e0776a9; unit guard
  #     SessionSigningIT.mintedInnerCertOmitsSourceAddress), so a node reached over a distinct IP
  #     accepts the cert. A re-introduced client-IP source-address pin would still match 127.0.0.1
  #     in loopback (a false-pass) but FAIL here — exactly the MockCp-style blind spot this harness
  #     exists to remove. (Pre-fix, bridge was the finding's repro: the node rejected the cert with
  #     "not from a permitted source address".)
  docker rm -f "$NODE_CONTAINER" >/dev/null 2>&1 || true
  # create -> cp the host key in as root (0600) -> start, so the entrypoint's
  # ssh-keygen -A keeps our pre-placed ed25519 key (it only fills MISSING keys).
  if [[ "$FS_NODE_NETMODE" == bridge ]]; then
    log "starting the node container ($NODE_NAME; BRIDGE port-map — node sees the docker SNAT; multi-host inner-cert regression guard)"
    docker create --name "$NODE_CONTAINER" -p 127.0.0.1:0:22 \
      -e TRUSTED_USER_CA="$SESSION_CA_LINE" "$NODE_IMAGE" >/dev/null
  else
    # The trailing `-p $FS_NODE_PORT` is passed through to sshd (entrypoint `exec sshd -D -e "$@"`).
    log "starting the node container ($NODE_NAME; host-net sshd :$FS_NODE_PORT; all-loopback)"
    docker create --name "$NODE_CONTAINER" --network host \
      -e TRUSTED_USER_CA="$SESSION_CA_LINE" "$NODE_IMAGE" -p "$FS_NODE_PORT" >/dev/null
  fi
  docker cp "$D/node_host_key"     "$NODE_CONTAINER:/etc/ssh/ssh_host_ed25519_key"
  docker cp "$D/node_host_key.pub" "$NODE_CONTAINER:/etc/ssh/ssh_host_ed25519_key.pub"
  docker start "$NODE_CONTAINER" >/dev/null
  # sshd must be listening before the Gateway dials it.
  local deadline=$((SECONDS + 60))
  until docker logs "$NODE_CONTAINER" 2>&1 | grep -q "Server listening on"; do
    docker ps -q --filter "name=$NODE_CONTAINER" | grep -q . || { docker logs "$NODE_CONTAINER" >&2; die "node container exited"; }
    [[ $SECONDS -lt $deadline ]] || { docker logs "$NODE_CONTAINER" >&2; die "node sshd never listened"; }
    sleep 1
  done
  if [[ "$FS_NODE_NETMODE" == bridge ]]; then
    NODE_PORT="$(docker port "$NODE_CONTAINER" 22/tcp | head -1 | sed 's/.*://')"
    [[ -n "$NODE_PORT" ]] || die "could not resolve node mapped port (bridge mode)"
  else
    NODE_PORT="$FS_NODE_PORT"
  fi
  ok "node up: $NODE_NAME sshd on 127.0.0.1:$NODE_PORT (netmode=$FS_NODE_NETMODE, pinned fp $NODE_HOSTKEY_FP)"
}

# Register the agentless node via the S16 REST API (POST /v1/nodes), proving the real admin
# API end-to-end. The CP creates the node (connector_kind=agentless, status=active) AND the
# pinned host anchor (runtime.node_host_key source='pinned_key') from pinnedHostKey — no SQL.
register_node() {
  log "registering $NODE_NAME via POST /v1/nodes (agentless 127.0.0.1:$NODE_PORT, pinned host key)"
  local body resp code
  # Build the JSON with python reading the host-key line from the env (it has spaces + base64
  # chars); never interpolate it into a shell-built JSON string.
  body="$(NODE_NAME="$NODE_NAME" NODE_PORT="$NODE_PORT" HK="$NODE_HOSTKEY_LINE" python3 -c '
import json, os
print(json.dumps({"name": os.environ["NODE_NAME"], "address": "127.0.0.1:" + os.environ["NODE_PORT"],
                  "labels": {"env": "fullstack"}, "pinnedHostKey": os.environ["HK"]}))')"
  resp="$(curl -s -w $'\n%{http_code}' -X POST "$CP_REST/v1/nodes" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -d "$body")"
  code="$(printf %s "$resp" | tail -1)"
  [[ "$code" == 201 || "$code" == 200 ]] || die "POST /v1/nodes failed ($code): $(printf %s "$resp" | head -1)"
  NODE_ID="$(printf %s "$resp" | head -1 | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])' 2>/dev/null)"
  [[ -n "$NODE_ID" ]] || die "POST /v1/nodes returned no node id: $resp"
  ok "node registered via REST (id=$NODE_ID, agentless, active)"
}

# Tier-0 hardening profile for the real-binary run (Session Twenty-One, NFR-5).
# FS_HARDENING: off (default — the S20 baseline, unchanged) | log | seccomp | full.
# The Gateway runs here as an unprivileged user on a high port, so the privilege
# drop is naturally a no-op; seccomp + Landlock are the live-exercised layers,
# proving the enforced profile does NOT break the real SSH data path.
gw_hardening_json() {
  case "${FS_HARDENING:-off}" in
    off)     printf '{}' ;;
    log)     printf '{"seccomp":{"mode":"log"}}' ;;
    seccomp) printf '{"seccomp":{"mode":"enforce"}}' ;;
    full)    printf '{"seccomp":{"mode":"enforce"},"landlock":{"enabled":true,"read_only_paths":["/usr","/lib","/lib64","/etc","/dev","/proc"],"read_write_paths":["%s"]}}' "$WORKDIR" ;;
    *)       die "unknown FS_HARDENING=${FS_HARDENING} (want: off|log|seccomp|full)" ;;
  esac
}

# Under a hardened profile use a SMALL ciphertext-spool threshold so a large
# session spills to disk — exercising that the spool lands in the Landlock-allowed
# data-dir, not /tmp (F-1). Default is the 8 MiB production value.
gw_spool_threshold() {
  case "${FS_HARDENING:-off}" in
    full | seccomp) printf '65536' ;;
    *) printf '8388608' ;;
  esac
}

launch_gateway() {
  local prof="${FS_HARDENING:-off}"
  log "rendering + launching the real Gateway (agentless, single-instance; hardening=$prof)"
  CP_MTLS_ENDPOINT="https://localhost:${FS_CP_MTLS_PORT}" \
  CP_SERVER_NAME="localhost" \
  GW_DATA_DIR="$WORKDIR/gw-data" \
  GW_ENROLL_TOKEN="$GW_ENROLL_TOKEN" \
  GW_CA_PEM="$WORKDIR/ca.pem" \
  GW_NAME="$GW_NAME" \
  GW_SSH_ADDR="127.0.0.1:${FS_GW_SSH_PORT}" \
  GW_HARDENING="$(gw_hardening_json)" \
  GW_SPOOL_THRESHOLD="$(gw_spool_threshold)" \
    envsubst '${CP_MTLS_ENDPOINT} ${CP_SERVER_NAME} ${GW_DATA_DIR} ${GW_ENROLL_TOKEN} ${GW_CA_PEM} ${GW_NAME} ${GW_SSH_ADDR} ${GW_HARDENING} ${GW_SPOOL_THRESHOLD}' \
    < "$SCRIPT_DIR/config/gateway-core.json.tmpl" > "$WORKDIR/gateway.json"
  rm -rf "$WORKDIR/gw-data"; mkdir -p "$WORKDIR/gw-data"
  RUST_LOG="${GW_RUST_LOG:-info}" "$GATEWAY_BIN" --config "$WORKDIR/gateway.json" > "$WORKDIR/gateway.log" 2>&1 &
  GW_PID=$!; PIDS+=("$GW_PID")
  local deadline=$((SECONDS + 180))
  until grep -q "outer SSH leg started" "$WORKDIR/gateway.log" 2>/dev/null; do
    kill -0 "$GW_PID" 2>/dev/null || { tail -40 "$WORKDIR/gateway.log" >&2; die "Gateway exited during startup (enrollment?)"; }
    [[ $SECONDS -lt $deadline ]] || { tail -40 "$WORKDIR/gateway.log" >&2; die "Gateway outer leg never started"; }
    sleep 1
  done
  ok "Gateway enrolled + outer SSH leg on 127.0.0.1:$FS_GW_SSH_PORT (log: $WORKDIR/gateway.log)"
}

# Run one stock-ssh attempt `<login>%<node>` through the Gateway and echo its combined output;
# the caller inspects the exit code + output (used by the deny-path + CP-down negatives).
ssh_attempt() {  # $1=login $2=node $3=remote-command
  docker run --rm --network host -v "$WORKDIR/client_key:/mnt/client_key:ro" --entrypoint sh \
    "$CLIENT_IMAGE" -c "cp /mnt/client_key /root/k && chmod 600 /root/k && \
      ssh -p $FS_GW_SSH_PORT -i /root/k -o IdentitiesOnly=yes -o PreferredAuthentications=publickey \
        -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=25 \
        '$1%$2@127.0.0.1' '$3'" 2>&1
}

# The headline: a stock ssh client runs a command on the REAL node, THROUGH the
# REAL CP Authorize decision. Returns the session output in $SESSION_OUT.
run_session() {
  log "ssh $NODE_LOGIN%$NODE_NAME@gw (:$FS_GW_SSH_PORT) — real CP Authorize -> real node"
  # --entrypoint sh: the ssh-client image's ENTRYPOINT is `sleep infinity`, so a bare
  # `docker run image sh -c ...` would exec `sleep sh -c ...`. Copy the key to a
  # root-owned 0600 path inside the container to sidestep host-uid perm quirks.
  SESSION_OUT="$(docker run --rm --network host \
      -v "$WORKDIR/client_key:/mnt/client_key:ro" \
      --entrypoint sh \
      "$CLIENT_IMAGE" \
      -c "cp /mnt/client_key /root/k && chmod 600 /root/k && \
        ssh -p $FS_GW_SSH_PORT -i /root/k -o IdentitiesOnly=yes \
          -o PreferredAuthentications=publickey -o BatchMode=yes \
          -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30 \
          '$NODE_LOGIN%$NODE_NAME@127.0.0.1' \
          'echo $MARKER; echo FULLSTACK_PATH_OK; hostname'" 2>&1)" \
    || die "cross-stack ssh failed:\n$SESSION_OUT\n--- gateway.log ---\n$(tail -30 "$WORKDIR/gateway.log")"
  grep -q FULLSTACK_PATH_OK <<<"$SESSION_OUT" || die "node output did not return: $SESSION_OUT"
  grep -q "$MARKER" <<<"$SESSION_OUT" || die "session marker not returned: $SESSION_OUT"
  ok "command ran on the REAL node via the REAL CP Authorize decision; output returned"
}

# ── recording integrity: the WORM object is the customer-sealed SLREC1 object ──
assert_recording() {
  log "asserting the session recording finalized as a WORM-locked, customer-sealed SLREC1 object"
  # The Gateway finalizes off the connection teardown; poll the CP's recording_ref.
  local deadline=$((SECONDS + 120)) status="" object_key="" worm_mode="" size_bytes="" chain="" digest=""
  while [[ $SECONDS -lt $deadline ]]; do
    status="$(PSQL -tAc "SELECT status FROM runtime.recording_ref ORDER BY created_at DESC LIMIT 1" || true)"
    [[ "$status" == "finalized" ]] && break
    sleep 2
  done
  [[ "$status" == "finalized" ]] || die "recording never finalized (status='${status:-none}'); gateway.log tail:\n$(tail -20 "$WORKDIR/gateway.log")"
  read -r object_key worm_mode size_bytes chain digest < <(PSQL -tAc \
    "SELECT object_key||' '||coalesce(worm_mode,'?')||' '||coalesce(size_bytes::text,'0')||' '||coalesce(hash_chain_head,'?')||' '||coalesce(content_digest,'?')
     FROM runtime.recording_ref ORDER BY created_at DESC LIMIT 1")
  [[ "$worm_mode" == "compliance" ]] || die "recording worm_mode is '$worm_mode', expected compliance"
  [[ "$chain" == sha256:* ]]  || die "hash_chain_head not committed: $chain"
  [[ "$digest" == sha256:* ]] || die "content_digest not committed: $digest"
  ok "recording_ref finalized: object=$object_key worm=$worm_mode size=$size_bytes chain=$chain"

  # Pull the object + its retention out of MinIO (mc ships in the minio image).
  log "fetching the WORM object from MinIO to verify it is opaque SLREC1 ciphertext"
  rm -f "$WORKDIR/obj.bin" "$WORKDIR/retention.txt"
  docker run --rm --network host -v "$WORKDIR:/out" --entrypoint sh "$MINIO_IMAGE" -c "
     mc alias set fs '$MINIO_ENDPOINT' '$MINIO_USER' '$MINIO_PASS' >/dev/null 2>&1 &&
     mc cp --quiet 'fs/$WORM_BUCKET/$object_key' /out/obj.bin >/dev/null 2>&1 &&
     mc stat 'fs/$WORM_BUCKET/$object_key' > /out/retention.txt 2>&1" \
    || die "could not fetch the recording object from MinIO"
  [[ -s "$WORKDIR/obj.bin" ]] || die "fetched recording object is empty"

  local magic; magic="$(head -c6 "$WORKDIR/obj.bin")"
  [[ "$magic" == "SLREC1" ]] || die "object is not an SLREC1 sealed object (magic='$magic')"
  local osize; osize="$(wc -c < "$WORKDIR/obj.bin")"
  [[ "$osize" == "$size_bytes" ]] || die "object size $osize != recording_ref.size_bytes $size_bytes"
  local osha; osha="sha256:$(sha256sum "$WORKDIR/obj.bin" | cut -d' ' -f1)"
  [[ "$osha" == "$digest" ]] || die "object sha256 $osha != recording_ref.content_digest $digest"
  # Platform holds only the customer PUBLIC key: the sealed object must not carry the session
  # plaintext (negative check).
  grep -qa "$MARKER" "$WORKDIR/obj.bin" && die "SESSION PLAINTEXT MARKER found in the WORM object — sealing failed"
  grep -qi "COMPLIANCE" "$WORKDIR/retention.txt" || die "WORM object is not COMPLIANCE object-locked; mc stat:\n$(cat "$WORKDIR/retention.txt")"
  ok "WORM object is opaque SLREC1 (magic ok, size+digest match, no plaintext), COMPLIANCE-locked"

  # SEC-LOW-1/2 — the POSITIVE crown-jewel proof: the WORM object DECRYPTS (customer private key,
  # which never left the harness — the CP only ever got the public half) back to the original
  # session bytes (marker PRESENT), and the hash-chain recomputes to the finalized head. Without
  # this, an empty/header-only SLREC1 finalize would pass every check above. Uses decrypt_recording
  # (reuses the exact production seal:: code).
  log "decrypt-proving the recording with the customer private key: session bytes present + hash-chain recomputes"
  openssl pkcs8 -topk8 -nocrypt -in "$WORKDIR/customer_key.pem" -outform DER -out "$WORKDIR/customer_key.pkcs8.der" 2>/dev/null \
    || die "could not convert the customer key to PKCS8 DER"
  local dec; dec="$("$DECRYPT_BIN" "$WORKDIR/customer_key.pkcs8.der" "$WORKDIR/obj.bin" 2>"$WORKDIR/decrypt.err")" \
    || die "decrypt_recording failed (customer key cannot open the object?): $(cat "$WORKDIR/decrypt.err")"
  grep -q "$MARKER" <<<"$dec" \
    || die "the session marker is NOT in the DECRYPTED recording — capture+seal produced no recoverable session bytes (empty/header-only finalize?)"
  local rechain; rechain="$(sed -n 's/^CHAIN_HEAD=//p' <<<"$dec" | head -1)"
  [[ "$rechain" == "$chain" ]] || die "recomputed hash-chain head ($rechain) != finalized head ($chain)"
  ok "recording decrypts to the original session (marker present) + hash-chain recomputes to the finalized head"
}

# ── Part B: the connect/authorize audit event carries + is searchable by all 5 dims ──
# The substantive FR-AUD-8/9 proof is SEARCHABILITY (an auditor finds the event by each
# dimension) + the single-correlationId correlated chain. The AuditEventResource response
# projects source_ip + correlation_id (top-level) and access_model (in `detail`); capabilities
# and node_labels are searchable but not projected (the schema omits them — by design).
assert_audit_dimensions() {
  log "asserting the connect/authorize audit event is searchable by all 5 dimensions + the correlated chain"
  mint_admin_token
  local sid; sid="$(PSQL -tAc "SELECT id FROM runtime.ssh_session ORDER BY created_at DESC LIMIT 1" | tr -d '[:space:]')"
  [[ -n "$sid" ]] || die "no ssh_session row to correlate against"

  # (1) the authorize event carries the projected dims populated.
  curl -s "$CP_REST/v1/audit-events?correlationId=$sid&action=authz.decision" \
    -H "Authorization: Bearer $ADMIN_TOKEN" > "$WORKDIR/audit-authz.json"
  SID="$sid" python3 - "$WORKDIR/audit-authz.json" <<'PY' || die "authorize audit event missing a projected dimension (see audit-authz.json)"
import sys, json, os
d = json.load(open(sys.argv[1]))
items = d.get("items") or []
assert items, "no authz.decision event returned"
e = items[0]
assert e.get("sourceIp") == "127.0.0.1", f"sourceIp not populated: {e.get('sourceIp')}"
assert e.get("correlationId") == os.environ["SID"], f"correlationId mismatch: {e.get('correlationId')}"
assert (e.get("detail") or {}).get("access_model") == "standing", f"access_model not standing: {e.get('detail')}"
print("authorize event carries sourceIp=%s access_model=%s correlationId(ok)" % (e["sourceIp"], e["detail"]["access_model"]))
PY
  ok "the authorize audit event carries source_ip + access_model + correlation_id"

  # (2) a search filtered by EACH of the 5 dimensions returns at least the session's event.
  local q n
  for q in "sourceIp=127.0.0.1" "accessModel=standing" "capability=exec" "nodeLabel=env=fullstack" "correlationId=$sid"; do
    n="$(curl -s "$CP_REST/v1/audit-events?$q" -H "Authorization: Bearer $ADMIN_TOKEN" \
      | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("items") or []))' 2>/dev/null)"
    [[ "${n:-0}" -ge 1 ]] || die "audit search by dimension returned nothing: ?$q"
    log "  search ?$q -> $n event(s)"
  done
  ok "each of source_ip / access_model / capabilities / node_labels / correlation_id is independently searchable"

  # (3) the correlated path: one correlationId reconstructs the session chain
  # (authz.decision + recording begin/upload/finalize).
  local chain
  chain="$(curl -s "$CP_REST/v1/audit-events?correlationId=$sid" -H "Authorization: Bearer $ADMIN_TOKEN" \
    | python3 -c 'import sys,json
d=json.load(sys.stdin); acts=[e.get("action") for e in (d.get("items") or [])]
assert any(a=="authz.decision" for a in acts), "chain missing authz.decision: "+str(acts)
assert any(a and a.startswith("recording.") for a in acts), "chain missing recording.*: "+str(acts)
print(",".join(acts))')" || die "correlated-path chain incomplete for correlationId=$sid"
  ok "correlated path: correlationId=$sid returns the chain [$chain]"
}

# ── SEC-LOW-3: deny-wins at the REAL-CP integration layer (not just the MockCp double). ──
# An ungranted login must be refused by the real CP Authorize — fail closed, generic §7.1.
assert_deny_closed() {
  log "deny-path: an UNGRANTED login ($DENY_LOGIN%$NODE_NAME) must be refused by the real CP (fail closed)"
  local out rc=0
  out="$(ssh_attempt "$DENY_LOGIN" "$NODE_NAME" 'echo DENIED_SHOULD_NOT_RUN')" || rc=$?
  [[ $rc -ne 0 ]] || die "an ungranted login was NOT refused (fail-OPEN): $out"
  grep -q DENIED_SHOULD_NOT_RUN <<<"$out" && die "the command RAN on an ungranted login — deny bypassed: $out"
  ok "deny-path: the ungranted login was refused by the real CP (rc=$rc, generic §7.1, no command ran)"
}

# ── NFR-2: with the real CP DOWN, a new session must fail CLOSED — never fail-open. LAST case
# (it kills the CP). The full-stack proves this in a way MockCp cannot: a real dead decision plane.
assert_cp_down() {
  log "NFR-2: killing the real CP; a NEW session MUST fail closed (never fail-open)"
  kill "$CP_PID" 2>/dev/null || true
  local d=$((SECONDS + 25))
  while kill -0 "$CP_PID" 2>/dev/null && [[ $SECONDS -lt $d ]]; do sleep 1; done
  ! curl -sf "http://localhost:${FS_CP_REST_PORT}/v1/healthz" >/dev/null 2>&1 || die "CP still healthy after kill; cannot prove CP-down"
  local out rc=0
  out="$(ssh_attempt "$NODE_LOGIN" "$NODE_NAME" 'echo CPDOWN_SHOULD_NOT_RUN')" || rc=$?
  [[ $rc -ne 0 ]] || die "a session SUCCEEDED with the CP DOWN (fail-OPEN — NFR-2 violated): $out"
  grep -q CPDOWN_SHOULD_NOT_RUN <<<"$out" && die "the command RAN with the CP down — fail-open: $out"
  ok "NFR-2: with the real CP down, the new session failed closed (rc=$rc); the Gateway never fails open"
}

report() {
  cat <<EOF

$(printf '\033[32m========================================================\033[0m')
$(printf '\033[32m  FULL-STACK CROSS-REPO E2E PASSED (topology=%s)\033[0m' "$TOPOLOGY")
$(printf '\033[32m========================================================\033[0m')
  Real CP jar   : $CP_JAR  (mTLS :$FS_CP_MTLS_PORT, REST :$FS_CP_REST_PORT)
  Real Gateway  : $GATEWAY_BIN  (agentless, ssh :$FS_GW_SSH_PORT)
  Real node     : $NODE_NAME container, sshd :$NODE_PORT (session-CA cert auth, pinned host key)
  Session       : ssh $NODE_LOGIN%$NODE_NAME@gw ran on the node via the REAL CP Authorize decision
  Recording     : finalized SLREC1 WORM object, COMPLIANCE-locked, customer-sealed
  Logs          : $WORKDIR/{cp,gateway}.log
EOF
}

# F-1: under a hardened profile the recorder spills ciphertext to disk once a
# session exceeds the (deliberately small) spool threshold. That spool MUST land in
# a Landlock-allowed path (the data-dir), not /tmp — a /tmp spool would EACCES and,
# in strict mode, tear the session down mid-flight. Force a spill with a large-output
# session and assert it still succeeds; every non-hardened run skips this.
assert_spill() {
  case "${FS_HARDENING:-off}" in
    full | seccomp) : ;;
    *) return 0 ;;
  esac
  log "F-1: forcing a recorder spill (>64KiB output) under hardening=$FS_HARDENING — must NOT tear down"
  local out rc=0
  out="$(ssh_attempt "$NODE_LOGIN" "$NODE_NAME" 'head -c 300000 /dev/zero | base64; echo SPILL_OK')" || rc=$?
  { [[ $rc -eq 0 ]] && grep -q SPILL_OK <<<"$out"; } \
    || die "large-output session failed under hardening — the ciphertext spool was likely EACCES'd (e.g. /tmp not in the Landlock set):\n$(tail -40 "$WORKDIR/gateway.log")"
  # Spool file lives under the data-dir (created + removed there), never /tmp.
  [[ -d "$WORKDIR/gw-data/recording-spool" ]] \
    || die "expected the spool dir under the data-dir (gw-data/recording-spool)"
  ok "recorder spill under hardening=$FS_HARDENING succeeded — spool in the data-dir, strict session intact (F-1)"
}

main() {
  preflight
  build_artifacts
  start_infra
  start_cp
  seed_cp
  mint_admin_token           # machine bearer for the S16 admin REST API
  start_node                 # generate the pinned host key + launch the node
  register_node              # POST /v1/nodes (agentless + pinned host anchor)
  launch_gateway
  run_session                # ssh through the REAL CP Authorize -> real node
  assert_recording           # SLREC1 WORM object + decrypt-proof (SEC-LOW-1/2)
  assert_audit_dimensions    # 5 dims searchable + correlated chain (Part B)
  assert_spill               # F-1: recorder spill lands in the Landlock-allowed data-dir
  assert_deny_closed         # deny-wins at the real CP (SEC-LOW-3)
  assert_cp_down             # NFR-2 fail-closed — LAST (kills the CP)
  report
}
main "$@"
