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
WAIT_SECS="${WAIT_SECS:-180}"
GW_NAME="${GW_NAME:-gw-fullstack}"
NODE_NAME="${NODE_NAME:-web-01}"
NODE_LOGIN="${NODE_LOGIN:-deploy}"
FS_NODE_PORT="${FS_NODE_PORT:-12222}"   # node sshd port (host network; see start_node WHY)
CLIENT_IDENTITY="${CLIENT_IDENTITY:-fullstack-user}"
MARKER="FULLSTACK_OK_$$"
KEEP_UP="${KEEP_UP:-}"

MINIO_ENDPOINT="http://127.0.0.1:${FS_MINIO_PORT}"
WORM_BUCKET="sessionlayer-recordings"
MINIO_USER="sessionlayer"
MINIO_PASS="sessionlayer-dev-secret"

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
  if [[ "$TOPOLOGY" == "agent" || "$TOPOLOGY" == "all" ]]; then
    [[ -n "${AGENT_BIN:-}" && -x "${AGENT_BIN:-/nonexistent}" ]] \
      || die "TOPOLOGY=$TOPOLOGY needs AGENT_BIN pointing at an executable agent binary"
  fi
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
  PIDS+=($!)
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
  local deadline=$((SECONDS + 90)) n=""
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

  export GW_ENROLL_TOKEN SESSION_CA_LINE
  ok "seed_cp done (mTLS CA + session CA + gw token + dp_rule + pin + customer key)"
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

  # --network host (NOT a bridge port-map) is REQUIRED, and it is load-bearing, not
  # cosmetic: the CP pins the inner-leg session cert's `source-address` critical option
  # to the OUTER CLIENT's source IP (AuthorizeRequest.source_ip). The Gateway dials the
  # node with a plain TcpStream::connect (no source preservation), so the node's sshd
  # checks that option against the GATEWAY peer. Only when client, Gateway and node all
  # observe 127.0.0.1 (this all-loopback single-host topology) does the pin match. On a
  # bridge port-map the node sees the docker SNAT (172.17.0.1) and rejects the valid cert
  # ("not from a permitted source address"). That mismatch is a real cross-repo finding
  # the per-repo MockCp masks by omitting source-address — see README.md "Cross-repo findings".
  log "starting the node container ($NODE_NAME; host-net sshd :$FS_NODE_PORT; trusts the session CA)"
  docker rm -f "$NODE_CONTAINER" >/dev/null 2>&1 || true
  # create -> cp the host key in as root (0600) -> start, so the entrypoint's
  # ssh-keygen -A keeps our pre-placed ed25519 key (it only fills MISSING keys). The
  # trailing `-p $FS_NODE_PORT` is passed through to sshd (entrypoint `exec sshd -D -e "$@"`).
  docker create --name "$NODE_CONTAINER" --network host \
    -e TRUSTED_USER_CA="$SESSION_CA_LINE" "$NODE_IMAGE" -p "$FS_NODE_PORT" >/dev/null
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
  NODE_PORT="$FS_NODE_PORT"
  ok "node up: $NODE_NAME sshd on 127.0.0.1:$NODE_PORT (pinned fp $NODE_HOSTKEY_FP)"
}

# Register the node in inventory as agentless with its dial address + pinned host key.
seed_node_inventory() {
  log "seed 7/7: node inventory ($NODE_NAME -> agentless 127.0.0.1:$NODE_PORT, pinned host key)"
  # Upsert then SELECT the id separately: psql prints an "INSERT 0 1" command tag on
  # stdout even under -tA, which would corrupt a RETURNING-captured id.
  PSQL -c "INSERT INTO runtime.node(id,name,connector_kind,status,resolved_labels,address)
    VALUES (gen_random_uuid(),'$NODE_NAME','agentless','active','{\"env\":\"fullstack\"}'::jsonb,'127.0.0.1:$NODE_PORT')
    ON CONFLICT (name) DO UPDATE SET address=EXCLUDED.address, status='active', connector_kind='agentless';" >/dev/null
  NODE_ID="$(PSQL -tAc "SELECT id FROM runtime.node WHERE name='$NODE_NAME'" | tr -d '[:space:]')"
  [[ -n "$NODE_ID" ]] || die "node insert returned no id"
  PSQL -c "INSERT INTO runtime.node_host_key(id,node_id,key_type,public_key,fingerprint,source,verified_at)
    VALUES (gen_random_uuid(),'$NODE_ID','ssh-ed25519','$NODE_HOSTKEY_LINE','$NODE_HOSTKEY_FP','pinned_key',now())
    ON CONFLICT (node_id,fingerprint) DO NOTHING;" >/dev/null
  ok "node inventory seeded (id=$NODE_ID)"
}

launch_gateway() {
  log "rendering + launching the real Gateway (agentless, single-instance)"
  CP_MTLS_ENDPOINT="https://localhost:${FS_CP_MTLS_PORT}" \
  CP_SERVER_NAME="localhost" \
  GW_DATA_DIR="$WORKDIR/gw-data" \
  GW_ENROLL_TOKEN="$GW_ENROLL_TOKEN" \
  GW_CA_PEM="$WORKDIR/ca.pem" \
  GW_NAME="$GW_NAME" \
  GW_SSH_ADDR="127.0.0.1:${FS_GW_SSH_PORT}" \
    envsubst '${CP_MTLS_ENDPOINT} ${CP_SERVER_NAME} ${GW_DATA_DIR} ${GW_ENROLL_TOKEN} ${GW_CA_PEM} ${GW_NAME} ${GW_SSH_ADDR}' \
    < "$SCRIPT_DIR/config/gateway-core.json.tmpl" > "$WORKDIR/gateway.json"
  rm -rf "$WORKDIR/gw-data"; mkdir -p "$WORKDIR/gw-data"
  RUST_LOG="${GW_RUST_LOG:-info}" "$GATEWAY_BIN" --config "$WORKDIR/gateway.json" > "$WORKDIR/gateway.log" 2>&1 &
  GW_PID=$!; PIDS+=("$GW_PID")
  local deadline=$((SECONDS + 90))
  until grep -q "outer SSH leg started" "$WORKDIR/gateway.log" 2>/dev/null; do
    kill -0 "$GW_PID" 2>/dev/null || { tail -40 "$WORKDIR/gateway.log" >&2; die "Gateway exited during startup (enrollment?)"; }
    [[ $SECONDS -lt $deadline ]] || { tail -40 "$WORKDIR/gateway.log" >&2; die "Gateway outer leg never started"; }
    sleep 1
  done
  ok "Gateway enrolled + outer SSH leg on 127.0.0.1:$FS_GW_SSH_PORT (log: $WORKDIR/gateway.log)"
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
  local deadline=$((SECONDS + 60)) status="" object_key="" worm_mode="" size_bytes="" chain="" digest=""
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
  # Platform holds only the customer PUBLIC key: the sealed object must not carry
  # the session plaintext (full ECIES decrypt-proof is per-repo recorder_it.rs).
  grep -qa "$MARKER" "$WORKDIR/obj.bin" && die "SESSION PLAINTEXT MARKER found in the WORM object — sealing failed"
  grep -qi "COMPLIANCE" "$WORKDIR/retention.txt" || die "WORM object is not COMPLIANCE object-locked; mc stat:\n$(cat "$WORKDIR/retention.txt")"
  ok "WORM object is opaque SLREC1 (magic ok, size+digest match, no plaintext), COMPLIANCE-locked"
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

main() {
  preflight
  build_artifacts
  start_infra
  start_cp
  seed_cp
  start_node
  seed_node_inventory
  launch_gateway
  run_session
  assert_recording
  report
}
main "$@"
