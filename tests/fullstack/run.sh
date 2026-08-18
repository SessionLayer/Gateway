#!/usr/bin/env bash
#
# Cross-repo, so NOT part of `cargo nextest` - run it (under the build lock on a
# small box) via: flock /tmp/sl-build.lock bash tests/fullstack/run.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GW_REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"

TOPOLOGY="${TOPOLOGY:-core}"
FS_PG_PORT="${FS_PG_PORT:-55432}"
FS_MINIO_PORT="${FS_MINIO_PORT:-59000}"
FS_MINIO_CONSOLE_PORT="${FS_MINIO_CONSOLE_PORT:-59001}"
FS_CP_MTLS_PORT="${FS_CP_MTLS_PORT:-19443}"
FS_CP_REST_PORT="${FS_CP_REST_PORT:-18080}"
FS_GW_SSH_PORT="${FS_GW_SSH_PORT:-12201}"
# PID-suffixed by default: a FIXED shared workdir (the same class of hazard as the
# /etc/hosts mapping below) means one run's preflight (rm -rf "$WORKDIR") silently
# deletes a peer's still-in-flight logs, and the loser never errors - it just carries on
# with no evidence. An explicit SL_FS_WORKDIR override opts back into a fixed
# path deliberately (e.g. a CI job that only ever runs one at a time and wants a
# predictable artifact-upload path); nothing here relies on a PRIOR run's WORKDIR
# surviving - preflight wipes it unconditionally regardless of whether the path is fixed
# or unique, and KEEP_UP's "surviving state" is the docker volumes/Gateway identity in the
# CP's database, not this directory. preflight() logs the resolved path so it never has
# to be guessed at.
WORKDIR="${SL_FS_WORKDIR:-/tmp/sl-fullstack-$$}"
WAIT_SECS="${WAIT_SECS:-300}"
GW_NAME="${GW_NAME:-gw-fullstack}"
NODE_NAME="${NODE_NAME:-web-01}"
NODE_LOGIN="${NODE_LOGIN:-deploy}"
FS_NODE_PORT="${FS_NODE_PORT:-12222}"
FS_NODE_NETMODE="${FS_NODE_NETMODE:-}"
if [[ -z "$FS_NODE_NETMODE" ]]; then
  [[ "$TOPOLOGY" == all ]] && FS_NODE_NETMODE=bridge || FS_NODE_NETMODE=loopback
fi
DENY_LOGIN="${DENY_LOGIN:-dba}"
# ── TOPOLOGY=agent ───────────────────────────────────────────────────────────
# The Gateway's agent-facing transport, which the Agent dials OUT to. Bound on all
# interfaces (not loopback) so the dial-out reaches the Gateway whichever network
# the node container is on; the Agent verifies the leaf by the Gateway's NAME,
# which is the dNSName SAN the CP stamps into it.
FS_GW_AGENT_PORT="${FS_GW_AGENT_PORT:-12444}"
AGENT_NODE_CONTAINER="sl-fs-agent-node"
FS_AGENT_NODE_PORT="${FS_AGENT_NODE_PORT:-12223}"
AGENT_NODE_IMAGE="sessionlayer-gw-fullstack-agentnode:test"
UNJOINED_NODE="${UNJOINED_NODE:-agent-unjoined}"
GW_MAX_DECISION_TTL_SECS="${GW_MAX_DECISION_TTL_SECS:-8}"
DECRYPT_BIN="${DECRYPT_BIN:-$GW_REPO/target/debug/examples/decrypt_recording}"
CLIENT_IDENTITY="${CLIENT_IDENTITY:-fullstack-user}"
MARKER="FULLSTACK_OK_$$"
KEEP_UP="${KEEP_UP:-}"
KEYVAULT_HOSTNAME="${KEYVAULT_HOSTNAME:-sl.vault.azure.net}"
# /etc/hosts is host-level state shared by every run on the box, so "did I
# add it" (a single process-local boolean) is not enough to decide "may I remove it" -
# run A adding it and run B correctly declining to re-add it does not mean B is done with
# it when A finishes first. Reference-counted instead: each run registers a marker file
# named after its own PID under KEYVAULT_HOSTS_REFS_DIR while it depends on the mapping,
# and the mapping is removed only when that directory is empty. KEYVAULT_HOSTS_LOCK makes
# "check/add/register" and "deregister/check/remove" atomic across concurrent processes.
KEYVAULT_HOSTS_LOCK="/tmp/sl-fullstack-keyvault-hosts.lock"
KEYVAULT_HOSTS_REFS_DIR="/tmp/sl-fullstack-keyvault-hosts.refs"
KEYVAULT_FAULT_MODE_ARMED=""
KMS_IMAGE="${KMS_IMAGE:-localstack/localstack:4}"
KMS_CONTAINER="sl-fs-kms"
# A FIXED port, unlike the Key Vault double's OS-assigned one. The Control Plane's
# endpoint-override is bound at CP boot, and assert_kms_fail_closed stops and restarts
# this container - which is exactly when docker hands a `0` host port a different number.
FS_KMS_PORT="${FS_KMS_PORT:-14566}"
KMS_REGION="${KMS_REGION:-us-east-1}"
KMS_ACCOUNT_ID="${KMS_ACCOUNT_ID:-000000000000}"
KMS_ENDPOINT="http://127.0.0.1:${FS_KMS_PORT}"
KMS_ACCESS_KEY_ID="${KMS_ACCESS_KEY_ID:-test}"
KMS_SECRET_ACCESS_KEY="${KMS_SECRET_ACCESS_KEY:-test}"
KMS_BASELINE_GETPUBKEY=0
KMS_PUBKEYS_BEFORE_ADOPTION=0
KMS_LOG_SNAPSHOT=""
# preflight does `rm -rf "$WORKDIR"`, so a run pointed at a fixed WORKDIR via
# SL_FS_WORKDIR can delete a prior run's logs before anyone reads them. The
# timestamp+PID suffix makes the evidence path unique per run regardless of how
# SL_FS_EVIDENCE_DIR is overridden, so two runs can never collide.
EVIDENCE_DIR="${SL_FS_EVIDENCE_DIR:-/tmp/sl-fullstack-evidence}/$(date -u +%Y%m%dT%H%M%SZ)-$$"

MINIO_ENDPOINT="http://127.0.0.1:${FS_MINIO_PORT}"
WORM_BUCKET="sessionlayer-recordings"
MINIO_USER="sessionlayer"
MINIO_PASS="sessionlayer-dev-secret"

# 127.0.0.1 rather than `localhost`: the Basic escape hatch is CIDR-gated on the peer
# address, so a `localhost` that resolved to ::1 would be judged against a rule the
# operator did not think they were writing.
CP_REST="http://127.0.0.1:${FS_CP_REST_PORT}"
ADMIN_ID="e2e-admin"
ADMIN_SECRET=""
ADMIN_TOKEN=""
BOOTSTRAP_USER="${BOOTSTRAP_USER:-fs-install-operator}"
BOOTSTRAP_PASSWORD=""
BOOTSTRAP_PASSWORD_HASH=""

NODE_IMAGE="sessionlayer-gw-fullstack-node:test"
CLIENT_IMAGE="sessionlayer-gw-fullstack-client:test"
MINIO_IMAGE="minio/minio:RELEASE.2025-04-08T15-41-24Z"
NODE_CONTAINER="sl-fs-node"

COMPOSE=(docker compose -f "$SCRIPT_DIR/infra-compose.yml")
export FS_PG_PORT FS_MINIO_PORT FS_MINIO_CONSOLE_PORT   # consumed by infra-compose.yml

log()  { printf '\033[36m[fs-e2e]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[fs-e2e] OK:\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[fs-e2e] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

PATH_ORIGINAL="$PATH"

# A failed run is exactly the outcome whose logs matter most, and exactly the one most
# likely to be produced on a shared box where a second run's preflight (rm -rf
# "$WORKDIR") can delete this run's WORKDIR before anyone reads it - a run that dies
# here left no way to recover what it had already proven. Copy the durable evidence out
# unconditionally, before anything else in cleanup, so it survives regardless of rc,
# KEEP_UP, or a concurrent run.
preserve_evidence() {
  local rc="$1"
  mkdir -p "$EVIDENCE_DIR" 2>/dev/null || return 0
  cp -p "$WORKDIR"/cp.log "$WORKDIR"/gateway.log "$EVIDENCE_DIR/" 2>/dev/null || true
  cp -p "$WORKDIR"/keyvault/requests.log "$WORKDIR"/keyvault/double.log "$EVIDENCE_DIR/" 2>/dev/null || true
  cp -p "$WORKDIR"/kms/kms.env "$WORKDIR"/kms/cp-insecure-endpoint.log "$WORKDIR"/kms/cp-endpoint-override-refused.log "$WORKDIR"/kms/localstack-at-stop.log "$EVIDENCE_DIR/" 2>/dev/null || true
  # KMS's request log - the counter every assertion in that leg is judged against - lives
  # inside the container, so it has to be pulled out before teardown removes it. The
  # explicit PATH is not decoration: a die() inside a rest-only operator step leaves the
  # docker stub on PATH, and this runs before cleanup restores it.
  PATH="$PATH_ORIGINAL" docker logs "$KMS_CONTAINER" > "$EVIDENCE_DIR/localstack-kms.log" 2>&1 || true
  echo "$rc" > "$EVIDENCE_DIR/exit-code.txt"
  log "evidence preserved (rc=$rc): $EVIDENCE_DIR"
}

PIDS=()
cleanup() {
  local rc=$?
  preserve_evidence "$rc"
  # Unconditional, even under KEEP_UP: a die() partway through
  # assert_keyvault_wrong_key_rejected must not leave the double signing with the wrong
  # key for whoever inspects or reuses it next. Best-effort - the double may already be
  # gone (e.g. assert_keyvault_fail_closed stopped it first in the same run).
  if [[ -n "$KEYVAULT_FAULT_MODE_ARMED" && -n "${KEYVAULT_URL:-}" ]]; then
    curl -sk "$KEYVAULT_URL/_test/fault-mode?mode=none" >/dev/null 2>&1 || true
  fi
  PATH="$PATH_ORIGINAL"   # teardown needs docker; the operator-flow shims must never block it
  if [[ -n "$KEEP_UP" ]]; then
    log "KEEP_UP set - leaving CP/Gateway/infra/node up for inspection (rc=$rc)"
    return
  fi
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  docker rm -f "$NODE_CONTAINER" "$AGENT_NODE_CONTAINER" "$KMS_CONTAINER" >/dev/null 2>&1 || true
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  release_keyvault_hostname
}
trap cleanup EXIT

# ── the no-database guard ────────────────────────────────────────────────────
# The claim under test is that an operator can complete a first install holding an API
# credential and nothing else, so every operator step runs with the database made
# unreachable. Shadowing the host `psql` binary is not enough on its own: this harness
# reaches Postgres as `docker compose exec postgres psql`, which resolves `psql` INSIDE
# the container and sails straight past a host-PATH stub. So the phases that are pure
# REST shadow `docker` as well, and `db_fixture` - a shell function, which bypasses PATH
# entirely - refuses to run at all while any operator phase is open.
SHIM_NO_DB=""
SHIM_NO_DOCKER=""
OPERATOR_PHASE=""

install_operator_shims() {
  SHIM_NO_DB="$WORKDIR/shim-no-db"
  SHIM_NO_DOCKER="$WORKDIR/shim-no-docker"
  mkdir -p "$SHIM_NO_DB" "$SHIM_NO_DOCKER"
  local tool
  for tool in psql pg_dump pg_restore pg_isready; do shim_stub "$SHIM_NO_DB/$tool"; done
  for tool in docker docker-compose; do shim_stub "$SHIM_NO_DOCKER/$tool"; done
  PATH="$SHIM_NO_DB:$PATH"
}

shim_stub() {
  printf '#!/bin/sh\necho "FAIL: $(basename "$0") was invoked inside the first-install operator flow" >&2\nexit 97\n' > "$1"
  chmod +x "$1"
}

operator_step() {
  PATH="${PATH#"$SHIM_NO_DOCKER":}"
  OPERATOR_PHASE="$1"
  if [[ "${2:-}" == rest-only ]]; then PATH="$SHIM_NO_DOCKER:$PATH"; fi
  log "operator step - no database credential available: $1"
}

operator_flow_end() {
  PATH="${PATH#"$SHIM_NO_DOCKER":}"
  OPERATOR_PHASE=""
  ok "the first install completed end to end with no database credential used at any point"
}

db_fixture() {
  [[ -z "$OPERATOR_PHASE" ]] \
    || die "the harness reached for the database during the operator step '$OPERATOR_PHASE' - the first install is not API-only"
  "${COMPOSE[@]}" exec -T postgres psql -U sessionlayer -d sessionlayer -v ON_ERROR_STOP=1 "$@"
}

API_AUTH=()
use_basic_credential()   { API_AUTH=(-u "$BOOTSTRAP_USER:$BOOTSTRAP_PASSWORD"); }
use_machine_credential() { API_AUTH=(-H "Authorization: Bearer $ADMIN_TOKEN"); }

api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-s -w $'\n%{http_code}' -X "$method" "$CP_REST$path" "${API_AUTH[@]}")
  if [[ -n "$body" ]]; then args+=(-H 'Content-Type: application/json' -d "$body"); fi
  curl "${args[@]}"
}

api_ok() {
  local out code
  out="$(api "$@")" || die "curl could not reach $1 $2"
  code="$(printf %s "$out" | tail -1)"
  [[ "$code" == 2?? ]] || die "$1 $2 -> HTTP $code: $(printf %s "$out" | sed '$d')"
  printf %s "$out" | sed '$d'
}

# Cold-start provisioning (the CA rows, the operator-settings singleton) can still be
# running when /v1/healthz goes green, so the readiness gate is the API serving what the
# install actually needs rather than a row count.
api_ok_eventually() {
  local deadline=$((SECONDS + 180)) out code
  while :; do
    out="$(api GET "$1")"
    code="$(printf %s "$out" | tail -1)"
    if [[ "$code" == 2?? ]]; then printf %s "$out" | sed '$d'; return 0; fi
    [[ $SECONDS -lt $deadline ]] || die "GET $1 never became available (last HTTP $code): $(printf %s "$out" | sed '$d')"
    sleep 2
  done
}

# Request bodies are built by python3, never by splicing shell values into a JSON string:
# a fingerprint, an OpenSSH key line and a base64 SPKI all carry characters that would
# break a hand-built body. A `%` prefix marks a value that is raw JSON - a number, a
# list, a boolean - rather than a string.
json() {
  python3 - "$@" <<'PY'
import json, sys
args = sys.argv[1:]
print(json.dumps({k: (json.loads(v[1:]) if v.startswith('%') else v)
                  for k, v in zip(args[::2], args[1::2])}))
PY
}

json_list() { python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@"; }

# A session id comes from the Gateway and is a random v4 UUID, so the id-keyset cursor
# the sessions API pages by is stable but NOT chronological - "the last item" is an
# arbitrary session. Order by when the session started instead.
latest_session_id() {
  api_ok GET "/v1/sessions?identity=$CLIENT_IDENTITY" | python3 -c '
import json, sys
items = json.load(sys.stdin).get("items") or []
print(max(items, key=lambda s: s["startedAt"])["id"] if items else "")'
}

session_ids() {
  api_ok GET "/v1/sessions?identity=$CLIENT_IDENTITY" \
    | python3 -c 'import json,sys;print(" ".join(s["id"] for s in json.load(sys.stdin).get("items") or []))'
}

json_get() {
  printf %s "$1" | python3 -c '
import json, sys
v = json.load(sys.stdin).get(sys.argv[1])
sys.stdout.write("" if v is None else (v if isinstance(v, str) else json.dumps(v)))' "$2"
}

# ── preflight: inputs + toolchain (wipes WORKDIR, installs the PATH shims) ───
preflight() {
  command -v docker  >/dev/null || die "docker is required"
  command -v openssl >/dev/null || die "openssl is required"
  command -v ssh-keygen >/dev/null || die "ssh-keygen is required"
  command -v curl    >/dev/null || die "curl is required (the whole operator flow is REST)"
  command -v python3 >/dev/null || die "python3 is required (JSON request bodies + responses)"
  command -v java    >/dev/null || die "java is required (the CP jar, and the escape-hatch hash)"
  command -v keytool >/dev/null || die "keytool is required (the Key Vault double's TLS keystore + CP truststore)"
  [[ -n "${CP_JAR:-}" ]] || die "CP_JAR must point at the real controlplane boot jar"
  [[ -f "$CP_JAR" ]]     || die "CP_JAR does not exist: $CP_JAR"
  case "$TOPOLOGY" in
    core|all) : ;;
    agent)
      [[ -n "${AGENT_BIN:-}" ]] || die "TOPOLOGY=agent needs AGENT_BIN pointing at the real sessionlayer-agent binary"
      [[ -x "$AGENT_BIN" ]]     || die "AGENT_BIN is not executable: $AGENT_BIN" ;;
    *) die "unknown TOPOLOGY '$TOPOLOGY' (core|agent|all)" ;;
  esac
  rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"
  install_operator_shims
  ok "preflight: CP_JAR=$CP_JAR TOPOLOGY=$TOPOLOGY workdir=$WORKDIR (psql shadowed for the whole run)"
}

build_artifacts() {
  if [[ -z "${GATEWAY_BIN:-}" ]]; then
    log "building the Gateway binary (cargo build -p gateway)"
    ( cd "$GW_REPO" && CARGO_INCREMENTAL=0 cargo build -p gateway >/dev/null 2>&1 ) \
      || die "gateway build failed (run 'cargo build -p gateway' to see why)"
    GATEWAY_BIN="$GW_REPO/target/debug/gateway"
  fi
  [[ -x "$GATEWAY_BIN" ]] || die "GATEWAY_BIN not executable: $GATEWAY_BIN"

  if [[ ! -x "$DECRYPT_BIN" ]]; then
    log "building the recording decrypt-prover (cargo build -p gateway-core --example decrypt_recording)"
    ( cd "$GW_REPO" && CARGO_INCREMENTAL=0 cargo build -p gateway-core --example decrypt_recording >/dev/null 2>&1 ) \
      || die "decrypt_recording example build failed (run 'cargo build -p gateway-core --example decrypt_recording')"
  fi
  [[ -x "$DECRYPT_BIN" ]] || die "DECRYPT_BIN not executable: $DECRYPT_BIN"

  build_image_once "$NODE_IMAGE"   "$GW_REPO/tests/fixtures/sshd"       "node"
  build_image_once "$CLIENT_IMAGE" "$GW_REPO/tests/fixtures/ssh-client" "ssh-client"
  ok "gateway=$GATEWAY_BIN; node+client images ready"
}

build_image_once() {
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

# Served from KEYVAULT_HOSTNAME so a real vault's WWW-Authenticate challenge can be
# satisfied (see ensure_keyvault_hostname) - the CN/SAN must name that same host, or
# the CP's own hostname verification refuses the connection before the challenge is
# ever reached.
#
# A standalone HTTPS double of the Azure Key Vault key/crypto surface, plus a
# truststore the CP jar can use to validate it. Copy (never replace) the JDK's own
# cacerts: handing the CP a truststore holding ONLY our double's cert would silently
# strip every other trust anchor the process needs.
build_keyvault_trust_material() {
  local D="$1" java_home cacerts
  keytool -genkeypair -alias keyvault-double -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA \
      -keystore "$D/keyvault-double.p12" -storetype PKCS12 -storepass "$KV_STOREPASS" -keypass "$KV_STOREPASS" \
      -dname "CN=$KEYVAULT_HOSTNAME" -ext "san=dns:$KEYVAULT_HOSTNAME,ip:127.0.0.1" -validity 3650 \
      >/dev/null 2>&1 || die "keytool could not generate the Key Vault double's TLS keystore"
  keytool -exportcert -alias keyvault-double -keystore "$D/keyvault-double.p12" -storetype PKCS12 \
      -storepass "$KV_STOREPASS" -rfc -file "$D/keyvault-double.pem" \
      >/dev/null 2>&1 || die "keytool could not export the Key Vault double's certificate"

  java_home="$(java -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java\.home *= *//p' | head -1)"
  cacerts="$java_home/lib/security/cacerts"
  [[ -f "$cacerts" ]] || die "could not locate the JDK cacerts truststore under $java_home"
  cp "$cacerts" "$D/keyvault-truststore"
  chmod u+w "$D/keyvault-truststore"
  keytool -importcert -noprompt -trustcacerts -alias keyvault-double -keystore "$D/keyvault-truststore" \
      -storepass changeit -file "$D/keyvault-double.pem" \
      >/dev/null 2>&1 || die "keytool could not import the Key Vault double's cert into the CP truststore"
}

# The real Key Vault SDK challenge policy only attaches a bearer token when the request
# host is the challenge's `resource` host or a subdomain of it (see keyvault/README.md)
# - an IP literal can be neither, so the double MUST be served from a real hostname.
# Idempotent (a developer machine, or this box, may already carry the mapping) and
# guarded: a failure to add it means this leg cannot run at all, so it dies loudly
# naming exactly why, rather than silently falling back to an IP.
#
# Concurrency-safe: add + register-as-a-user happen inside one flock'd critical section,
# so a second run either observes the mapping already correctly in place (and just adds
# its own ref) or genuinely races nobody. The subshell can't call die() itself - `exit N`
# there only ends the subshell under `set -e`, not the script - so it signals failure via
# exit code and the outer function calls die() after inspecting it.
ensure_keyvault_hostname() {
  mkdir -p "$KEYVAULT_HOSTS_REFS_DIR"
  local rc=0
  (
    flock -x 9
    resolved="$(getent hosts "$KEYVAULT_HOSTNAME" 2>/dev/null | awk '{print $1; exit}')"
    if [[ -n "$resolved" && "$resolved" != "127.0.0.1" ]]; then
      exit 2
    fi
    if [[ -z "$resolved" ]]; then
      printf '127.0.0.1 %s\n' "$KEYVAULT_HOSTNAME" | sudo -n tee -a /etc/hosts >/dev/null 2>&1 || exit 3
    fi
    : > "$KEYVAULT_HOSTS_REFS_DIR/$$"
  ) 9>"$KEYVAULT_HOSTS_LOCK" || rc=$?
  case "$rc" in
    0) ;;
    2) die "$KEYVAULT_HOSTNAME already resolves to something other than 127.0.0.1 - refusing to shadow an existing, unrelated hosts/DNS entry for this name" ;;
    3) die "could not add '127.0.0.1 $KEYVAULT_HOSTNAME' to /etc/hosts (needs passwordless sudo) - the Key Vault double must be served from a hostname a real vault's WWW-Authenticate challenge resource can be a parent of, which no IP literal can ever be" ;;
    *) die "ensure_keyvault_hostname: unexpected internal failure (exit $rc)" ;;
  esac
  ok "hosts: $KEYVAULT_HOSTNAME resolves to 127.0.0.1 (this run registered as a user of the mapping)"
}

release_keyvault_hostname() {
  (
    flock -x 9
    rm -f "$KEYVAULT_HOSTS_REFS_DIR/$$"
    if [[ -z "$(ls -A "$KEYVAULT_HOSTS_REFS_DIR" 2>/dev/null)" ]]; then
      sudo -n sed -i "\#^127\.0\.0\.1 ${KEYVAULT_HOSTNAME//./\\.}\$#d" /etc/hosts 2>/dev/null || true
    fi
  ) 9>"$KEYVAULT_HOSTS_LOCK" 2>/dev/null || true
}

# Start the double BEFORE the CP, so the CP's azure.vault-uri and the
# truststore that must trust it are both ready at CP boot. These CP properties are
# passed unconditionally, while the active session CA is still 'local' (see start_cp) -
# proving that merely configuring Key Vault changes nothing until a CA is rotated onto
# it (adopt_session_ca_onto_keyvault, run later).
start_keyvault_double() {
  log "starting the Key Vault double (standalone HTTPS double of the Azure Key Vault key/crypto REST surface)"
  ensure_keyvault_hostname
  local D="$WORKDIR/keyvault"
  mkdir -p "$D"
  KV_STOREPASS="$(openssl rand -hex 16)"
  build_keyvault_trust_material "$D"

  java "$SCRIPT_DIR/keyvault/KeyVaultDouble.java" \
      --keystore "$D/keyvault-double.p12" --storepass "$KV_STOREPASS" --hostname "$KEYVAULT_HOSTNAME" \
      --key-name session-ca --request-log "$D/requests.log" \
      > "$D/double.log" 2>&1 &
  KV_PID=$!; PIDS+=("$KV_PID")

  local deadline=$((SECONDS + 60))
  until KEYVAULT_URL="$(sed -n 's/^KEYVAULT_URL=//p' "$D/double.log" | head -1)"; [[ -n "$KEYVAULT_URL" ]]; do
    kill -0 "$KV_PID" 2>/dev/null || { cat "$D/double.log" >&2; die "the Key Vault double exited during startup"; }
    [[ $SECONDS -lt $deadline ]] || { cat "$D/double.log" >&2; die "the Key Vault double never printed KEYVAULT_URL"; }
    sleep 1
  done
  KEY_ID="$(sed -n 's/^KEY_ID=//p' "$D/double.log" | head -1)"
  MSI_ENDPOINT="$(sed -n 's/^MSI_ENDPOINT=//p' "$D/double.log" | head -1)"
  PUBKEY_SPKI_B64="$(sed -n 's/^PUBKEY_SPKI_B64=//p' "$D/double.log" | head -1)"
  [[ -n "$KEY_ID" && -n "$MSI_ENDPOINT" && -n "$PUBKEY_SPKI_B64" ]] \
    || die "the Key Vault double did not print KEY_ID/MSI_ENDPOINT/PUBKEY_SPKI_B64"
  KEYVAULT_REQUEST_LOG="$D/requests.log"
  KEYVAULT_TRUSTSTORE="$D/keyvault-truststore"

  local ready_deadline=$((SECONDS + 15))
  until curl -sk -o /dev/null "$KEY_ID" && curl -s -o /dev/null "$MSI_ENDPOINT"; do
    [[ $SECONDS -lt $ready_deadline ]] || die "the Key Vault double never became reachable at $KEYVAULT_URL / $MSI_ENDPOINT"
    sleep 1
  done
  # The two readiness probes just above are the ONLY expected lines until rotation -
  # assert_keyvault_untouched_before_rotation asserts nothing more accumulates before then.
  KEYVAULT_BASELINE_LINES="$(wc -l < "$KEYVAULT_REQUEST_LOG")"
  ok "Key Vault double up: $KEYVAULT_URL (key=$KEY_ID); managed-identity endpoint: $MSI_ENDPOINT"
}

start_kms_localstack() {
  log "starting LocalStack KMS on 127.0.0.1:$FS_KMS_PORT (real P-256 key generation, real ECDSA signing, real AWS protocol)"
  mkdir -p "$WORKDIR/kms"
  kms_run_container
  kms_wait_ready
  kms_create_key
  # Reading the baseline through kms_await_count also proves the counter mechanism itself
  # on every run: the harness has just made a GetPublicKey call, so if LocalStack's
  # request-log line ever stops matching, this dies here naming that, rather than every
  # later assertion silently counting zero forever.
  KMS_BASELINE_GETPUBKEY="$(kms_await_count kms_get_public_key_count 1)" \
    || die "LocalStack's request log did not record the harness's own GetPublicKey - its log is not a usable call counter, so this leg cannot prove what signed anything"
  ok "LocalStack KMS up with a P-256 SIGN_VERIFY CA key ($KMS_BASELINE_GETPUBKEY GetPublicKey baseline, all the harness's own)"
}

kms_run_container() {
  docker rm -f "$KMS_CONTAINER" >/dev/null 2>&1 || true
  # DNS_ADDRESS=0 / SKIP_SSL_CERT_DOWNLOAD=1 / DISABLE_EVENTS=1 turn off the three things
  # LocalStack does on startup that reach the internet: its own DNS server, a certificate
  # fetch from api.localstack.cloud, and telemetry. None is used by anything here, and on a
  # host that cannot resolve those names they do not fail fast - startup went from 12
  # seconds to over seven minutes waiting on them, which reads as a hung container rather
  # than as a network the test was never entitled to.
  docker run -d --name "$KMS_CONTAINER" -p "127.0.0.1:${FS_KMS_PORT}:4566" \
    -e SERVICES=kms -e DNS_ADDRESS=0 -e SKIP_SSL_CERT_DOWNLOAD=1 -e DISABLE_EVENTS=1 \
    "$KMS_IMAGE" >/dev/null \
    || die "could not start the LocalStack KMS container ($KMS_IMAGE) on 127.0.0.1:$FS_KMS_PORT"
}

# Bring KMS back after a deliberate stop. `docker start` cannot revive a container that has
# been removed, and one stopped on purpose is a prime candidate for a prune, so a fresh
# container is the fallback. Either way the caller must re-create its key: a restarted
# LocalStack has lost every key it was holding.
kms_restart() {
  docker start "$KMS_CONTAINER" >/dev/null 2>&1 \
    || { log "the stopped KMS container no longer exists - re-creating it"; kms_run_container; }
  kms_wait_ready
}

# Readiness is LocalStack's own health endpoint reporting the service, never a sleep: the
# edge port answers well before KMS is loadable, and a create-key against it in that window
# fails in a way that reads like a broken image. `available` is the loaded-on-demand state
# and `running` is what it becomes after the first call, so a restart mid-run satisfies
# either.
kms_wait_ready() {
  local deadline=$((SECONDS + WAIT_SECS)) state=""
  until state="$(curl -s "$KMS_ENDPOINT/_localstack/health" 2>/dev/null | python3 -c '
import json, sys
try:
    print((json.load(sys.stdin).get("services") or {}).get("kms", ""))
except Exception:
    print("")')"; [[ "$state" == available || "$state" == running ]]; do
    docker ps -q --filter "name=$KMS_CONTAINER" | grep -q . \
      || { docker logs "$KMS_CONTAINER" 2>&1 | tail -40 >&2; die "the LocalStack KMS container exited during startup"; }
    [[ $SECONDS -lt $deadline ]] \
      || { docker logs "$KMS_CONTAINER" 2>&1 | tail -40 >&2; die "LocalStack never reported kms ready (last state '$state')"; }
    sleep 2
  done
}

kms_create_key() {
  local created public tag=()
  [[ -n "${1:-}" ]] && tag=(--tags "TagKey=_custom_id_,TagValue=$1")
  created="$(docker exec -e AWS_DEFAULT_REGION="$KMS_REGION" "$KMS_CONTAINER" \
    awslocal kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY "${tag[@]}" 2>&1)" \
    || die "kms create-key failed: $created"
  KMS_KEY_ARN="$(printf %s "$created" | python3 -c 'import json,sys;print(json.load(sys.stdin)["KeyMetadata"]["Arn"])')" \
    || die "could not read a key ARN out of the create-key response: $created"
  public="$(docker exec -e AWS_DEFAULT_REGION="$KMS_REGION" "$KMS_CONTAINER" \
    awslocal kms get-public-key --key-id "$KMS_KEY_ARN" 2>&1)" \
    || die "kms get-public-key failed: $public"
  KMS_PUBKEY_SPKI_B64="$(printf %s "$public" | python3 -c 'import json,sys;print(json.load(sys.stdin)["PublicKey"])')" \
    || die "could not read a public key out of the get-public-key response: $public"
  [[ "$KMS_KEY_ARN" == "arn:aws:kms:$KMS_REGION:$KMS_ACCOUNT_ID:key/"* ]] \
    || die "the created key's ARN is outside the region/account the Control Plane is anchored to: $KMS_KEY_ARN"
  # The same scraping discipline the Key Vault double's KEY=value banner gets, written from
  # here rather than from the caller so that EVERY key this run adopts is recorded: a run
  # that recovers from a KMS outage adopts a second one, and which ARN each session was
  # signed under is the whole point of keeping this.
  printf 'KMS_ENDPOINT=%s\nKMS_KEY_ARN=%s\nKMS_PUBKEY_SPKI_B64=%s\n' \
    "$KMS_ENDPOINT" "$KMS_KEY_ARN" "$KMS_PUBKEY_SPKI_B64" >> "$WORKDIR/kms/kms.env"
  log "KMS_ENDPOINT=$KMS_ENDPOINT"
  log "KMS_KEY_ARN=$KMS_KEY_ARN"
  log "KMS_PUBKEY_SPKI_B64=$KMS_PUBKEY_SPKI_B64"
}

kms_restart_with_fresh_key() {
  kms_restart
  kms_create_key
}

# LocalStack logs one line per AWS API call it serves, and `docker logs` keeps serving
# those lines after the container is STOPPED - which is what makes this usable as the
# independent counter assert_kms_fail_closed needs. The `=> 200` is not decoration: a
# refused Sign (a wrong-length digest earns a ValidationException) logs the same operation
# name with a 4xx, and counting it would read as a signature that never happened.
#
# A stopped container is not the same as a surviving one, though: pruning stopped
# containers is routine on shared boxes and CI runners, and a pruned container serves no
# log at all - every count would silently read zero, which is indistinguishable from "KMS
# was never reached" and would turn the fail-closed scenario into a pass for the wrong
# reason. assert_kms_fail_closed therefore snapshots the log to disk the moment it stops
# the container, and these fall back to that snapshot.
kms_request_log() { docker logs "$KMS_CONTAINER" 2>/dev/null || cat "${KMS_LOG_SNAPSHOT:-/dev/null}" 2>/dev/null; }
kms_sign_count()           { kms_request_log | grep -cE 'AWS kms\.Sign => 200' || true; }
kms_get_public_key_count() { kms_request_log | grep -cE 'AWS kms\.GetPublicKey => 200' || true; }

# LocalStack appends its request-log line after the response is already on the wire, so a
# count read the instant an API call returns can legitimately miss it. Poll to a deadline
# rather than read once: a false negative here would be indistinguishable from the Control
# Plane never having reached KMS at all, which is exactly the finding this leg exists to
# make trustworthy.
kms_await_count() {
  local deadline=$((SECONDS + 20)) n
  while :; do
    n="$("$1")"
    [[ "${n:-0}" -ge "$2" ]] && { printf %s "$n"; return 0; }
    [[ $SECONDS -lt $deadline ]] || { printf %s "$n"; return 1; }
    sleep 1
  done
}

# An endpoint-override redirects every KMS call the Control Plane makes - including the read
# that establishes the CA's pinned public key, which is why the pinning verification cannot
# bound a redirect it was itself bootstrapped through, and including the credentials SigV4
# signs each request with. So it is a trust-root decision, not a local convenience, and it
# is gated twice: setting one at all needs allow-endpoint-override, and a plaintext one
# needs allow-insecure-endpoint on top of that.
#
# Both gates are exercised, in the order the Control Plane evaluates them, because they fail
# for different reasons and one passing says nothing about the other: omitting both must be
# refused for the override itself, and permitting the override with a plaintext URL must
# still be refused for the scheme. A single case would leave whichever gate it did not reach
# unproven while looking like full coverage.
#
# Booting the real jar is what makes this a proof: the property binding, the validation and
# the context failure are all the real ones, where a guard exercised only through a test's
# own ApplicationContextRunner passes just as happily when the production wiring is absent.
assert_cp_refuses_insecure_kms_endpoint() {
  # Owned by ControlPlane's AwsKmsProperties, not by anything this repo controls, so both are
  # known to drift: when one moves, re-read that class and update the string rather than the
  # shape of this check. Matched on the property each gate names, never on a URL or an ARN.
  kms_boot_must_fail "no allow-endpoint-override" \
    "sessionlayer.ca.aws.allow-endpoint-override=true (dev/test only)" \
    "cp-endpoint-override-refused.log"
  kms_boot_must_fail "an override permitted but the endpoint plaintext" \
    "must use https unless sessionlayer.ca.aws.allow-insecure-endpoint=true" \
    "cp-insecure-endpoint.log" \
    --sessionlayer.ca.aws.allow-endpoint-override=true
}

kms_boot_must_fail() {
  local what="$1" expect="$2" out="$WORKDIR/kms/$3" rc=0
  shift 3
  log "boot guard: the Control Plane must refuse to start with $what"
  SESSIONLAYER_CA_LOCAL_ALLOW_DEV_KEK=true \
  SESSIONLAYER_MTLS_SERVER_PORT="$FS_CP_MTLS_PORT" \
  SERVER_PORT="$FS_CP_REST_PORT" \
  SESSIONLAYER_RECORDING_WORM_ENDPOINT="$MINIO_ENDPOINT" \
  SPRING_R2DBC_URL="r2dbc:postgresql://localhost:${FS_PG_PORT}/sessionlayer" \
  SPRING_R2DBC_USERNAME="sessionlayer" SPRING_R2DBC_PASSWORD="sessionlayer" \
  SPRING_FLYWAY_URL="jdbc:postgresql://localhost:${FS_PG_PORT}/sessionlayer" \
  SPRING_FLYWAY_USER="sessionlayer" SPRING_FLYWAY_PASSWORD="sessionlayer" \
  AWS_ACCESS_KEY_ID="$KMS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$KMS_SECRET_ACCESS_KEY" AWS_REGION="$KMS_REGION" \
    timeout "$WAIT_SECS" java -jar "$CP_JAR" \
      --sessionlayer.ca.aws.enabled=true \
      --sessionlayer.ca.aws.region="$KMS_REGION" \
      --sessionlayer.ca.aws.account-id="$KMS_ACCOUNT_ID" \
      --sessionlayer.ca.aws.endpoint-override="$KMS_ENDPOINT" \
      "$@" \
      > "$out" 2>&1 || rc=$?
  [[ $rc -ne 0 ]] \
    || die "the Control Plane started and exited cleanly with $what; see $out"
  # 124 is `timeout` killing a Control Plane that came up anyway - the exact failure this
  # guard exists to prevent. A bare rc!=0 check would read that kill as a refusal and pass,
  # which is the failure shape worth naming rather than simplifying away: a check that
  # cannot tell the outcome it wants from the outcome it fears does not stop passing when
  # the guard breaks, it just stops meaning anything. Do not collapse these two tests.
  [[ $rc -ne 124 ]] \
    || die "the Control Plane neither refused $what nor exited - it was still running when the timeout killed it; see $out"
  grep -q "$expect" "$out" \
    || die "the Control Plane exited (rc=$rc) but not visibly for '$what' - the gate that refused is not the one under test; see $out"
  ok "boot guard: $what failed the application context (rc=$rc)"
}

arm_bootstrap_escape_hatch() {
  local D="$WORKDIR/escape-hatch"
  mkdir -p "$D"
  BOOTSTRAP_PASSWORD="$(openssl rand -hex 24)"
  python3 - "$CP_JAR" "$D" <<'PY'
import os, posixpath, sys, zipfile
jar, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(jar) as z:
    found = [n for n in z.namelist() if '/spring-security-crypto-' in n and n.endswith('.jar')]
    if not found:
        raise SystemExit('spring-security-crypto is not inside the Control Plane jar')
    open(os.path.join(out, posixpath.basename(found[0])), 'wb').write(z.read(found[0]))
PY
  cat > "$D/BcryptHash.java" <<'JAVA'
public final class BcryptHash {
	public static void main(String[] args) {
		System.out.println(org.springframework.security.crypto.bcrypt.BCrypt
				.hashpw(args[0], org.springframework.security.crypto.bcrypt.BCrypt.gensalt(10)));
	}
}
JAVA
  BOOTSTRAP_PASSWORD_HASH="$(java -cp "$D"/spring-security-crypto-*.jar "$D/BcryptHash.java" "$BOOTSTRAP_PASSWORD")" \
    || die "could not compute the escape-hatch password hash"
  [[ "$BOOTSTRAP_PASSWORD_HASH" == \$2* ]] || die "not a bcrypt hash: $BOOTSTRAP_PASSWORD_HASH"
  use_basic_credential
  ok "escape hatch armed for '$BOOTSTRAP_USER' from deployment configuration (127.0.0.1 only)"
}

cp_key_service_flags() {
  [[ "$TOPOLOGY" == agent ]] && return 0
  printf '%s\n' \
    "--sessionlayer.ca.azure.enabled=true" \
    "--sessionlayer.ca.azure.vault-uri=$KEYVAULT_URL" \
    "--sessionlayer.ca.azure.credential=managed-identity" \
    "--sessionlayer.ca.aws.enabled=true" \
    "--sessionlayer.ca.aws.region=$KMS_REGION" \
    "--sessionlayer.ca.aws.account-id=$KMS_ACCOUNT_ID" \
    "--sessionlayer.ca.aws.endpoint-override=$KMS_ENDPOINT" \
    "--sessionlayer.ca.aws.allow-endpoint-override=true" \
    "--sessionlayer.ca.aws.allow-insecure-endpoint=true"
}

start_cp() {
  log "starting the real Control Plane jar (mTLS :$FS_CP_MTLS_PORT, REST :$FS_CP_REST_PORT)"
  # azure.enabled/vault-uri are set unconditionally, from boot, while every CA is
  # still 'local' - the first session below (still local) is the proof that configuring
  # Key Vault support changes nothing until a CA is actually rotated onto it.
  #
  # credential=managed-identity + IDENTITY_ENDPOINT/IDENTITY_HEADER: the vault's own
  # WWW-Authenticate challenge means the CP's credential must actually obtain a token, and
  # this is the shape that needs no real Entra tenant - msal4j's App Service managed-
  # identity source is a plain, unauthenticated-to-us GET, never the tenant/authority-
  # validated OAuth2 path the other credential kinds would need. It is also the credential
  # documented as the production recommendation (no secret to leak or rotate), not a
  # test-only shortcut.
  #
  # aws.* is set unconditionally from boot for the same reason azure.* is, and there is no
  # credential property to set: the SDK's default chain resolves the AWS_* variables below,
  # which is the one place a credential belongs. allow-insecure-endpoint is the deliberate
  # opt-in a plaintext LocalStack endpoint requires - assert_cp_refuses_insecure_kms_endpoint
  # has already proven, against this same jar, that omitting it refuses the boot.
  arm_bootstrap_escape_hatch
  local ca_flags=() jvm_flags=()
  mapfile -t ca_flags < <(cp_key_service_flags)
  [[ -n "${KEYVAULT_TRUSTSTORE:-}" ]] && jvm_flags=(
    "-Djavax.net.ssl.trustStore=$KEYVAULT_TRUSTSTORE"
    -Djavax.net.ssl.trustStorePassword=changeit
  )
  SESSIONLAYER_CA_LOCAL_ALLOW_DEV_KEK=true \
  SESSIONLAYER_MTLS_SERVER_PORT="$FS_CP_MTLS_PORT" \
  SERVER_PORT="$FS_CP_REST_PORT" \
  SESSIONLAYER_RECORDING_WORM_ENDPOINT="$MINIO_ENDPOINT" \
  SPRING_R2DBC_URL="r2dbc:postgresql://localhost:${FS_PG_PORT}/sessionlayer" \
  SPRING_R2DBC_USERNAME="sessionlayer" SPRING_R2DBC_PASSWORD="sessionlayer" \
  SPRING_FLYWAY_URL="jdbc:postgresql://localhost:${FS_PG_PORT}/sessionlayer" \
  SPRING_FLYWAY_USER="sessionlayer" SPRING_FLYWAY_PASSWORD="sessionlayer" \
  IDENTITY_ENDPOINT="${MSI_ENDPOINT:-}" IDENTITY_HEADER="fs-e2e-keyvault-double" \
  AWS_ACCESS_KEY_ID="${KMS_ACCESS_KEY_ID:-}" AWS_SECRET_ACCESS_KEY="${KMS_SECRET_ACCESS_KEY:-}" AWS_REGION="${KMS_REGION:-}" \
    java \
      "${jvm_flags[@]}" \
      -jar "$CP_JAR" \
      --sessionlayer.rest-security.basic-auth.enabled=true \
      --sessionlayer.rest-security.basic-auth.username="$BOOTSTRAP_USER" \
      --sessionlayer.rest-security.basic-auth.password-hash="$BOOTSTRAP_PASSWORD_HASH" \
      --sessionlayer.rest-security.basic-auth.allowed-cidrs=127.0.0.1/32,::1/128 \
      "${ca_flags[@]}" \
      > "$WORKDIR/cp.log" 2>&1 &
  CP_PID=$!; PIDS+=("$CP_PID")
  local deadline=$((SECONDS + WAIT_SECS))
  until curl -sf "$CP_REST/v1/healthz" >/dev/null 2>&1; do
    kill -0 "${PIDS[-1]}" 2>/dev/null || { tail -60 "$WORKDIR/cp.log" >&2; die "CP process exited during startup"; }
    [[ $SECONDS -lt $deadline ]] || { tail -60 "$WORKDIR/cp.log" >&2; die "CP never became healthy"; }
    sleep 2
  done
  ok "Control Plane healthy (log: $WORKDIR/cp.log)"
}

printed_bootstrap_credential() {
  sed -n 's/.*FIRST-ADMIN BOOTSTRAP CREDENTIAL (shown once): \([A-Za-z0-9_-]*\).*/\1/p' "$WORKDIR/cp.log" | head -1
}

# Something has to be first, and this is it. Deployment configuration arms the Basic
# escape hatch; the Control Plane prints a one-time bootstrap credential to its log on a
# first boot; the operator reads it out of the log and claims it, naming the escape-hatch
# username as the subject, which binds platform-admin to that name. Reading a log the
# operator already owns is not a database credential, and the claim endpoint itself needs
# no credential at all - which is why this call does not carry one.
claim_first_admin() {
  operator_step "bootstrap the first admin" rest-only
  local deadline=$((SECONDS + 180)) credential="" resp code
  # The printed credential is also the readiness signal for the operator-settings
  # singleton: the bootstrap runner creates the row before it arms anything.
  until credential="$(printed_bootstrap_credential)"; [[ -n "$credential" ]]; do
    kill -0 "$CP_PID" 2>/dev/null || die "the Control Plane exited before printing a bootstrap credential"
    [[ $SECONDS -lt $deadline ]] || die "no first-admin bootstrap credential was printed - is this database really fresh?"
    sleep 2
  done
  resp="$(curl -s -w $'\n%{http_code}' -X POST "$CP_REST/v1/bootstrap/claim" -H 'Content-Type: application/json' \
    -d "$(json credential "$credential" subject "$BOOTSTRAP_USER")")"
  code="$(printf %s "$resp" | tail -1)"
  [[ "$code" == 200 ]] || die "the bootstrap claim was refused (HTTP $code): $(printf %s "$resp" | sed '$d')"

  api_ok GET /v1/operator-settings > "$WORKDIR/settings-at-install.json"
  ok "first admin bootstrapped: '$BOOTSTRAP_USER' claimed the printed credential and resolves platform-admin"
}

provision_admin_service_account() {
  operator_step "create the admin machine identity" rest-only
  local created credential roles sa_id role_id
  created="$(api_ok POST /v1/service-accounts \
    "$(json name "$ADMIN_ID" description "full-stack first-install admin" authMethod client_secret)")"
  sa_id="$(json_get "$created" id)"
  [[ -n "$sa_id" ]] || die "the service-account response carried no id: $created"

  credential="$(api_ok POST "/v1/service-accounts/$sa_id/credentials" "$(json credentialType client_secret)")"
  ADMIN_SECRET="$(json_get "$credential" clientSecret)"
  [[ -n "$ADMIN_SECRET" ]] || die "the credential response carried no client secret: $credential"

  roles="$(api_ok GET /v1/roles)"
  role_id="$(printf %s "$roles" | python3 -c '
import json, sys
for role in json.load(sys.stdin).get("items") or []:
    if role.get("name") == sys.argv[1]:
        print(role["id"])
        break' platform-admin)"
  [[ -n "$role_id" ]] || die "the bootstrap claim created no platform-admin role: $roles"
  api_ok POST /v1/role-bindings "$(json roleId "$role_id" subjectKind user subject "$ADMIN_ID")" >/dev/null

  mint_admin_token
  api_ok GET /v1/operator-settings >/dev/null
  ok "machine identity '$ADMIN_ID' created over REST, bound to platform-admin, and now in use"
}

# Mint a machine bearer from the public client-credentials endpoint. Request and response
# are OAuth2 snake_case; the Control Plane self-signs and self-verifies with a key
# regenerated per boot, so this has to be re-run after any Control Plane restart.
mint_admin_token() {
  local resp
  resp="$(curl -s "$CP_REST/v1/oauth2/token" -H 'Content-Type: application/json' \
    -d "$(json grant_type client_credentials client_id "$ADMIN_ID" client_secret "$ADMIN_SECRET")")"
  ADMIN_TOKEN="$(json_get "$resp" access_token)"
  [[ -n "$ADMIN_TOKEN" ]] || die "could not mint the admin machine token: $resp"
  use_machine_credential
  ok "admin machine bearer minted (client-credentials)"
}

# The two pieces of public trust material an install has to distribute: the internal mTLS
# anchor the Gateway pins, and the SESSION CA public key the node lists in
# TrustedUserCAKeys. The inner-leg user certificate is signed by the session CA, so that
# is the key a node must trust - not the mTLS anchor.
export_trust_material() {
  operator_step "export the trust anchor and the session CA public key" rest-only
  local D="$WORKDIR" anchor ca served computed line_fingerprint code

  anchor="$(api_ok_eventually /v1/cas/mtls/trust-anchor)"
  printf %s "$anchor" | python3 -c 'import sys,json;sys.stdout.write(json.load(sys.stdin)["pem"])' > "$D/ca.pem"
  openssl x509 -in "$D/ca.pem" -noout -subject >/dev/null || die "the trust-anchor PEM did not parse"
  ! grep -qi 'PRIVATE KEY' <<<"$anchor" || die "the trust-anchor response contained private key material"
  served="$(json_get "$anchor" fingerprintSha256)"
  computed="$(openssl x509 -in "$D/ca.pem" -outform der | sha256sum | cut -d' ' -f1)"
  [[ "$served" == "$computed" ]] || die "trust-anchor fingerprint mismatch: served=$served computed=$computed"

  ca="$(api_ok_eventually /v1/cas/session/public-key)"
  SESSION_CA_LINE="$(json_get "$ca" opensshPublicKey)"
  printf '%s\n' "$SESSION_CA_LINE" > "$D/session_ca.line"
  # The key type carries the curve (`ecdsa-sha2-nistp256`), so the alternation cannot
  # anchor a space straight after the family name.
  grep -qE '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+) [A-Za-z0-9+/]+=*( |$)' "$D/session_ca.line" \
    || die "the exported session CA is not an OpenSSH public-key line: $SESSION_CA_LINE"
  ! grep -qi 'PRIVATE' <<<"$ca" || die "the CA public-key response contained private key material"
  line_fingerprint="$(ssh-keygen -lf "$D/session_ca.line" | awk '{print $2}')"
  [[ "$line_fingerprint" == "$(json_get "$ca" fingerprint)" ]] \
    || die "the served fingerprint does not match the served key: $line_fingerprint vs $(json_get "$ca" fingerprint)"

  # The internal mTLS CA is not a member of this collection - it has its own trust-anchor
  # sibling - and admitting it here would put a second, unreviewed export path on it.
  code="$(api GET /v1/cas/mtls/public-key | tail -1)"
  [[ "$code" != 2?? ]] || die "the SSH CA export admitted the internal mTLS CA (HTTP $code)"

  ok "trust anchor + session CA public key exported over REST (session CA $line_fingerprint)"
}

# The step that used to force an operator to hold a database credential. With strict
# recording on - the shipped default - a Control Plane with no customer key refuses every
# session, so a first install could not be completed without it. The private half is
# generated here and never leaves; the Control Plane is given the public SPKI only, which
# is what makes the decrypt at the end of this run a proof rather than a claim.
provision_recording_key() {
  operator_step "provision the customer recording key and ratchet the WORM default" rest-only
  local D="$WORKDIR" pub fingerprint settings provisioned readback updated
  openssl ecparam -name prime256v1 -genkey -noout -out "$D/customer_key.pem" 2>/dev/null
  openssl ec -in "$D/customer_key.pem" -pubout -outform DER 2>/dev/null > "$D/customer_pub.der"
  pub="$(base64 -w0 < "$D/customer_pub.der")"
  fingerprint="$(sha256sum "$D/customer_pub.der" | cut -d' ' -f1)"

  settings="$(api_ok GET /v1/operator-settings)"
  # A first provisioning carries neither the fingerprint echo nor the acknowledgement
  # flag: both are refused when there is no key being replaced.
  provisioned="$(api_ok PUT /v1/operator-settings/recording-customer-key \
    "$(json publicKey "$pub" sealAlgorithm ecies_p256 version "%$(json_get "$settings" version)")")"
  [[ "$(json_get "$provisioned" fingerprintSha256)" == "$fingerprint" ]] \
    || die "the stored key fingerprint is not the key that was submitted"

  readback="$(api_ok GET /v1/operator-settings/recording-customer-key)"
  [[ "$(json_get "$readback" configured)" == true ]] || die "the recording key reads back unprovisioned"
  [[ "$(json_get "$readback" publicKey)" == "$pub" ]] || die "the key read back is not the key provisioned"
  ! grep -qi 'PRIVATE' <<<"$readback" || die "the recording-key response carried private key material"

  # COMPLIANCE object-lock is the strengthening direction of the ratchet, and it is what
  # makes the finalized object immutable even to the store's root credential. A genuine
  # read-modify-write of the whole resource: omitting a field would CLEAR it, and omitting
  # one a deployment property pins would be refused rather than silently reverted later.
  settings="$(api_ok GET /v1/operator-settings)"
  updated="$(api_ok PUT /v1/operator-settings "$(printf %s "$settings" | python3 -c '
import json, sys
current = json.load(sys.stdin)
body = {field: current[field]
        for field in ("auditRetentionDays", "recordingRetentionDays", "otpTtlSeconds",
                      "defaultMaxSessionSeconds", "defaultIdleTimeoutSeconds",
                      "defaultMaxConcurrentSessions")
        if current.get(field) is not None}
body["defaultWormMode"] = "compliance"
body["version"] = current["version"]
print(json.dumps(body))')")"
  [[ "$(json_get "$updated" defaultWormMode)" == compliance ]] || die "the WORM default did not move to compliance"
  [[ "$(json_get "$updated" recordingKeyConfigured)" == true ]] \
    || die "the settings resource does not report the recording key as configured"
  ok "customer recording key provisioned (sha256 $fingerprint); WORM default ratcheted to compliance"
}

create_grants() {
  operator_step "create the data-plane rule and the client pin" rest-only
  local D="$WORKDIR" fingerprint
  api_ok POST /v1/rules "$(IDENTITY="$CLIENT_IDENTITY" LOGIN="$NODE_LOGIN" python3 -c '
import json, os
print(json.dumps({"name": "fullstack-allow",
                  "identitySelector": {"identities": [os.environ["IDENTITY"]]},
                  "nodeLabelSelector": {},
                  "principals": [os.environ["LOGIN"]],
                  "ttlSeconds": 3600,
                  "capabilities": ["shell", "exec"],
                  "effect": "allow"}))')" >/dev/null

  rm -f "$D/client_key" "$D/client_key.pub"; ssh-keygen -t ed25519 -N '' -f "$D/client_key" -q
  fingerprint="$(ssh-keygen -lf "$D/client_key.pub" | awk '{print $2}')"
  api_ok POST /v1/pins "$(json fingerprint "$fingerprint" identity "$CLIENT_IDENTITY" \
    principals "%$(json_list "$NODE_LOGIN")" ttlSeconds %3600)" >/dev/null
  ok "grant + pin created over REST ($CLIENT_IDENTITY -> $NODE_LOGIN, $fingerprint)"
}

# A Gateway name has to be free before it can be enrolled under. On a genuinely fresh
# install nothing holds it and this is a no-op; a re-run against a surviving volume
# (KEEP_UP) finds the previous run's identity, and without freeing it the enrolment below
# would be a no-op rather than a test. `force` because the identity being freed is a
# Gateway this harness is about to replace.
free_gateway_name() {
  operator_step "confirm the Gateway name is free" rest-only
  local existing
  existing="$(api_ok GET "/v1/gateways?name=$GW_NAME" | python3 -c '
import json, sys
for gateway in json.load(sys.stdin).get("items") or []:
    print(gateway["id"])')"
  if [[ -z "$existing" ]]; then
    ok "no Gateway identity holds '$GW_NAME' (the fresh-install case)"
    return
  fi
  local id
  for id in $existing; do
    api_ok DELETE "/v1/gateways/$id?force=true" >/dev/null
  done
  ok "released the Gateway identity holding '$GW_NAME' over REST"
}

issue_gateway_enrollment_token() {
  operator_step "issue the Gateway enrolment token" rest-only
  local minted listed
  minted="$(api_ok POST /v1/gateway-enrollment-tokens "$(json gatewayName "$GW_NAME" ttlSeconds %7200)")"
  GW_ENROLL_TOKEN="$(json_get "$minted" token)"
  [[ -n "$GW_ENROLL_TOKEN" ]] || die "the mint returned no token: $minted"
  listed="$(api_ok GET /v1/gateway-enrollment-tokens)"
  ! grep -qF "$GW_ENROLL_TOKEN" <<<"$listed" || die "the list response leaked the raw enrolment token"
  ok "Gateway enrolment token minted over REST (single-use, $GW_NAME)"
}

# Generate the node's host key, start the node container with it + the session-CA
# TrustedUserCAKeys line the export step obtained over REST, and pin that exact host key
# in inventory (no TOFU). Still an operator step - installing a node is one - so the
# database stays out of reach; the docker stub lifts because a node is a container here.
start_node() {
  operator_step "install the node and configure its TrustedUserCAKeys"
  local D="$WORKDIR"
  [[ -n "${SESSION_CA_LINE:-}" ]] || die "no session CA line was exported; the node would trust nothing"
  log "generating the node host key (pinned; no TOFU)"
  rm -f "$D/node_host_key" "$D/node_host_key.pub"
  ssh-keygen -t ed25519 -N '' -f "$D/node_host_key" -q
  NODE_HOSTKEY_LINE="$(awk '{print $1" "$2}' "$D/node_host_key.pub")"
  NODE_HOSTKEY_FP="$(ssh-keygen -lf "$D/node_host_key.pub" | awk '{print $2}')"

  # Node network mode (FS_NODE_NETMODE), and why it matters:
  #   loopback (default): node on --network host, so the Gateway (a host process, plain
  #     TcpStream::connect) reaches its sshd on 127.0.0.1:<port> and the registered dial address
  #     is 127.0.0.1:<port>. Simple single-host connectivity - no docker port-map / SNAT in the
  #     byte path.
  #   bridge: node on a docker port-map, so its sshd sees the inner connection from the docker
  #     SNAT (172.17.0.1) - a DISTINCT IP from the client's 127.0.0.1. This is BOTH the multi-host
  #     proof AND the regression guard for it: the CP OMITS source-address on the inner-leg
  #     session cert (unit guard SessionSigningIT.mintedInnerCertOmitsSourceAddress), so a node
  #     reached over a distinct IP accepts the cert - the inner key, which never leaves the
  #     Gateway, is what actually binds the cert. A client-IP source-address pin would match 127.0.0.1
  #     in loopback (a false-pass) but FAIL here - exactly the MockCp-style blind spot this harness
  #     exists to remove. (Pre-fix, bridge was the finding's repro: the node rejected the cert with
  #     "not from a permitted source address".)
  docker rm -f "$NODE_CONTAINER" >/dev/null 2>&1 || true
  # create -> cp the host key in as root (0600) -> start, so the entrypoint's
  # ssh-keygen -A keeps our pre-placed ed25519 key (it only fills MISSING keys).
  if [[ "$FS_NODE_NETMODE" == bridge ]]; then
    log "starting the node container ($NODE_NAME; BRIDGE port-map - node sees the docker SNAT; multi-host inner-cert regression guard)"
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

register_node() {
  operator_step "register the node in inventory" rest-only
  log "registering $NODE_NAME via POST /v1/nodes (agentless 127.0.0.1:$NODE_PORT, pinned host key)"
  local body created
  body="$(NODE_NAME="$NODE_NAME" NODE_PORT="$NODE_PORT" HK="$NODE_HOSTKEY_LINE" python3 -c '
import json, os
print(json.dumps({"name": os.environ["NODE_NAME"], "address": "127.0.0.1:" + os.environ["NODE_PORT"],
                  "labels": {"env": "fullstack"}, "pinnedHostKey": os.environ["HK"]}))')"
  created="$(api_ok POST /v1/nodes "$body")"
  NODE_ID="$(json_get "$created" id)"
  [[ -n "$NODE_ID" ]] || die "POST /v1/nodes returned no node id: $created"
  ok "node registered via REST (id=$NODE_ID, agentless, active)"
}

# Tier-0 hardening profile for the real-binary run.
# FS_HARDENING: off (the default, and the unhardened baseline) | log | seccomp | full.
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
# session spills to disk - exercising that the spool lands in the Landlock-allowed
# data-dir, not /tmp. Default is the 8 MiB production value.
gw_spool_threshold() {
  case "${FS_HARDENING:-off}" in
    full | seccomp) printf '65536' ;;
    *) printf '8388608' ;;
  esac
}

launch_gateway() {
  operator_step "start the Gateway, which enrols itself with the minted token" rest-only
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
  GW_MAX_DECISION_TTL_SECS="$GW_MAX_DECISION_TTL_SECS" \
    envsubst '${CP_MTLS_ENDPOINT} ${CP_SERVER_NAME} ${GW_DATA_DIR} ${GW_ENROLL_TOKEN} ${GW_CA_PEM} ${GW_NAME} ${GW_SSH_ADDR} ${GW_HARDENING} ${GW_SPOOL_THRESHOLD} ${GW_MAX_DECISION_TTL_SECS}' \
    < "$SCRIPT_DIR/config/gateway-core.json.tmpl" > "$WORKDIR/gateway.json"
  rm -rf "$WORKDIR/gw-data"; mkdir -p "$WORKDIR/gw-data"
  RUST_LOG="${GW_RUST_LOG:-info}" "$GATEWAY_BIN" --config "$WORKDIR/gateway.json" > "$WORKDIR/gateway.log" 2>&1 &
  GW_PID=$!; PIDS+=("$GW_PID")
  local deadline=$((SECONDS + 180))
  # Wait for the accept loop to be up - which is AFTER hardening is
  # applied (bind→apply→serve), so this proves a session runs under the profile.
  until grep -q "outer SSH leg listening" "$WORKDIR/gateway.log" 2>/dev/null; do
    kill -0 "$GW_PID" 2>/dev/null || { tail -40 "$WORKDIR/gateway.log" >&2; die "Gateway exited during startup (enrollment?)"; }
    [[ $SECONDS -lt $deadline ]] || { tail -40 "$WORKDIR/gateway.log" >&2; die "Gateway outer leg never started"; }
    sleep 1
  done
  ok "Gateway enrolled + outer SSH leg on 127.0.0.1:$FS_GW_SSH_PORT (log: $WORKDIR/gateway.log)"
}

ssh_attempt() {
  docker run --rm --network host -v "$WORKDIR/client_key:/mnt/client_key:ro" --entrypoint sh \
    "$CLIENT_IMAGE" -c "cp /mnt/client_key /root/k && chmod 600 /root/k && \
      ssh -p $FS_GW_SSH_PORT -i /root/k -o IdentitiesOnly=yes -o PreferredAuthentications=publickey \
        -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=25 \
        '$1%$2@127.0.0.1' '$3'" 2>&1
}

run_session() {
  operator_step "run a real SSH session through the Gateway"
  log "ssh $NODE_LOGIN%$NODE_NAME@gw (:$FS_GW_SSH_PORT) - real CP Authorize -> real node"
  # --entrypoint sh: the ssh-client image's ENTRYPOINT is `sleep infinity`, so a bare
  # `docker run image sh -c ...` would exec `sleep sh -c ...`. Copy the key to a
  # root-owned 0600 path inside the container to sidestep host-uid perm quirks.
  AGENT_SIDE_LOG=""
  [[ "$TOPOLOGY" == agent ]] && AGENT_SIDE_LOG="$(agent_log | tail -25)"
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
    || die "cross-stack ssh failed:\n$SESSION_OUT\n--- gateway.log ---\n$(tail -30 "$WORKDIR/gateway.log")${AGENT_SIDE_LOG:+\n--- agent.log ---\n$(agent_log | tail -25)}"
  grep -q FULLSTACK_PATH_OK <<<"$SESSION_OUT" || die "node output did not return: $SESSION_OUT"
  grep -q "$MARKER" <<<"$SESSION_OUT" || die "session marker not returned: $SESSION_OUT"
  ok "command ran on the REAL node via the REAL CP Authorize decision; output returned"
}

# The operator's own route to the bytes, and the crown-jewel proof: list the recording
# over the API, ask for an export URL, download it, and open it with the private key that
# never left this machine. The Control Plane can do none of the last part - it only ever
# held the public half - so a successful decrypt demonstrates that property instead of
# asserting it. Without the decrypt, an empty or header-only finalize would satisfy every
# other check here.
export_and_decrypt_recording() {
  operator_step "export the recording and decrypt it offline" rest-only
  local D="$WORKDIR" deadline=$((SECONDS + 120)) recording="" signed url method magic size decrypted rechain
  # The Gateway finalizes off the connection teardown, so the status is eventually
  # consistent with the session having ended.
  while [[ $SECONDS -lt $deadline ]]; do
    recording="$(api_ok GET "/v1/recordings?identity=$CLIENT_IDENTITY" | python3 -c '
import json, sys
for item in json.load(sys.stdin).get("items") or []:
    if item.get("status") == "finalized":
        print(json.dumps(item))
        break')"
    [[ -n "$recording" ]] && break
    sleep 2
  done
  [[ -n "$recording" ]] \
    || die "no finalized recording for $CLIENT_IDENTITY; gateway.log tail:\n$(tail -20 "$D/gateway.log")"

  RECORDING_ID="$(json_get "$recording" id)"
  RECORDING_CHAIN="$(json_get "$recording" hashChainHead)"
  RECORDING_SIZE="$(json_get "$recording" sizeBytes)"
  [[ "$(json_get "$recording" wormMode)" == compliance ]] \
    || die "the recording's WORM mode is '$(json_get "$recording" wormMode)', expected compliance"
  [[ "$RECORDING_CHAIN" == sha256:* ]] || die "no hash-chain head was committed: $RECORDING_CHAIN"

  signed="$(api_ok POST "/v1/recordings/$RECORDING_ID/export")"
  url="$(json_get "$signed" url)"
  method="$(json_get "$signed" method)"
  [[ -n "$url" ]] || die "the export response carried no URL: $signed"
  [[ "$method" == GET ]] || die "the export URL is for $method, not GET"
  rm -f "$D/obj.bin"
  curl -sf -o "$D/obj.bin" "$url" || die "the export URL did not serve the object"
  [[ -s "$D/obj.bin" ]] || die "the exported recording object is empty"

  magic="$(head -c6 "$D/obj.bin")"
  [[ "$magic" == "SLREC1" ]] || die "the exported object is not an SLREC1 sealed object (magic='$magic')"
  size="$(wc -c < "$D/obj.bin")"
  [[ "$size" == "$RECORDING_SIZE" ]] || die "exported object size $size is not the recorded sizeBytes $RECORDING_SIZE"
  ! grep -qa "$MARKER" "$D/obj.bin" || die "SESSION PLAINTEXT MARKER found in the exported object - sealing failed"

  openssl pkcs8 -topk8 -nocrypt -in "$D/customer_key.pem" -outform DER -out "$D/customer_key.pkcs8.der" 2>/dev/null \
    || die "could not convert the customer key to PKCS8 DER"
  decrypted="$("$DECRYPT_BIN" "$D/customer_key.pkcs8.der" "$D/obj.bin" 2>"$D/decrypt.err")" \
    || die "the customer private key could not open the object: $(cat "$D/decrypt.err")"
  grep -q "$MARKER" <<<"$decrypted" \
    || die "the session marker is NOT in the DECRYPTED recording - capture and seal produced no recoverable session bytes"
  rechain="$(sed -n 's/^CHAIN_HEAD=//p' <<<"$decrypted" | head -1)"
  [[ "$rechain" == "$RECORDING_CHAIN" ]] \
    || die "the recomputed hash-chain head ($rechain) is not the finalized head ($RECORDING_CHAIN)"
  ok "recording exported over REST and opened with the offline private key: session bytes present, hash-chain recomputes"
}

# Not an operator step: a white-box cross-check that the platform's own record of the
# object matches the bytes an operator can download, and that the store really applied the
# lock. `content_digest` has no API projection - it is internal tamper-evidence rather
# than something an operator acts on - and the object lock is a property of the store, not
# of the Control Plane's metadata, so neither can be read over REST by design.
assert_recording_store_integrity() {
  log "cross-checking the exported object against the Control Plane's own record of it"
  local object_key digest computed
  read -r object_key digest < <(db_fixture -tAc \
    "SELECT object_key||' '||coalesce(content_digest,'?') FROM runtime.recording_ref ORDER BY created_at DESC LIMIT 1")
  [[ "$digest" == sha256:* ]] || die "content_digest was not committed: $digest"
  computed="sha256:$(sha256sum "$WORKDIR/obj.bin" | cut -d' ' -f1)"
  [[ "$computed" == "$digest" ]] || die "the exported object's sha256 $computed is not the recorded content_digest $digest"

  rm -f "$WORKDIR/retention.txt"
  docker run --rm --network host -v "$WORKDIR:/out" --entrypoint sh "$MINIO_IMAGE" -c "
     mc alias set fs '$MINIO_ENDPOINT' '$MINIO_USER' '$MINIO_PASS' >/dev/null 2>&1 &&
     mc stat 'fs/$WORM_BUCKET/$object_key' > /out/retention.txt 2>&1" \
    || die "could not stat the recording object in the WORM store"
  grep -qi "COMPLIANCE" "$WORKDIR/retention.txt" \
    || die "the WORM object is not COMPLIANCE object-locked; mc stat:\n$(cat "$WORKDIR/retention.txt")"
  ok "the exported object matches the recorded content digest and is COMPLIANCE object-locked"
}

# ── The connect/authorize audit event carries + is searchable by all 5 dimensions ──
# The substantive proof is SEARCHABILITY (an auditor finds the event by each
# dimension) + the single-correlationId correlated chain. The AuditEventResource response
# projects source_ip + correlation_id (top-level) and access_model (in `detail`); capabilities
# and node_labels are searchable but not projected (the schema omits them - by design).
assert_audit_dimensions() {
  log "asserting the connect/authorize audit event is searchable by all 5 dimensions + the correlated chain"
  mint_admin_token
  local sid
  sid="$(latest_session_id)"
  [[ -n "$sid" ]] || die "the sessions API returned no session to correlate against"

  api_ok GET "/v1/audit-events?correlationId=$sid&action=authz.decision" > "$WORKDIR/audit-authz.json"
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

  local q n
  for q in "sourceIp=127.0.0.1" "accessModel=standing" "capability=exec" "nodeLabel=env=fullstack" "correlationId=$sid"; do
    n="$(api_ok GET "/v1/audit-events?$q" \
      | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("items") or []))' 2>/dev/null)"
    [[ "${n:-0}" -ge 1 ]] || die "audit search by dimension returned nothing: ?$q"
    log "  search ?$q -> $n event(s)"
  done
  ok "each of source_ip / access_model / capabilities / node_labels / correlation_id is independently searchable"

  local chain
  chain="$(api_ok GET "/v1/audit-events?correlationId=$sid" \
    | python3 -c 'import sys,json
d=json.load(sys.stdin); acts=[e.get("action") for e in (d.get("items") or [])]
assert any(a=="authz.decision" for a in acts), "chain missing authz.decision: "+str(acts)
assert any(a and a.startswith("recording.") for a in acts), "chain missing recording.*: "+str(acts)
print(",".join(acts))')" || die "correlated-path chain incomplete for correlationId=$sid"
  ok "correlated path: correlationId=$sid returns the chain [$chain]"
}

# ── The per-channel re-Authorize past decision_ttl, against a REAL CP ──
# A one-shot `ssh <cmd>` opens its only channel immediately, so it can never cross the
# TTL boundary; only a multiplexed master can, and the per-repo suites drive a MockCp
# with no ssh_session table, which is the shape that cannot exhibit a re-Authorize
# failure at all. So this is the only place the composition is exercised.
#
# Succeeding is not the proof: a re-validate that never ran also succeeds. The assertion
# that matters is a SECOND authz.decision at the Control Plane for the SAME session id.
#
# The wait is a knob of its own rather than `ttl + 5` so the two can be varied against
# each other: raising the cap above the wait, without touching anything else, must make
# this assertion FAIL with exactly one decision. An assertion that cannot be made to fail
# would be indistinguishable from one that never runs.
assert_channel_revalidate() {
  local ttl="$GW_MAX_DECISION_TTL_SECS" sock="/root/cm.sock" target="$NODE_LOGIN%$NODE_NAME@127.0.0.1"
  local wait_secs="${FS_REVALIDATE_WAIT_SECS:-$((GW_MAX_DECISION_TTL_SECS + 5))}"
  local opts="-p $FS_GW_SSH_PORT -i /root/k -o IdentitiesOnly=yes -o PreferredAuthentications=publickey"
  opts="$opts -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30"
  log "per-channel re-Authorize: a multiplexed channel opened ${wait_secs}s into a connection, past a ${ttl}s decision_ttl cap, must re-Authorize at the real CP"
  mint_admin_token
  # Identify the multiplexed connection's session by set difference rather than by
  # ordering: session ids are the Gateway's random v4 UUIDs, so no sort over them means
  # "most recent", and asserting against the wrong session would read as a re-validate
  # that never ran.
  local before after out rc=0
  before="$(session_ids)"
  out="$(docker run --rm --network host -v "$WORKDIR/client_key:/mnt/client_key:ro" --entrypoint sh \
    "$CLIENT_IMAGE" -c "cp /mnt/client_key /root/k && chmod 600 /root/k && \
      ssh $opts -M -N -f -S $sock -o ControlMaster=yes '$target' && \
      ssh -S $sock '$target' 'echo CM_FIRST_OK' && \
      sleep $wait_secs && \
      ssh -S $sock '$target' 'echo CM_SECOND_OK'; \
      cmrc=\$?; ssh -S $sock -O exit '$target' >/dev/null 2>&1; exit \$cmrc" 2>&1)" || rc=$?
  [[ $rc -eq 0 ]] \
    || die "the multiplexed second channel was refused past decision_ttl - the per-channel re-Authorize failed:\n$out\n--- gateway.log ---\n$(tail -40 "$WORKDIR/gateway.log")"
  grep -q CM_FIRST_OK  <<<"$out" || die "the first multiplexed channel did not run: $out"
  grep -q CM_SECOND_OK <<<"$out" || die "the second multiplexed channel did not run: $out"

  mint_admin_token
  local sid decisions
  after="$(session_ids)"
  sid="$(BEFORE="$before" AFTER="$after" python3 -c '
import os
before = set(os.environ["BEFORE"].split())
new = [s for s in os.environ["AFTER"].split() if s not in before]
print(new[0] if new else "")')"
  [[ -n "$sid" ]] || die "the multiplexed connection produced no new session; the sessions API reports [$after]"
  decisions="$(api_ok GET "/v1/audit-events?correlationId=$sid&action=authz.decision" \
    | python3 -c 'import json,sys;print(len(json.load(sys.stdin).get("items") or []))')"
  [[ "${decisions:-0}" -ge 2 ]] \
    || die "session $sid recorded only ${decisions:-0} authz.decision event(s): the second channel was served from the cached decision, so the re-validate never ran"
  ok "per-channel re-Authorize: the second channel re-Authorized against the real CP ($decisions decisions for session $sid) and ran"
}

assert_deny_closed() {
  log "deny-path: an UNGRANTED login ($DENY_LOGIN%$NODE_NAME) must be refused by the real CP (fail closed)"
  local out rc=0
  out="$(ssh_attempt "$DENY_LOGIN" "$NODE_NAME" 'echo DENIED_SHOULD_NOT_RUN')" || rc=$?
  [[ $rc -ne 0 ]] || die "an ungranted login was NOT refused (fail-OPEN): $out"
  grep -q DENIED_SHOULD_NOT_RUN <<<"$out" && die "the command RAN on an ungranted login - deny bypassed: $out"
  ok "deny-path: the ungranted login was refused by the real CP (rc=$rc, generic denial, no command ran)"
}

# The `bearer=true` filter is NOT decorative - do not drop it as a simplification. The
# SDK's challenge policy always tries once unauthenticated first (bearer=false, refused
# with a 401) before replaying the same operation with a token, so counting every line
# matching /sign would silently double (or more) the count of every real signing
# operation. The trailing [^ ]* tolerates the real SDK's ?api-version=... query string,
# which a plain curl probe against the double does not send but the Control Plane's SDK
# client does - an earlier version of this pattern required a literal trailing space and
# would have silently read 0 forever against a real client.
keyvault_sign_count() {
  grep -cE '^POST .*/sign[^ ]* bearer=true' "$KEYVAULT_REQUEST_LOG" || true
}

# Whether a certificate was actually issued for a given session id - the ONLY reliable
# signal for that, found the hard way: a recording is created, uploaded and finalized for
# a session regardless of whether its inner-leg certificate was ever obtained, because
# recording is gated on the outer-leg connection, not on cert issuance. "no new recording
# appeared" therefore proves nothing about whether a certificate was issued, and an
# earlier version of both fault-closed scenarios below asserted exactly that.
#
# Checks for the ABSENCE of a session.sign SUCCESS event, deliberately not the absence of
# any session.sign event at all: today a rejected sign (an unmapped exception in
# SessionCertificateService) leaves no audit event whatsoever, success or denied - a
# real Control Plane gap, reported and being fixed separately. Once that lands, a denied
# event will appear where today there is none, and this check must keep passing rather
# than start failing on what would then be a correct fix.
certificate_issued_for_session() {
  api_ok GET "/v1/audit-events?correlationId=$1&action=session.sign" \
    | python3 -c 'import json,sys
d = json.load(sys.stdin)
print("yes" if any(i.get("outcome") == "success" for i in (d.get("items") or [])) else "no")'
}

new_session_id() {
  local before="$1" after
  after="$(session_ids)"
  BEFORE="$before" AFTER="$after" python3 -c '
import os
before = set(os.environ["BEFORE"].split())
new = [s for s in os.environ["AFTER"].split() if s not in before]
print(new[0] if new else "")'
}

# "Configuring Key Vault changes nothing until a CA is rotated onto it" is worth
# more than a log a human happens to read afterward: an eager future change (e.g.
# resolving the CA's public key at startup for some new health probe) would move this
# count and nothing else in the suite would notice. Asserted, not merely observed - the
# whole first install + first session + audit search + channel re-Authorize + deny-path
# all run between start_keyvault_double and here, so this covers all of it.
assert_keyvault_untouched_before_rotation() {
  local current
  current="$(wc -l < "$KEYVAULT_REQUEST_LOG")"
  [[ "$current" -eq "$KEYVAULT_BASELINE_LINES" ]] \
    || die "the Key Vault double received $((current - KEYVAULT_BASELINE_LINES)) unexpected request(s) before the session CA was ever rotated onto it (baseline $KEYVAULT_BASELINE_LINES, now $current): $KEYVAULT_REQUEST_LOG"
  ok "the Control Plane made zero vault requests while configured for Key Vault but not yet rotated onto it ($KEYVAULT_BASELINE_LINES baseline line(s), all the harness's own readiness probes)"
}

# ── rotate the session CA onto Key Vault, over the API, no database credential ──
# A Key Vault CA's private key never leaves the vault, so adoption is necessarily a
# ROTATION onto a new key (POST /v1/cas is refused once a kind has an active CA), with
# the trust-distribution consequences that follow (redistribute_trust_for_keyvault_ca).
adopt_session_ca_onto_keyvault() {
  operator_step "rotate the session CA onto Key Vault" rest-only
  local D="$WORKDIR/keyvault" session_ca_id rotated backend state ref pubkey fp
  mint_admin_token

  session_ca_id="$(api_ok GET /v1/cas | python3 -c '
import json, sys
for ca in json.load(sys.stdin).get("items") or []:
    if ca.get("caKind") == "session" and ca.get("rotationState") == "active":
        print(ca["id"]); break')"
  [[ -n "$session_ca_id" ]] || die "no active session CA found to rotate (GET /v1/cas)"

  rotated="$(api_ok POST "/v1/cas/$session_ca_id/rotate" "$(json backend azure_keyvault keyReference "$KEY_ID")")"
  backend="$(json_get "$rotated" backend)"
  state="$(json_get "$rotated" rotationState)"
  ref="$(json_get "$rotated" keyReference)"
  [[ "$backend" == azure_keyvault ]] || die "rotate did not move the backend to azure_keyvault: $rotated"
  [[ "$state" == active ]] || die "the rotated CA is not active: $rotated"
  [[ "$ref" == "$KEY_ID" ]] || die "the rotated CA's keyReference is not the vault key: $ref vs $KEY_ID"

  pubkey="$(api_ok GET /v1/cas/session/public-key)"
  [[ "$(json_get "$pubkey" publicKeySpkiDer)" == "$PUBKEY_SPKI_B64" ]] \
    || die "the CP is not publishing the vault's public key: $(json_get "$pubkey" publicKeySpkiDer) vs $PUBKEY_SPKI_B64"
  KEYVAULT_SESSION_CA_LINE="$(json_get "$pubkey" opensshPublicKey)"
  printf '%s\n' "$KEYVAULT_SESSION_CA_LINE" > "$D/session_ca.line"
  fp="$(ssh-keygen -lf "$D/session_ca.line" | awk '{print $2}')"
  [[ "$fp" == "$(json_get "$pubkey" fingerprint)" ]] \
    || die "the served fingerprint does not match the served Key-Vault-backed key: $fp vs $(json_get "$pubkey" fingerprint)"

  grep -qE '^GET .*/keys/.*bearer=true' "$KEYVAULT_REQUEST_LOG" \
    || die "the Control Plane never authenticated a read of the key from the vault at adoption - request log: $KEYVAULT_REQUEST_LOG"
  ok "session CA rotated onto Key Vault over REST (backend=$backend keyReference=$ref, fingerprint $fp); the vault's request log recorded the read"
}

# The documented rotation procedure (the overlap window): the node already trusts the
# OLD local session CA (export_trust_material/start_node); the Key-Vault-backed CA is a
# SEPARATE trusted line, appended without removing the old one, so both verify during the
# overlap - this IS the operational step a real rotation runbook performs, so the harness
# following it is the point. TrustedUserCAKeys is re-read on every authentication attempt
# regardless, so the SIGHUP below is not what makes this take effect; it is sent anyway
# because it is what an operator's runbook does after editing the file.
redistribute_trust_for_keyvault_ca() {
  operator_step "redistribute trust for the Key-Vault-backed session CA"
  [[ -n "${KEYVAULT_SESSION_CA_LINE:-}" ]] \
    || die "no Key-Vault-backed session CA line was exported; the node would trust nothing new"
  printf '%s\n' "$KEYVAULT_SESSION_CA_LINE" | docker exec -i "$NODE_CONTAINER" sh -c 'cat >> /etc/ssh/trusted_user_ca.pub' \
    || die "could not append the Key-Vault-backed CA to the node's TrustedUserCAKeys"
  docker exec "$NODE_CONTAINER" sh -c 'kill -HUP 1' \
    || die "could not SIGHUP the node's sshd after trust redistribution"
  ok "node now trusts both the original local CA and the Key-Vault-backed session CA (appended; sshd SIGHUP'd)"
}

# The proof that sessions really do work when the CA lives in Key Vault: this session
# runs on a CA whose ACTIVE backend is now azure_keyvault, so unlike the very first
# session above (still local when it ran) the inner-leg certificate can only have been
# minted by a REAL sign against the vault double - the sign count increasing is the
# load-bearing assertion, because success alone is also what a stale local signer would
# look like.
assert_keyvault_backed_session() {
  local before after
  before="$(keyvault_sign_count)"
  [[ "$before" -eq 0 ]] \
    || die "the vault was asked to sign $before time(s) before the session CA was even rotated onto it"
  run_session
  after="$(keyvault_sign_count)"
  [[ "$after" -gt "$before" ]] \
    || die "the Key Vault double's sign count did not increase ($before -> $after) - the session cert was not signed by the vault"
  ok "Key-Vault-backed session ran; the vault double's sign count increased ($before -> $after)"
}

# This is a permanent scenario, run every time rather than exercised manually, so it
# proves the signature check "at the real network/JVM boundary, not only in a CP unit test" on every
# execution. The runtime fault-mode toggle exists exactly so this can run on every
# execution without restarting the double or changing its port (see keyvault/README.md).
#
# The restore-and-succeed step at the end is not optional: without it, "the session
# failed" cannot be told apart from "the fault-mode toggle simply broke the double" -
# proving the guard fired requires also proving the double is still capable of a normal
# session immediately afterward.
assert_keyvault_wrong_key_rejected() {
  log "wrong-key vault: flipping the vault double to sign with a different key; a NEW session must be refused and no certificate issued"
  curl -sk "$KEYVAULT_URL/_test/fault-mode?mode=wrong_key" >/dev/null \
    || die "could not arm the wrong-key fault mode on the Key Vault double"
  KEYVAULT_FAULT_MODE_ARMED=1

  mint_admin_token
  local before_sessions out rc=0
  before_sessions="$(session_ids)"
  out="$(ssh_attempt "$NODE_LOGIN" "$NODE_NAME" 'echo WRONGKEY_SHOULD_NOT_RUN')" || rc=$?
  [[ $rc -ne 0 ]] || die "a session SUCCEEDED while the vault was signing with the WRONG key: $out"
  grep -q WRONGKEY_SHOULD_NOT_RUN <<<"$out" && die "the command RAN while the vault was signing with the wrong key: $out"

  # LOAD-BEARING here, unlike the analogous string in assert_keyvault_fail_closed: there
  # the vault is stopped, so the sign-count-unchanged check independently proves it was
  # never reached, and the log line is only corroborating. Here the session genuinely
  # fails AND the vault genuinely gets called (it signs, just with the wrong key), so
  # nothing else in this scenario tells apart "the signature check caught it" from "the
  # session failed for some unrelated reason" - this grep is that discriminator. The
  # string is owned by ControlPlane's
  # io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultSigner (its verify-failure
  # reason) - it is known to drift (a citation suffix has already been
  # removed from it upstream once), so if this grep ever starts failing, re-read
  # that class fresh before assuming the guard broke.
  grep -q "returned signature does not verify against the pinned public key" "$WORKDIR/cp.log" \
    || die "cp.log shows no signature-verification failure - the session failed, but this scenario cannot tell whether the signature check caught it or something unrelated did"

  mint_admin_token
  local sid
  sid="$(new_session_id "$before_sessions")"
  [[ -n "$sid" ]] || die "the wrong-key attempt produced no new session to check for an issued certificate"
  [[ "$(certificate_issued_for_session "$sid")" == no ]] \
    || die "a certificate WAS issued for session $sid even though the vault signed with the wrong key"

  curl -sk "$KEYVAULT_URL/_test/fault-mode?mode=none" >/dev/null \
    || die "could not restore the Key Vault double to normal signing"
  KEYVAULT_FAULT_MODE_ARMED=""
  run_session
  ok "wrong-key vault: the wrong-key session was refused (no certificate issued for session $sid), and a normal session succeeded immediately after restoring the double"
}

# The credential-acquisition chain (App Service managed identity - see the credential=
# comment in start_cp and keyvault/README.md): the very first request to the vault must
# carry no Authorization at all, because the challenge has to fire before any token
# exists to attach; and the managed-identity token endpoint must be hit EXACTLY once
# across everything above (one adoption read + one session sign, each of which is
# itself two vault requests) - the credential is meant to cache and reuse the token, and
# a regression there would mean a token round trip per certificate, not merely an
# inefficiency but a rate-limit risk against a real vault.
assert_keyvault_credential_flow() {
  local first_sdk_line msi_hits
  # NOT head -1: the harness's own readiness-probe curls in start_keyvault_double land
  # earlier in the log and are also (trivially) bearer=false, which would make this pass
  # for the wrong reason regardless of the Control Plane's actual behavior. Filtering to
  # the SDK's own user-agent isolates the first request that genuinely came from it.
  first_sdk_line="$(grep 'User-agent=\[azsdk-' "$KEYVAULT_REQUEST_LOG" | head -1)"
  [[ -n "$first_sdk_line" ]] || die "no request from the Control Plane's SDK ever reached the vault"
  [[ "$first_sdk_line" == *"bearer=false"* ]] \
    || die "the Control Plane's first request to the vault was not unauthenticated: $first_sdk_line"
  # Same reasoning: the readiness probe also hits /msi/token (bare, no query string), so a
  # pattern that does not require one silently over-counts by exactly one. Only the SDK's
  # own call carries ?api-version=...&resource=....
  msi_hits="$(grep -cE '^GET /msi/token\?' "$KEYVAULT_REQUEST_LOG" || true)"
  [[ "$msi_hits" -eq 1 ]] \
    || die "the managed-identity token endpoint was hit $msi_hits time(s); expected exactly 1 (the credential should cache and reuse the token, not re-fetch it per operation)"
  ok "credential flow: the Control Plane's first vault request carried no Authorization, and the managed-identity token was fetched exactly once and reused for every operation since"
}

# ── The single most important behavioral requirement of the Key Vault CA backend: an
# unreachable vault must NEVER fall back to local signing. Stop the double (the CP stays
# up) and attempt a session. A bare rc!=0 also holds for an unrelated failure (e.g. an
# ungranted login or the wrong node), so that is not what this scenario turns on - the
# two assertions below it are, because each is checked against a party other than the
# SSH client itself: the vault's own counter (it cannot have been reached without moving)
# and whether a certificate was actually issued for the new session (see
# certificate_issued_for_session - NOT "did a recording appear", which is created
# regardless of inner-leg outcome and was this scenario's own bug the first time a real
# jar exercised it). Fault-inject by pointing NODE_LOGIN/NODE_NAME at a login that was
# never going to work: rc!=0 still holds, but both of those load-bearing checks then
# correctly find nothing wrong, exposing that a bare rc!=0 check would have passed for
# the wrong reason.
assert_keyvault_fail_closed() {
  log "fail-closed: stopping the Key Vault double; a NEW session on the Key-Vault-backed CA must fail closed, never fall back to local"
  local before_signs before_sessions out rc=0
  before_signs="$(keyvault_sign_count)"
  mint_admin_token
  before_sessions="$(session_ids)"

  kill "$KV_PID" 2>/dev/null || true
  local d=$((SECONDS + 15))
  while kill -0 "$KV_PID" 2>/dev/null && [[ $SECONDS -lt $d ]]; do sleep 1; done

  out="$(ssh_attempt "$NODE_LOGIN" "$NODE_NAME" 'echo KVDOWN_SHOULD_NOT_RUN')" || rc=$?
  [[ $rc -ne 0 ]] || die "a session SUCCEEDED with the Key Vault double down (fail-OPEN): $out"
  grep -q KVDOWN_SHOULD_NOT_RUN <<<"$out" && die "the command RAN with the Key Vault double down - fail-open: $out"

  local after_signs
  after_signs="$(keyvault_sign_count)"
  [[ "$after_signs" -eq "$before_signs" ]] \
    || die "the vault double's sign count moved ($before_signs -> $after_signs) while it was stopped - impossible unless something else is signing"

  mint_admin_token
  local sid
  sid="$(new_session_id "$before_sessions")"
  [[ -n "$sid" ]] || die "the vault-down attempt produced no new session to check for an issued certificate"
  [[ "$(certificate_issued_for_session "$sid")" == no ]] \
    || die "a certificate WAS issued for session $sid even though the Key Vault double was stopped"

  # Corroborating only: names the failure as Key-Vault-specific rather than merely
  # confirming the two checks above. Not what the scenario turns on - this string is owned
  # by ControlPlane's io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultSigner
  # .KeyVaultSigningException message text, not a contract this repo controls, so its
  # absence still fails loudly here, but a change to it should not need touching this
  # scenario's verdict - update the string, not the check's shape, when it moves.
  grep -q "Key Vault signing failed for key" "$WORKDIR/cp.log" \
    || die "cp.log shows no Key-Vault-specific signing failure (corroborating check) - the session failed, but not visibly for the Key Vault reason"
  ok "fail-closed: with the Key Vault double down, the new session failed closed (rc=$rc); sign count unchanged ($before_signs); no certificate issued for session $sid; the Control Plane never fell back to local"
}

# ── the AWS KMS leg ──────────────────────────────────────────────────────────
# The same claim the Key Vault leg makes, for the other key service: the Control Plane has
# been booted with sessionlayer.ca.aws.* set since start_cp, and everything above - the
# whole first install, several real sessions, the audit searches, and an entire rotation
# onto a DIFFERENT key service - has run without it making one KMS call. Asserted rather
# than read off a log afterwards, because an eager future change (resolving a CA's public
# key at startup for some new health probe, say) would move these counts and nothing else
# in the suite would notice.
# The redirect's only runtime trace. Once the process is up an endpoint override is
# otherwise invisible - no field on the CA, nothing in the certificates it signs - so an
# operator inspecting a running Control Plane has no other way to learn that its KMS calls,
# and the credentials signing them, are going somewhere the region did not choose. A startup
# line nobody ever checks is indistinguishable from one that was never emitted, which is why
# this is asserted rather than left for a human to notice.
assert_kms_endpoint_override_is_logged() {
  grep -q "AWS KMS calls are redirected to $KMS_ENDPOINT by sessionlayer.ca.aws.endpoint-override" "$WORKDIR/cp.log" \
    || die "the Control Plane logged no warning that its KMS endpoint is overridden - the redirect would leave no runtime trace at all; see $WORKDIR/cp.log"
  grep -q "Plaintext HTTP is permitted on it." "$WORKDIR/cp.log" \
    || die "the endpoint-override warning does not record that plaintext HTTP is permitted, which this run has enabled; see $WORKDIR/cp.log"
  ok "the Control Plane warned at startup that its KMS endpoint is overridden to $KMS_ENDPOINT, and that plaintext is permitted on it"
}

assert_kms_untouched_before_rotation() {
  local signs pubkeys
  signs="$(kms_sign_count)"
  pubkeys="$(kms_get_public_key_count)"
  [[ "$signs" -eq 0 ]] \
    || die "KMS was asked to sign $signs time(s) before the session CA was ever rotated onto it"
  [[ "$pubkeys" -eq "$KMS_BASELINE_GETPUBKEY" ]] \
    || die "KMS served $((pubkeys - KMS_BASELINE_GETPUBKEY)) unexpected GetPublicKey call(s) before the session CA was rotated onto it (baseline $KMS_BASELINE_GETPUBKEY, now $pubkeys)"
  ok "the Control Plane made zero KMS calls while configured for KMS but not yet rotated onto it (0 signatures; $KMS_BASELINE_GETPUBKEY GetPublicKey, all the harness's own)"
}

# Adoption is a ROTATION for the same reason it is on Key Vault: a KMS-held private key
# cannot be imported, so the CA moves onto a new key rather than migrating its old one,
# with the trust-distribution consequences that follow (redistribute_trust_for_kms_ca).
#
# The CA rotated here is already on Key Vault, so this is a key-service-to-key-service
# rotation rather than local -> KMS, and that is the stronger claim: no part of the path
# can be satisfied by a database-held private key that was simply left in place, because
# there has not been one since the Key Vault rotation above.
adopt_session_ca_onto_kms() {
  # Read before the operator phase opens - docker is deliberately unavailable inside one,
  # and this is a harness assertion rather than anything an operator does.
  KMS_PUBKEYS_BEFORE_ADOPTION="$(kms_get_public_key_count)"
  operator_step "rotate the session CA onto AWS KMS" rest-only
  local D="$WORKDIR/kms" session_ca_id rotated backend state ref pubkey fp
  mint_admin_token

  session_ca_id="$(api_ok GET /v1/cas | python3 -c '
import json, sys
for ca in json.load(sys.stdin).get("items") or []:
    if ca.get("caKind") == "session" and ca.get("rotationState") == "active":
        print(ca["id"]); break')"
  [[ -n "$session_ca_id" ]] || die "no active session CA found to rotate (GET /v1/cas)"

  rotated="$(api_ok POST "/v1/cas/$session_ca_id/rotate" "$(json backend aws_kms keyReference "$KMS_KEY_ARN")")"
  backend="$(json_get "$rotated" backend)"
  state="$(json_get "$rotated" rotationState)"
  ref="$(json_get "$rotated" keyReference)"
  [[ "$backend" == aws_kms ]] || die "rotate did not move the backend to aws_kms: $rotated"
  [[ "$state" == active ]] || die "the rotated CA is not active: $rotated"
  [[ "$ref" == "$KMS_KEY_ARN" ]] || die "the rotated CA's keyReference is not the KMS key ARN: $ref vs $KMS_KEY_ARN"

  pubkey="$(api_ok GET /v1/cas/session/public-key)"
  [[ "$(json_get "$pubkey" publicKeySpkiDer)" == "$KMS_PUBKEY_SPKI_B64" ]] \
    || die "the CP is not publishing the KMS key's public half: $(json_get "$pubkey" publicKeySpkiDer) vs $KMS_PUBKEY_SPKI_B64"
  KMS_SESSION_CA_LINE="$(json_get "$pubkey" opensshPublicKey)"
  printf '%s\n' "$KMS_SESSION_CA_LINE" > "$D/session_ca.line"
  fp="$(ssh-keygen -lf "$D/session_ca.line" | awk '{print $2}')"
  [[ "$fp" == "$(json_get "$pubkey" fingerprint)" ]] \
    || die "the served fingerprint does not match the served KMS-backed key: $fp vs $(json_get "$pubkey" fingerprint)"
  ! grep -qi 'PRIVATE' <<<"$pubkey" || die "the CA public-key response contained private key material"
  ok "session CA rotated onto AWS KMS over REST (backend=$backend keyReference=$ref, fingerprint $fp)"
}

redistribute_trust_for_kms_ca() {
  operator_step "redistribute trust for the KMS-backed session CA"
  [[ -n "${KMS_SESSION_CA_LINE:-}" ]] \
    || die "no KMS-backed session CA line was exported; the node would trust nothing new"
  printf '%s\n' "$KMS_SESSION_CA_LINE" | docker exec -i "$NODE_CONTAINER" sh -c 'cat >> /etc/ssh/trusted_user_ca.pub' \
    || die "could not append the KMS-backed CA to the node's TrustedUserCAKeys"
  docker exec "$NODE_CONTAINER" sh -c 'kill -HUP 1' \
    || die "could not SIGHUP the node's sshd after trust redistribution"
  ok "node now trusts the KMS-backed session CA as well (appended; sshd SIGHUP'd)"
}

# The headline claim of this leg: a real SSH session, through the real Gateway, to the real
# node, whose inner-leg certificate was signed by a CA key held in KMS.
#
# Success alone is not the proof - a Control Plane that quietly kept signing with a key it
# already held would look identical from the client's side - so the load-bearing assertions
# are two counters read from KMS's OWN request log: the adoption GetPublicKey (the single
# read this seam performs) and a successful Sign across the session.
#
# There is a second, weaker argument available here - the Key Vault double is already
# stopped by the time this runs, so a session that succeeds cannot be vault-signed - and it
# is deliberately NOT what this turns on. That argument is a property of the order the
# scenarios happen to run in, which the next person to add a scenario is free to change
# without ever reading this comment. The counters are a property of what KMS was actually
# asked to do, so they keep meaning the same thing in any order.
assert_kms_backed_session() {
  local before after pubkeys
  pubkeys="$(kms_await_count kms_get_public_key_count $((KMS_PUBKEYS_BEFORE_ADOPTION + 1)))" \
    || die "KMS records no GetPublicKey across the rotation (still $KMS_PUBKEYS_BEFORE_ADOPTION) - the adopted CA's public half came from somewhere other than KMS"
  before="$(kms_sign_count)"
  run_session
  after="$(kms_await_count kms_sign_count $((before + 1)))" \
    || die "KMS's own request log records no successful Sign across the session ($before -> $after) - the inner-leg certificate was not signed in KMS"
  ok "KMS-backed session ran on the real node; KMS's sign count increased ($before -> $after) and its adoption read is recorded ($KMS_PUBKEYS_BEFORE_ADOPTION -> $pubkeys)"
}

# The guard the whole backend rests on: every signature KMS returns is verified locally
# against the pinned public key before it is trusted, which is what turns "the KMS key is
# pinned" from a documented intent into an enforced one. A permanent scenario, run every
# time, so it is proven at the real network and JVM boundary rather than by a unit test
# over a mocked client - the Azure backend's equivalent is permanent for the same reason,
# and the two guards protect the same property.
#
# The fault is injected with LocalStack's `_custom_id_` tag: the pinned ARN is re-created
# from a DIFFERENT keypair, so the reference the CA is anchored to resolves, and answers,
# and signs - with the wrong key. Against real KMS this is the shape an alias repoint
# produces, which is why the key-reference grammar refuses aliases outright; here it is the
# nearest faithful reproduction, because KMS asymmetric key material never rotates in place.
#
# Note what is deliberately NOT the discriminator. The session fails, but so does an
# ungranted login. KMS is reached and does sign, so an unchanged sign count would prove
# nothing either - the count going UP is what separates this from the unreachable case
# below. What identifies the pinned-key check as the thing that refused is the cp.log grep,
# and here that grep is load-bearing rather than corroborating.
assert_kms_wrong_key_rejected() {
  log "flipping the pinned KMS ARN onto different key material; a NEW session must be refused and no certificate issued"
  local pinned_arn="$KMS_KEY_ARN" pinned_spki="$KMS_PUBKEY_SPKI_B64" key_id="${KMS_KEY_ARN##*/}"

  # Stopping is how LocalStack is made to forget the real key so the ARN can be rebuilt on
  # top of it; the snapshot is taken for the same reason it is in assert_kms_fail_closed,
  # since the container is a prune candidate for as long as it is down.
  docker stop "$KMS_CONTAINER" >/dev/null || die "could not stop KMS to swap the key material"
  KMS_LOG_SNAPSHOT="$WORKDIR/kms/localstack-at-keyswap.log"
  docker logs "$KMS_CONTAINER" > "$KMS_LOG_SNAPSHOT" 2>&1 \
    || die "could not snapshot KMS's request log before swapping the key material"
  kms_restart
  kms_create_key "$key_id"

  [[ "$KMS_KEY_ARN" == "$pinned_arn" ]] \
    || die "the impostor key did not take the pinned ARN ($KMS_KEY_ARN vs $pinned_arn) - the CA is no longer pointed at it, so this scenario would prove nothing"
  [[ "$KMS_PUBKEY_SPKI_B64" != "$pinned_spki" ]] \
    || die "the re-created key carries the SAME public key as the pinned one - no fault was injected and this scenario would prove nothing"

  # Read after the restart so both counts are on the same log, whether the container was
  # restarted or replaced.
  local before_signs after_signs before_sessions out rc=0
  before_signs="$(kms_sign_count)"
  mint_admin_token
  before_sessions="$(session_ids)"

  out="$(ssh_attempt "$NODE_LOGIN" "$NODE_NAME" 'echo WRONGKEY_SHOULD_NOT_RUN')" || rc=$?
  [[ $rc -ne 0 ]] || die "a session SUCCEEDED while KMS was signing with the WRONG key: $out"
  grep -q WRONGKEY_SHOULD_NOT_RUN <<<"$out" && die "the command RAN while KMS was signing with the wrong key: $out"

  after_signs="$(kms_await_count kms_sign_count $((before_signs + 1)))" \
    || die "KMS was never asked to sign ($before_signs -> $after_signs) - the session failed before reaching it, so this run says nothing about the pinned-key check"

  # LOAD-BEARING, unlike the same-shaped grep in assert_kms_fail_closed: there the container
  # is stopped and the flat sign count independently proves KMS was never reached, so the log
  # line only corroborates. Here the session genuinely fails AND KMS genuinely signs, so
  # nothing else tells "the pinned-key check caught it" apart from "the session failed for an
  # unrelated reason". The string is owned by ControlPlane's AwsKmsSigner and is known to
  # drift; the message around it carries an account-redacted ARN
  # (arn:aws:kms:<region>:***:key/<id>), so match the reason and never a full ARN. If this
  # ever starts failing, re-read that class fresh before assuming the guard broke.
  grep -q "returned signature does not verify against the pinned public key" "$WORKDIR/cp.log" \
    || die "cp.log shows no pinned-key verification failure - the session failed, but this scenario cannot tell whether the guard caught it or something unrelated did"

  mint_admin_token
  local sid
  sid="$(new_session_id "$before_sessions")"
  [[ -n "$sid" ]] || die "the wrong-key attempt produced no new session to check for an issued certificate"
  [[ "$(certificate_issued_for_session "$sid")" == no ]] \
    || die "a certificate WAS issued for session $sid even though KMS signed with the wrong key"
  ok "the wrong-key session was refused (KMS signed, $before_signs -> $after_signs; the pinned-key check rejected it; no certificate issued for session $sid)"

  log "restoring KMS to a key the CA can be rotated onto, and proving a normal session still runs"
  kms_create_key
  adopt_session_ca_onto_kms
  redistribute_trust_for_kms_ca
  assert_kms_backed_session
  ok "a normal session succeeded immediately after restoring KMS to a correctly-pinned key"
}

# The most important behavioural requirement of the KMS backend: an unreachable KMS must
# NEVER fall back to local signing. The container is stopped outright, so the SDK gets a
# connection refused rather than a slow timeout. A bare rc!=0 is not what this scenario
# turns on - an ungranted login or a wrong node name produces one too - the two checks
# below are, and each is judged against a party other than the ssh client: KMS's own
# counter, which cannot move while its container is stopped, and whether a certificate was
# actually issued for the session the attempt created (see certificate_issued_for_session;
# NOT "did a recording appear", which happens regardless of the inner leg's outcome).
assert_kms_fail_closed() {
  log "stopping KMS; a NEW session on the KMS-backed CA must fail closed, never fall back to local"
  local before_signs before_sessions out rc=0
  before_signs="$(kms_sign_count)"
  mint_admin_token
  before_sessions="$(session_ids)"

  docker stop "$KMS_CONTAINER" >/dev/null || die "could not stop the LocalStack KMS container"
  # Snapshotted the instant it is stopped, because from here on nothing guarantees the
  # container still exists: pruning stopped containers is routine, and it takes the request
  # log - the thing this whole scenario is judged on - with it. Taken here, at a point where
  # die() still ends the run, rather than lazily inside a counter, where a command
  # substitution would swallow the exit.
  KMS_LOG_SNAPSHOT="$WORKDIR/kms/localstack-at-stop.log"
  docker logs "$KMS_CONTAINER" > "$KMS_LOG_SNAPSHOT" 2>&1 \
    || die "could not snapshot KMS's request log before the fail-closed attempt - the counter below would have nothing to read"
  [[ -s "$KMS_LOG_SNAPSHOT" ]] || die "the snapshotted KMS request log is empty"

  out="$(ssh_attempt "$NODE_LOGIN" "$NODE_NAME" 'echo KMSDOWN_SHOULD_NOT_RUN')" || rc=$?
  [[ $rc -ne 0 ]] || die "a session SUCCEEDED with KMS stopped (fail-OPEN): $out"
  grep -q KMSDOWN_SHOULD_NOT_RUN <<<"$out" && die "the command RAN with KMS stopped - fail-open: $out"

  local after_signs
  after_signs="$(kms_sign_count)"
  [[ "$after_signs" -eq "$before_signs" ]] \
    || die "KMS's sign count moved ($before_signs -> $after_signs) while its container was stopped - impossible unless something else is signing"

  mint_admin_token
  local sid
  sid="$(new_session_id "$before_sessions")"
  [[ -n "$sid" ]] || die "the KMS-down attempt produced no new session to check for an issued certificate"
  [[ "$(certificate_issued_for_session "$sid")" == no ]] \
    || die "a certificate WAS issued for session $sid even though KMS was stopped"

  grep -q "KMS signing failed for key" "$WORKDIR/cp.log" \
    || die "cp.log shows no KMS-specific signing failure (corroborating check) - the session failed, but not visibly for the KMS reason"
  ok "with KMS stopped, the new session failed closed (rc=$rc); sign count unchanged ($before_signs); no certificate issued for session $sid; the Control Plane never fell back to local"

  restore_kms_and_run_a_session
}

# Without this, "the session failed" cannot be told apart from "the harness broke", which
# is the same reason the Key Vault leg restores its double and runs a session immediately
# after faulting it.
#
# LocalStack community holds its keys in memory, so restarting the container necessarily
# produces a DIFFERENT key: recovery here is a second adoption, which is also what the loss
# of a real KMS key would force an operator to perform. Every assertion is the same
# function the first adoption used, so a recovery that only half worked fails identically.
restore_kms_and_run_a_session() {
  log "restarting KMS and re-adopting: this leg has to end able to run a normal session, or the failure above proves nothing"
  kms_restart_with_fresh_key
  adopt_session_ca_onto_kms
  redistribute_trust_for_kms_ca
  assert_kms_backed_session
  operator_flow_end
  ok "KMS recovered: a fresh key was adopted over REST and a normal session ran on it"
}

# ── With the real CP DOWN, a new session must fail CLOSED - never fail-open. LAST case
# (it kills the CP). The full-stack proves this in a way MockCp cannot: a real dead decision plane.
assert_cp_down() {
  log "CP-down: killing the real CP; a NEW session MUST fail closed (never fail-open)"
  kill "$CP_PID" 2>/dev/null || true
  local d=$((SECONDS + 25))
  while kill -0 "$CP_PID" 2>/dev/null && [[ $SECONDS -lt $d ]]; do sleep 1; done
  ! curl -sf "$CP_REST/v1/healthz" >/dev/null 2>&1 || die "CP still healthy after kill; cannot prove CP-down"
  local out rc=0
  out="$(ssh_attempt "$NODE_LOGIN" "$NODE_NAME" 'echo CPDOWN_SHOULD_NOT_RUN')" || rc=$?
  [[ $rc -ne 0 ]] || die "a session SUCCEEDED with the CP DOWN (fail-OPEN): $out"
  grep -q CPDOWN_SHOULD_NOT_RUN <<<"$out" && die "the command RAN with the CP down - fail-open: $out"
  ok "CP-down: with the real CP down, the new session failed closed (rc=$rc); the Gateway never fails open"
}

report() {
  cat <<EOF

$(printf '\033[32m========================================================\033[0m')
$(printf '\033[32m  FULL-STACK CROSS-REPO E2E PASSED (topology=%s)\033[0m' "$TOPOLOGY")
$(printf '\033[32m========================================================\033[0m')
  Real CP jar   : $CP_JAR  (mTLS :$FS_CP_MTLS_PORT, REST :$FS_CP_REST_PORT)
  Real Gateway  : $GATEWAY_BIN  (agentless, ssh :$FS_GW_SSH_PORT)
  Real node     : $NODE_NAME container, sshd :$NODE_PORT (session-CA cert auth, pinned host key)
  First install : bootstrap claim -> machine identity -> trust anchor + session CA ->
                  recording key + WORM ratchet -> rule + pin -> gateway token -> node,
                  every step over REST with the database unreachable
  Session       : ssh $NODE_LOGIN%$NODE_NAME@gw ran on the node via the REAL CP Authorize decision
  Recording     : exported over REST and opened with the offline customer private key
  Key Vault     : session CA rotated onto $KEYVAULT_URL over REST; a second session was
                  signed there (fail-closed proven with the vault stopped)
  AWS KMS       : session CA rotated on again, off Key Vault onto a key in LocalStack
                  KMS at $KMS_ENDPOINT; a session ran on a certificate signed there;
                  fail-closed proven with KMS stopped, then a fresh key adopted and a
                  normal session proven on it ($KMS_KEY_ARN)
  Logs          : $WORKDIR/{cp,gateway}.log, kms/kms.env
EOF
}

# Under a hardened profile the recorder spills ciphertext to disk once a
# session exceeds the (deliberately small) spool threshold. That spool MUST land in
# a Landlock-allowed path (the data-dir), not /tmp - a /tmp spool would EACCES and,
# in strict mode, tear the session down mid-flight. Force a spill with a large-output
# session and assert it still succeeds; every non-hardened run skips this.
assert_spill() {
  case "${FS_HARDENING:-off}" in
    full | seccomp) : ;;
    *) return 0 ;;
  esac
  log "recorder spill: forcing a spill (>64KiB output) under hardening=$FS_HARDENING - must NOT tear down"
  local out rc=0
  out="$(ssh_attempt "$NODE_LOGIN" "$NODE_NAME" 'head -c 300000 /dev/zero | base64; echo SPILL_OK')" || rc=$?
  { [[ $rc -eq 0 ]] && grep -q SPILL_OK <<<"$out"; } \
    || die "large-output session failed under hardening - the ciphertext spool was likely EACCES'd (e.g. /tmp not in the Landlock set):\n$(tail -40 "$WORKDIR/gateway.log")"
  [[ -d "$WORKDIR/gw-data/recording-spool" ]] \
    || die "expected the spool dir under the data-dir (gw-data/recording-spool)"
  ok "recorder spill under hardening=$FS_HARDENING succeeded - spool in the data-dir, strict session intact"
}


# ── TOPOLOGY=agent: the outbound-agent leg ───────────────────────────────────
#
# What this topology proves that the core one structurally cannot: a node the Gateway
# NEVER dials. The Agent dials OUT to the Gateway and splices each dial-back to the sshd
# in its own container, and the Control Plane's view of whether that node is usable comes
# from a presence claim rather than from anything anyone can reach out and probe.
#
# The health arc it walks is the whole point, and every value in it is asserted:
#   unhealthy - the Agent joined a name nobody registered, so the CP auto-created the node
#               with NO host anchor. It holds a live control channel and is still unusable,
#               because the Gateway never TOFUs. Presence alone must NOT read as healthy.
#   healthy - after the anchor is repaired over REST, with owningGateway naming this
#               Gateway.
#   unknown - a second node, anchored at registration, that no Agent ever joins.
# A run that returned a constant would fail two of those three.

build_agent_node_image() {
  if [[ -z "${FS_FORCE_BUILD:-}" ]] && docker image inspect "$AGENT_NODE_IMAGE" >/dev/null 2>&1; then
    log "reusing existing agent-node image ($AGENT_NODE_IMAGE)"
    return
  fi
  log "building the agent-node fixture image ($AGENT_NODE_IMAGE)"
  docker build -q -t "$AGENT_NODE_IMAGE" \
    --build-arg "NODE_IMAGE=$NODE_IMAGE" "$SCRIPT_DIR/agent-node" >/dev/null \
    || die "agent-node image build failed"
}

# A join token scoped to a node name the CP has never seen. Minting does not require the
# node to exist - which is exactly how a node comes to exist with no anchor.
issue_agent_join_token() {
  operator_step "issue the agent join token" rest-only
  local minted listed
  minted="$(api_ok POST /v1/join-tokens "$(json nodeName "$NODE_NAME" ttlSeconds %7200)")"
  AGENT_JOIN_TOKEN="$(json_get "$minted" token)"
  [[ -n "$AGENT_JOIN_TOKEN" ]] || die "the join-token mint returned no token: $minted"
  listed="$(api_ok GET /v1/join-tokens)"
  ! grep -qF "$AGENT_JOIN_TOKEN" <<<"$listed" || die "the list response leaked the raw join token"
  ok "agent join token minted over REST (single-use, scoped to '$NODE_NAME')"
}

register_unjoined_agent_node() {
  operator_step "register a second agent node that no Agent will join" rest-only
  local created
  created="$(api_ok POST /v1/nodes "$(NODE="$UNJOINED_NODE" HK="$NODE_HOSTKEY_LINE" python3 -c '
import json, os
print(json.dumps({"name": os.environ["NODE"], "connectorKind": "agent",
                  "labels": {"env": "fullstack"}, "pinnedHostKey": os.environ["HK"]}))')")"
  UNJOINED_NODE_ID="$(json_get "$created" id)"
  [[ -n "$UNJOINED_NODE_ID" ]] || die "POST /v1/nodes returned no id for $UNJOINED_NODE: $created"
  ok "registered $UNJOINED_NODE (agent, anchored, unclaimed)"
}

# The advertise URL is an ADDRESS, not the Gateway's name, for the same reason the Agent's
# own endpoints are: it is handed to the Agent in a dial-back instruction, and the Agent
# resolves it AFTER Landlock has taken /etc/resolv.conf and /etc/hosts away from it. A named
# advertise URL produces a dial-back the agent simply refuses, which surfaces at the Gateway
# as an opaque "agent refused the dial-back". The verified identity is unaffected - the Agent
# checks the certificate against its configured --gateway-server-name.
launch_gateway_agent() {
  operator_step "start the Gateway with its agent transport, which enrols itself" rest-only
  log "rendering + launching the real Gateway (outbound-agent transport on :$FS_GW_AGENT_PORT)"
  CP_MTLS_ENDPOINT="https://localhost:${FS_CP_MTLS_PORT}" \
  CP_SERVER_NAME="localhost" \
  GW_DATA_DIR="$WORKDIR/gw-data" \
  GW_ENROLL_TOKEN="$GW_ENROLL_TOKEN" \
  GW_CA_PEM="$WORKDIR/ca.pem" \
  GW_NAME="$GW_NAME" \
  GW_SSH_ADDR="127.0.0.1:${FS_GW_SSH_PORT}" \
  GW_AGENT_ADDR="0.0.0.0:${FS_GW_AGENT_PORT}" \
  GW_AGENT_ADVERTISE="wss://127.0.0.1:${FS_GW_AGENT_PORT}" \
    envsubst '${CP_MTLS_ENDPOINT} ${CP_SERVER_NAME} ${GW_DATA_DIR} ${GW_ENROLL_TOKEN} ${GW_CA_PEM} ${GW_NAME} ${GW_SSH_ADDR} ${GW_AGENT_ADDR} ${GW_AGENT_ADVERTISE}' \
    < "$SCRIPT_DIR/config/gateway-agent.json.tmpl" > "$WORKDIR/gateway.json"
  rm -rf "$WORKDIR/gw-data"; mkdir -p "$WORKDIR/gw-data"
  RUST_LOG="${GW_RUST_LOG:-info}" "$GATEWAY_BIN" --config "$WORKDIR/gateway.json" > "$WORKDIR/gateway.log" 2>&1 &
  GW_PID=$!; PIDS+=("$GW_PID")
  local deadline=$((SECONDS + 180))
  until grep -q "outer SSH leg listening" "$WORKDIR/gateway.log" 2>/dev/null; do
    kill -0 "$GW_PID" 2>/dev/null || { tail -40 "$WORKDIR/gateway.log" >&2; die "Gateway exited during startup (enrollment?)"; }
    [[ $SECONDS -lt $deadline ]] || { tail -40 "$WORKDIR/gateway.log" >&2; die "Gateway outer leg never started"; }
    sleep 1
  done
  grep -q "outbound-agent transport" "$WORKDIR/gateway.log" \
    || die "the Gateway started without its agent transport; the Agent would have nothing to dial:\n$(tail -40 "$WORKDIR/gateway.log")"
  ok "Gateway enrolled; outer SSH leg :$FS_GW_SSH_PORT, agent transport :$FS_GW_AGENT_PORT"
}

# The node container runs the REAL Agent binary, non-root, enrolling with the real CP over
# a real join token, then dialling out to the Gateway. Two constraints shape how it is
# started, and both were found by running it rather than by reading:
#
# 1. HOST networking, with the node's sshd on a port THIS HARNESS allocated. The Agent
#    dials out, so it needs to reach the CP and the Gateway, which are host processes; a
#    bridge container cannot necessarily reach them (on the box this was developed on, the
#    docker bridge cannot reach the host at all). Host networking removes that dependency -
#    but `--splice-addr 127.0.0.1:22` in a shared namespace would be the HOST's sshd, and on
#    a box that runs one that is a green run which proved nothing. Allocating the port here
#    and passing it as the splice address removes the ambiguity: the only thing listening on
#    FS_AGENT_NODE_PORT is the sshd this harness just started in this container.
# 2. Both endpoints are dialled by IP with the verified name supplied SEPARATELY, which is
#    not a shortcut around DNS but the only shape that works. The Agent applies Tier-0
#    hardening BEFORE it joins, and its Landlock read set is its CA file plus its join
#    material and nothing else, so /etc/resolv.conf, /etc/hosts and /etc/nsswitch.conf are
#    all unreadable by the time it dials; a hostname endpoint fails as an opaque "transport
#    error". TLS identity is unweakened - --cp-server-name / --gateway-server-name are what
#    the certificate is verified against, and they still have to match the CP-stamped SANs.
start_agent_node() {
  log "generating the node host key (the anchor is deliberately NOT registered yet)"
  local D="$WORKDIR"
  rm -f "$D/node_host_key" "$D/node_host_key.pub"
  ssh-keygen -t ed25519 -N '' -f "$D/node_host_key" -q
  NODE_HOSTKEY_LINE="$(awk '{print $1" "$2}' "$D/node_host_key.pub")"
  NODE_HOSTKEY_FP="$(ssh-keygen -lf "$D/node_host_key.pub" | awk '{print $2}')"

  docker rm -f "$AGENT_NODE_CONTAINER" >/dev/null 2>&1 || true
  docker create --name "$AGENT_NODE_CONTAINER" --network host \
    -e TRUSTED_USER_CA="$SESSION_CA_LINE" \
    -e AGENT_JOIN_TOKEN="$AGENT_JOIN_TOKEN" \
    -e AGENT_NODE_NAME="$NODE_NAME" \
    -e AGENT_CP_ENDPOINT="https://127.0.0.1:${FS_CP_MTLS_PORT}" \
    -e AGENT_CP_SERVER_NAME="controlplane" \
    -e AGENT_GATEWAY_ENDPOINT="wss://127.0.0.1:${FS_GW_AGENT_PORT}" \
    -e AGENT_GATEWAY_SERVER_NAME="$GW_NAME" \
    -e AGENT_SPLICE_ADDR="127.0.0.1:${FS_AGENT_NODE_PORT}" \
    -e AGENT_LOG="${AGENT_LOG:-info}" \
    "$AGENT_NODE_IMAGE" -p "$FS_AGENT_NODE_PORT" >/dev/null
  docker cp "$D/node_host_key"     "$AGENT_NODE_CONTAINER:/etc/ssh/ssh_host_ed25519_key"
  docker cp "$D/node_host_key.pub" "$AGENT_NODE_CONTAINER:/etc/ssh/ssh_host_ed25519_key.pub"
  docker cp "$AGENT_BIN"           "$AGENT_NODE_CONTAINER:/agent/sessionlayer-agent"
  docker cp "$D/ca.pem"            "$AGENT_NODE_CONTAINER:/agent/ca.pem"
  docker start "$AGENT_NODE_CONTAINER" >/dev/null

  local deadline=$((SECONDS + 120))
  until docker logs "$AGENT_NODE_CONTAINER" 2>&1 | grep -q "Server listening on"; do
    docker ps -q --filter "name=$AGENT_NODE_CONTAINER" | grep -q . \
      || { docker logs "$AGENT_NODE_CONTAINER" >&2; die "agent-node container exited"; }
    [[ $SECONDS -lt $deadline ]] || { agent_log >&2; die "the agent node's sshd never listened"; }
    sleep 1
  done
  ok "agent node up ($NODE_NAME; sshd in-container only, host key $NODE_HOSTKEY_FP)"
}

agent_log() { docker exec "$AGENT_NODE_CONTAINER" cat /agent/agent.log 2>/dev/null || true; }

node_view() {
  # NODES_BODY is kept for the failure path. A helper that answers "" for BOTH "the API
  # refused me" and "the node is not there yet" turns a broken query into a polling timeout
  # that blames the node - which is exactly how the first version of this wasted a run.
  NODES_BODY="$(api_ok GET /v1/nodes)"
  # NodeList's array is `nodes`, NOT the `items` every other list response in this API
  # uses. Reading `items` here yields "no such node" in EVERY state, which is a check that
  # can only ever fail - and, polled, one that blames the node for the parser's mistake.
  printf %s "$NODES_BODY" | NAME="$1" python3 -c '
import json, os, sys
want = os.environ["NAME"]
body = json.load(sys.stdin)
listed = body.get("nodes")
if listed is None:
    raise SystemExit("GET /v1/nodes has no `nodes` array; the response shape moved: %r" % body)
for node in listed:
    if node.get("name") == want:
        print(node["id"], node.get("health") or "-", node.get("owningGateway") or "-")
        break'
}

await_node_health() {
  local deadline=$((SECONDS + ${3:-120})) view
  while :; do
    view="$(node_view "$1")"
    read -r NODE_ID NODE_HEALTH NODE_OWNER <<<"${view:-- - -}"
    [[ "$NODE_HEALTH" != "$2" ]] || return 0
    [[ $SECONDS -lt $deadline ]] || {
      agent_log >&2
      printf 'GET /v1/nodes returned:\n%s\n' "$NODES_BODY" >&2
      die "node '$1' never reported health=$2 (last: health=$NODE_HEALTH owningGateway=$NODE_OWNER)"
    }
    sleep 2
  done
}

assert_agent_node_is_unhealthy_without_an_anchor() {
  log "the joined-but-anchorless node must read unhealthy, live control channel notwithstanding"
  await_node_health "$NODE_NAME" unhealthy 180
  AGENT_NODE_ID="$NODE_ID"
  local anchors count
  anchors="$(api_ok GET "/v1/nodes/$AGENT_NODE_ID/host-anchors")"
  # `anchors` is the array; a count taken from a key that does not exist is zero for the
  # wrong reason and would let this assertion pass against any response at all.
  count="$(python3 -c '
import json, sys
d = json.load(sys.stdin)
if "anchors" not in d:
    raise SystemExit("host-anchors response has no `anchors` array: %r" % d)
print(len(d["anchors"]))' <<<"$anchors")" \
    || die "could not read the anchor set: $anchors"
  [[ "$count" == 0 ]] \
    || die "the auto-created node already had $count anchor(s); the unhealthy reading proves nothing: $anchors"
  ok "auto-created node $NODE_NAME is unhealthy with zero anchors (id=$AGENT_NODE_ID)"
}

repair_host_anchor() {
  operator_step "repair the node's host anchor over REST" rest-only
  api_ok PUT "/v1/nodes/$AGENT_NODE_ID/host-anchors" \
    "$(json pinnedHostKey "$NODE_HOSTKEY_LINE")" >/dev/null
  local after
  after="$(api_ok GET "/v1/nodes/$AGENT_NODE_ID/host-anchors")"
  [[ "$(python3 -c 'import json,sys;print(len(json.load(sys.stdin)["anchors"]))' <<<"$after")" == 1 ]] \
    || die "the anchor PUT returned 2xx but the node still has no single anchor: $after"
  ok "host anchor written over REST (pinned $NODE_HOSTKEY_FP)"
}

assert_agent_node_is_healthy_and_owned() {
  log "with the anchor repaired, the node must read healthy and name its owner"
  await_node_health "$NODE_NAME" healthy 180
  [[ "$NODE_OWNER" == "$GW_NAME" ]] \
    || die "health is healthy but owningGateway is '$NODE_OWNER', not the Gateway holding the channel ('$GW_NAME')"
  ok "$NODE_NAME reports health=healthy owningGateway=$GW_NAME over GET /v1/nodes"
}

assert_unjoined_agent_node_is_unknown() {
  local view health
  view="$(node_view "$UNJOINED_NODE")"
  health="$(awk '{print $2}' <<<"$view")"
  [[ "$health" == unknown ]] \
    || die "an anchored agent node no Agent ever joined must read unknown, got '$health'"
  ok "$UNJOINED_NODE reports health=unknown (anchored, never claimed)"
}

# The reduced agent scenario. Deliberately NOT the core run's full chain: Key Vault, KMS
# and CP-down are proven there against the same binaries, and re-proving them here would
# spend the budget this leg needs. What is here is what only this topology can show.
main_agent() {
  NODE_NAME="${AGENT_NODE_NAME:-agent-01}"
  preflight
  build_artifacts
  build_agent_node_image
  start_infra
  start_cp

  claim_first_admin
  provision_admin_service_account
  export_trust_material
  provision_recording_key
  create_grants
  free_gateway_name
  issue_gateway_enrollment_token
  issue_agent_join_token
  launch_gateway_agent          # the agent transport must exist before the Agent dials it
  operator_flow_end

  start_agent_node
  assert_agent_node_is_unhealthy_without_an_anchor
  repair_host_anchor
  register_unjoined_agent_node
  operator_flow_end
  assert_agent_node_is_healthy_and_owned
  assert_unjoined_agent_node_is_unknown

  run_session
  export_and_decrypt_recording
  report_agent
}

report_agent() {
  cat <<EOF

$(printf '\033[32m========================================================\033[0m')
$(printf '\033[32m  FULL-STACK AGENT-TOPOLOGY E2E PASSED\033[0m')
$(printf '\033[32m========================================================\033[0m')
  Real CP jar   : $CP_JAR  (mTLS :$FS_CP_MTLS_PORT, REST :$FS_CP_REST_PORT)
  Real Gateway  : $GATEWAY_BIN  (ssh :$FS_GW_SSH_PORT, agent transport :$FS_GW_AGENT_PORT)
  Real Agent    : $AGENT_BIN  (in $AGENT_NODE_CONTAINER, non-root, real join token)
  Node health   : $NODE_NAME  unhealthy (joined, anchorless) -> healthy, owningGateway=$GW_NAME
                  $UNJOINED_NODE  unknown (anchored, never claimed)
  Session       : ssh $NODE_LOGIN%$NODE_NAME@gw spliced through the Agent's own channel -
                  the Gateway holds no dial address for this node and never dialled it
  Recording     : exported over REST and opened with the offline customer private key
  Logs          : $WORKDIR/{cp,gateway}.log, docker exec $AGENT_NODE_CONTAINER cat /agent/agent.log
EOF
}

main() {
  if [[ "$TOPOLOGY" == agent ]]; then main_agent; return; fi
  preflight
  build_artifacts
  start_infra
  start_keyvault_double
  start_kms_localstack
  assert_cp_refuses_insecure_kms_endpoint
  start_cp

  claim_first_admin
  provision_admin_service_account
  export_trust_material
  provision_recording_key
  create_grants
  free_gateway_name
  issue_gateway_enrollment_token
  start_node
  register_node
  launch_gateway
  run_session
  export_and_decrypt_recording
  operator_flow_end

  assert_recording_store_integrity
  assert_audit_dimensions
  assert_channel_revalidate
  assert_spill
  assert_deny_closed

  assert_keyvault_untouched_before_rotation
  adopt_session_ca_onto_keyvault
  redistribute_trust_for_keyvault_ca
  assert_keyvault_backed_session
  assert_keyvault_wrong_key_rejected
  assert_keyvault_credential_flow
  operator_flow_end

  assert_keyvault_fail_closed  # the vault double stays down from here

  assert_kms_endpoint_override_is_logged
  assert_kms_untouched_before_rotation
  adopt_session_ca_onto_kms
  redistribute_trust_for_kms_ca
  assert_kms_backed_session
  assert_kms_wrong_key_rejected
  operator_flow_end
  assert_kms_fail_closed

  assert_cp_down
  report
}
main "$@"
