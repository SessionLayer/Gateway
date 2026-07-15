#!/usr/bin/env bash
#
# Re-vendor the frozen CP <-> Gateway proto from the canonical contracts dir.
#
# The authoritative proto lives in ../ControlPlane-API/contracts/proto (Design
# §13; contracts/README.md). Because the parent SessionLayer/ folder is NOT a
# git repo and CI checks out THIS repo alone, the Gateway vendors a committed
# copy under proto/ and generates from it in build.rs.
#
# Run this to re-sync after a (versioned) contract change. It is a no-op with a
# note when the source path is absent (e.g. in CI or a lone checkout).
#
# Policy: contracts are FROZEN. Only re-sync after a versioned change per
# contracts/VERSIONING.md, honouring the N-1 compatibility window, then rebuild
# (build.rs regenerates the client/server code from the vendored copy).
set -euo pipefail
cd "$(dirname "$0")/.."

SRC_ROOT="../ControlPlane-API/contracts/proto"

if [[ ! -d "$SRC_ROOT" ]]; then
  echo "[sync-contracts] source $SRC_ROOT not present (expected in CI or a lone checkout); nothing to do."
  exit 0
fi

# Session Four added identity.proto (GatewayIdentity: EnrollGateway,
# RenewGatewayIdentity) and signing.proto (SessionSigning:
# SignSessionCertificate) as additive services on the mTLS plane. Session Five
# added authz.proto (Authorization: Authorize) — the connect-time decision.
# Session Seven added auth.proto (OuterLegAuth: ResolveUserCert / ResolvePin /
# ResolveOtp / Begin+PollDeviceFlow) — the outer-leg authentication RPCs.
# Session Nine added recording.proto (Recording: BeginRecording /
# FinalizeRecording) and an additive recording_token field on authz.proto.
# Session Ten added lock.proto (LockFeed: StreamLocks — the actively-pushed lock
# deny-list) and additive identity/groups/node_labels on authz DecisionContext.
# Session Thirteen added break-glass auth resolution to auth.proto
# (OuterLegAuth: ResolveBreakglassKey / ResolveBreakglassCode) + additive
# breakglass_token (AuthorizeRequest) and access_model (DecisionContext) on authz.
# Session Fourteen added agent/v1/wire.proto (the Agent<->Gateway wire payloads —
# messages only, no gRPC service; the framed WebSocket protocol itself is
# specified in contracts/wire/agent-gateway-v1.md), an additive node_name on
# authz NodeConnection, and IssueGatewayServerCertificate on identity.proto.
# Session Fifteen added presence.proto (Presence: Heartbeat / Release — the HA
# ownership write path; the read is folded into authz NodeConnection owner
# fields 5-8) and gateway/v1/coordination.proto (the Gateway<->Gateway
# DialBackSignal + SLGW1 relay token + RELAY_* frame payloads; the framed
# protocol itself is contracts/wire/gateway-relay-v1.md).
RELS=(
  "sessionlayer/controlplane/v1/common.proto"
  "sessionlayer/controlplane/v1/handshake.proto"
  "sessionlayer/controlplane/v1/identity.proto"
  "sessionlayer/controlplane/v1/signing.proto"
  "sessionlayer/controlplane/v1/authz.proto"
  "sessionlayer/controlplane/v1/auth.proto"
  "sessionlayer/controlplane/v1/recording.proto"
  "sessionlayer/controlplane/v1/lock.proto"
  "sessionlayer/controlplane/v1/presence.proto"
  "sessionlayer/gateway/v1/coordination.proto"
  "sessionlayer/agent/v1/wire.proto"
)

for rel in "${RELS[@]}"; do
  mkdir -p "proto/$(dirname "$rel")"
  cp -v "$SRC_ROOT/$rel" "proto/$rel"
done

# Session Fifteen also vendors the frozen wire-conformance golden frames (generated + self-
# checked from the frozen codec+proto), consumed by tests/wire_conformance.rs so the Gateway CI
# catches wire drift on its own (F-wireversion-1). Regenerate upstream only on a contract change.
CONF_SRC="../ControlPlane-API/contracts/wire/conformance/frames.json"
if [[ -f "$CONF_SRC" ]]; then
  mkdir -p proto/wire-conformance
  cp -v "$CONF_SRC" proto/wire-conformance/frames.json
fi

echo "[sync-contracts] vendored proto re-synced from $SRC_ROOT"
echo "[sync-contracts] NOTE: contracts are FROZEN; re-sync only after a versioned change (contracts/VERSIONING.md), then rebuild."
