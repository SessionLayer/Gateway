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

SRC="../ControlPlane-API/contracts/proto/sessionlayer/controlplane/v1"
DST="proto/sessionlayer/controlplane/v1"

if [[ ! -d "$SRC" ]]; then
  echo "[sync-contracts] source $SRC not present (expected in CI or a lone checkout); nothing to do."
  exit 0
fi

mkdir -p "$DST"
# Session Four added identity.proto (GatewayIdentity: EnrollGateway,
# RenewGatewayIdentity) and signing.proto (SessionSigning:
# SignSessionCertificate) as additive services on the mTLS plane.
for f in common.proto handshake.proto identity.proto signing.proto; do
  cp -v "$SRC/$f" "$DST/$f"
done

echo "[sync-contracts] vendored proto re-synced from $SRC"
echo "[sync-contracts] NOTE: contracts are FROZEN; re-sync only after a versioned change (contracts/VERSIONING.md), then rebuild."
