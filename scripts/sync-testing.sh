#!/usr/bin/env bash
#
# Re-vendor the canonical Docker test node from the parent testing/ dir.
#
# The authoritative test node (Debian 13 + OpenSSH 10, cert-only) lives in
# ../testing/docker/sshd (testing/README.md; user directive: never rely on host
# ssh for tests). Because the parent SessionLayer/ folder is NOT a git repo and
# CI checks out THIS repo alone, the node is VENDORED (committed) under
# tests/fixtures/sshd/ and driven via the `testcontainers` crate.
#
# Mirrors scripts/sync-contracts.sh. No-op with a note when the source is absent
# (CI or a lone checkout). Keep the vendored copy in sync with the canonical
# source; re-run after any change to testing/.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="../testing/docker/sshd"
DST="tests/fixtures/sshd"

if [[ ! -d "$SRC" ]]; then
  echo "[sync-testing] source $SRC not present (expected in CI or a lone checkout); nothing to do."
  exit 0
fi

mkdir -p "$DST"
for f in Dockerfile entrypoint.sh sshd_config; do
  cp -v "$SRC/$f" "$DST/$f"
done

echo "[sync-testing] vendored test node re-synced from $SRC into $DST"
