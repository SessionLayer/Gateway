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

ROOT="../testing/docker"

if [[ ! -d "$ROOT/sshd" ]]; then
  echo "[sync-testing] source $ROOT not present (expected in CI or a lone checkout); nothing to do."
  exit 0
fi

# The Debian 13 node (sshd) and, since Session Eight, the openssh-**client** that
# drives the outer/inner-leg E2E both live canonically under testing/docker/ and
# are vendored here for the lone-repo CI checkout.
mkdir -p tests/fixtures/sshd
for f in Dockerfile entrypoint.sh sshd_config; do
  cp -v "$ROOT/sshd/$f" "tests/fixtures/sshd/$f"
done

mkdir -p tests/fixtures/ssh-client
cp -v "$ROOT/ssh-client/Dockerfile" "tests/fixtures/ssh-client/Dockerfile"

echo "[sync-testing] vendored test node + ssh-client re-synced from $ROOT"
