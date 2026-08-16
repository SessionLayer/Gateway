#!/usr/bin/env bash
#
# Vendor the frozen CP <-> Gateway proto (+ wire-conformance golden frames) from
# SessionLayer/Contracts, pinned by contracts.lock. A sibling-checkout-path sync would be
# a silent no-op in CI, which checks out one repo at a time, so a sibling path never
# exists there; this does a REAL clone of the pinned tag and verifies the resolved commit
# SHA before copying anything, so a moved or re-pushed tag cannot silently swap content.
set -euo pipefail
cd "$(dirname "$0")/.."

LOCK="contracts.lock"
mode="${1:-sync}"

repo=$(sed -n 's/^repo=//p' "$LOCK")
tag=$(sed -n 's/^tag=//p' "$LOCK")
want_sha=$(sed -n 's/^sha=//p' "$LOCK")

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone --quiet --depth 1 --branch "$tag" "https://github.com/${repo}.git" "$tmp/src"
got_sha="$(git -C "$tmp/src" rev-parse HEAD)"
if [ "$got_sha" != "$want_sha" ]; then
  echo "DRIFT: ${repo}@${tag} resolves to ${got_sha}, but ${LOCK} pins ${want_sha}." >&2
  echo "       The tag may have moved. Refusing to vendor without a reviewed contracts.lock update." >&2
  exit 1
fi

PAIRS=(
  "proto/sessionlayer/controlplane/v1/common.proto|proto/sessionlayer/controlplane/v1/common.proto"
  "proto/sessionlayer/controlplane/v1/handshake.proto|proto/sessionlayer/controlplane/v1/handshake.proto"
  "proto/sessionlayer/controlplane/v1/identity.proto|proto/sessionlayer/controlplane/v1/identity.proto"
  "proto/sessionlayer/controlplane/v1/signing.proto|proto/sessionlayer/controlplane/v1/signing.proto"
  "proto/sessionlayer/controlplane/v1/authz.proto|proto/sessionlayer/controlplane/v1/authz.proto"
  "proto/sessionlayer/controlplane/v1/auth.proto|proto/sessionlayer/controlplane/v1/auth.proto"
  "proto/sessionlayer/controlplane/v1/recording.proto|proto/sessionlayer/controlplane/v1/recording.proto"
  "proto/sessionlayer/controlplane/v1/lock.proto|proto/sessionlayer/controlplane/v1/lock.proto"
  "proto/sessionlayer/controlplane/v1/presence.proto|proto/sessionlayer/controlplane/v1/presence.proto"
  "proto/sessionlayer/gateway/v1/coordination.proto|proto/sessionlayer/gateway/v1/coordination.proto"
  "proto/sessionlayer/agent/v1/wire.proto|proto/sessionlayer/agent/v1/wire.proto"
  "wire/conformance/frames.json|proto/wire-conformance/frames.json"
)


# Shared Rust sources from the Contracts repo (rust/, a sibling of contracts/).
# mtls.rs/tls.rs/secret.rs were duplicated byte-for-byte here and in the other Rust
# consumer; a fix to the pinned-cert verifier in one did not reach the other. Vendored
# as plain source, so nothing enters [dependencies] or the SBOM.
EXTRAS=(
  "$tmp/src/rust/mtls.rs|gateway-core/src/mtls.rs"
  "$tmp/src/rust/tls.rs|gateway-core/src/tls.rs"
  "$tmp/src/rust/secret.rs|gateway-core/src/secret.rs"
)

rc=0
sync_one() {
  local src="$tmp/src/contracts/$1" dst="$2"
  if [ ! -f "$src" ]; then
    echo "DRIFT: canonical ${1} is missing at ${repo}@${tag}" >&2
    rc=1
    return
  fi
  case "$mode" in
    --check)
      if diff -u "$dst" "$src" >/dev/null 2>&1; then
        echo "in sync: ${dst}"
      else
        echo "DRIFT: ${dst} differs from ${repo}@${tag}:contracts/${1}" >&2
        diff -u "$dst" "$src" >&2 || true
        rc=1
      fi
      ;;
    sync)
      mkdir -p "$(dirname "$dst")"
      cp "$src" "$dst"
      echo "vendored: ${1} -> ${dst}"
      ;;
    *)
      echo "usage: $0 [--check]" >&2
      exit 2
      ;;
  esac
}

sync_abs() {
  local src="$1" dst="$2"
  if [ ! -f "$src" ]; then
    echo "DRIFT: canonical ${src#$tmp/src/} is missing at ${repo}@${tag}" >&2
    rc=1
    return
  fi
  case "$mode" in
    --check)
      if diff -u "$dst" "$src" >/dev/null 2>&1; then
        echo "in sync: ${dst}"
      else
        echo "DRIFT: ${dst} differs from ${repo}@${tag}:${src#$tmp/src/}" >&2
        diff -u "$dst" "$src" >&2 || true
        rc=1
      fi
      ;;
    sync)
      mkdir -p "$(dirname "$dst")"
      cp "$src" "$dst"
      echo "vendored: ${src#$tmp/src/} -> ${dst}"
      ;;
  esac
}

for pair in "${PAIRS[@]}"; do
  sync_one "${pair%%|*}" "${pair##*|}"
done

for pair in "${EXTRAS[@]}"; do
  sync_abs "${pair%%|*}" "${pair##*|}"
done

# Per-file diffing only sees files we already know about, so a file ADDED to the
# vendored tree is invisible to it -- the gate would pass while shipping proto the
# pinned tag never contained. ControlPlane is immune because it diffs the whole
# subtree, but it also vendors the whole subtree; we vendor a curated subset, so the
# equivalent check is "nothing here that is not on the list".
expected=$(for pair in "${PAIRS[@]}"; do echo "${pair##*|}"; done | sort -u)
actual=$(find proto -type f \( -name '*.proto' -o -name '*.json' \) | sort)
if extra=$(comm -13 <(echo "$expected") <(echo "$actual")) && [ -n "$extra" ]; then
  echo "DRIFT: vendored file(s) not present in the curated set from ${repo}@${tag}:" >&2
  echo "$extra" | sed 's/^/  /' >&2
  rc=1
fi

if [ "$mode" = "sync" ]; then
  echo "Vendored from ${repo}@${tag} (${got_sha:0:12}). Review the diff, rebuild (cargo build), and commit."
fi
exit "$rc"
