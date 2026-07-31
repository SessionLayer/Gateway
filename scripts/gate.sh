#!/usr/bin/env bash
set -euo pipefail; cd "$(dirname "$0")/.."
# First, and cheap: a shipped alert whose selector matches no series looks
# exactly like a healthy fleet, so the observability YAML is checked against the
# spans the code emits before anything is compiled.
python3 scripts/check_span_selectors.py .
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo audit -D warnings
cargo deny check
echo "gate OK"
