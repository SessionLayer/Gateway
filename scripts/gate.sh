#!/usr/bin/env bash
set -euo pipefail; cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo audit -D warnings
cargo deny check
open=0; shopt -s nullglob
for f in audit/F-*.md; do
  sev=$(grep -iE '^- *Severity:' "$f"|head -1|sed -E 's/.*Severity:[[:space:]]*//I'|tr 'A-Z' 'a-z'|tr -cd 'a-z')
  st=$(grep -iE '^- *Status:' "$f"|head -1|sed -E 's/.*Status:[[:space:]]*//I'|tr 'A-Z' 'a-z'|tr -cd 'a-z-')
  case "$sev" in critical|high|medium) [ "$st" = open ] && { echo "OPEN $sev: $f"; open=$((open+1)); };; esac
done
[ "$open" -gt 0 ] && { echo "$open open medium+ finding(s)"; exit 1; }; echo "gate OK"
