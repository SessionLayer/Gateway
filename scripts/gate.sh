#!/usr/bin/env bash
set -euo pipefail; cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo audit -D warnings
cargo deny check
# Findings gate. Blocks if any medium+ finding is still Open, and FAILS CLOSED on
# any finding file whose Severity/Status front-matter cannot be parsed — a
# misformatted, qualified, or missing header must not slip through (F-gate-1).
# Resolved findings live under audit/closed/ and are not scanned here.
open=0; bad=0; shopt -s nullglob
# Extract the first bareword token after "<field>:", tolerant of leading
# whitespace and markdown emphasis, case-insensitive; empty if absent.
extract() {
  local field="$1" file="$2"
  { grep -ioE "^[[:space:]]*-[[:space:]]*\**${field}\**:[[:space:]]*\**[[:space:]]*[a-zA-Z-]+" "$file" || true; } \
    | head -1 | { grep -ioE '[a-zA-Z-]+$' || true; } | tr 'A-Z' 'a-z'
}
for f in audit/F-*.md; do
  sev=$(extract Severity "$f")
  st=$(extract Status "$f")
  case "$sev" in
    critical|high|medium|low|info) ;;
    *) echo "UNPARSEABLE Severity: $f"; bad=$((bad+1)); continue ;;
  esac
  case "$st" in
    open|verified-fixed|accepted-risk) ;;
    *) echo "UNPARSEABLE Status: $f"; bad=$((bad+1)); continue ;;
  esac
  case "$sev" in
    critical|high|medium) [ "$st" = open ] && { echo "OPEN $sev: $f"; open=$((open+1)); } ;;
  esac
done
if [ "$open" -gt 0 ] || [ "$bad" -gt 0 ]; then
  echo "findings gate FAILED: $open open medium+, $bad unparseable"; exit 1
fi
echo "gate OK"
