#!/usr/bin/env bash
set -euo pipefail; cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo audit -D warnings
cargo deny check
# Findings gate — NO-DEFER (Session 3 §7). Blocks on ANY finding whose Status is
# Open, of ANY severity (critical|high|medium|low|info), AND fails on any finding
# whose Status is Deferred — the no-defer rule bans kicking work down the road.
# Verified-Fixed and Accepted-Risk are the only allowed statuses. Parse
# FAIL-CLOSED: any unparseable/unknown Status blocks the gate. Resolved findings
# live under audit/closed/ and are not scanned here.
open=0; deferred=0; bad=0
shopt -s nullglob
for f in audit/F-*.md; do
  st=$(grep -iE '^- *Status:' "$f" | head -1 | sed -E 's/.*Status:[[:space:]]*//I' | tr 'A-Z' 'a-z' | tr -cd 'a-z-')
  case "$st" in
    verified-fixed|accepted-risk) : ;;
    open) echo "OPEN finding: $f"; open=$((open+1)) ;;
    deferred) echo "DEFERRED finding (banned by the no-defer gate): $f"; deferred=$((deferred+1)) ;;
    *) echo "UNPARSEABLE/unknown status ('$st'): $f"; bad=$((bad+1)) ;;
  esac
done
total=$((open + deferred + bad))
if [ "$total" -gt 0 ]; then
  echo "findings gate FAILED: $open open, $deferred deferred, $bad unparseable"; exit 1
fi
echo "gate OK"
