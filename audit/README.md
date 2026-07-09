# Gateway audit ledger

Security/quality findings for the SessionLayer Gateway, filed during the
red-team pass and tracked to closure.

## Phase (`STATE`)

`audit/STATE` holds the current phase:

- `ROUND_DISCOVERY` — scaffolding + red-team discovery. Findings are filed here.
- `ROUND_FINAL` — final validation. The idle/CI gate enforces a clean Rust gate
  (`scripts/gate.sh`) and **zero open medium+ findings**. Do not enter this
  phase with a failing gate.

## Finding files

One file per finding, `audit/F-<area>-<n>.md`, with EXACT front-matter (a grep
in `scripts/gate.sh` and the idle hook depends on it):

```
# F-<area>-<n>: <title>
- Severity: critical|high|medium|low|info
- Status: Open|Verified-Fixed|Accepted-Risk
- Area: <area>
```

## Closing findings

When a finding is resolved (`Verified-Fixed`) or accepted (`Accepted-Risk`),
**move its file into `audit/closed/`**. Two gates read this directory:

- `scripts/gate.sh` scans only top-level `audit/F-*.md` and blocks on any
  medium+ that is still `Open`.
- The user-scope idle hook greps `audit/` for medium+ `Severity` lines,
  excluding `audit/closed/`, regardless of `Status`.

Keeping resolved findings under `audit/closed/` satisfies both.
