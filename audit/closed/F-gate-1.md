# F-gate-1: Merge gate's findings-parser fails open on malformed/missing front-matter
- Severity: medium
- Status: Verified-Fixed
- Area: gate

**Issue.** `scripts/gate.sh`'s findings loop was the sole enforcement of
"zero open medium+". Its severity/status extraction (`grep | sed | tr -cd`)
treated anything it could not parse as non-blocking, in BOTH directions: a
qualified severity (`Severity: critical, needs triage`), markdown emphasis
(`**Severity:** medium`), an indented header, `Status: Open (investigating)`,
or a **missing** `Status:` line all yielded a PASS. A genuinely-open medium+
finding with any formatting slip merged silently.

**Fix.** Rewrote the parser to extract the first bareword token after
`Severity:`/`Status:` (tolerant of leading whitespace and `**` emphasis,
case-insensitive) and to **fail closed**: a finding whose severity is not one
of `critical|high|medium|low|info` or whose status is not one of
`open|verified-fixed|accepted-risk` now blocks the gate (`bad` counter →
`exit 1`), as does any still-`Open` medium+.

**Verification.** Ran the new parser over nine adversarial fixtures: the five
genuinely-open medium+ cases (including qualified/emphasised/indented/`OPEN — WIP`)
all block; missing-status and unknown-severity files fail closed; a
`low`/`Open` and a `high`/`Verified-Fixed` correctly pass. `gate OK` on the
clean tree.
