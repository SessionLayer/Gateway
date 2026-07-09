# F-ci-1: CI hardening — no job timeout, no concurrency cancel
- Severity: info
- Status: Verified-Fixed
- Area: ci

**Issue.** The `gate` job had no `timeout-minutes`, so a hung build could run
to GitHub's 6h default (CI-resource waste), and superseded runs on a ref were
not cancelled. (Not exploitable given `permissions: contents: read` and no
secrets.)

**Fix.** Added `timeout-minutes: 30` to the `gate` job and a top-level
`concurrency` group (`ci-${{ github.ref }}`, `cancel-in-progress: true`).
Tool installs (`taiki-e/install-action`, SHA-pinned) remain at latest; the
action verifies checksums — accepted as a defense-in-depth note.

**Verification.** Workflow YAML reviewed; the single required job id `gate`
is unchanged.
