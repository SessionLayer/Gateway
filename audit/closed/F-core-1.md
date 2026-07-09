# F-core-1: forbid(unsafe_code) not enforced repo-wide (binary crate omitted it)
- Severity: low
- Status: Verified-Fixed
- Area: core

**Issue.** `#![forbid(unsafe_code)]` was set only in `gateway-core/src/lib.rs`.
The `gateway` binary crate — which becomes the daemon owning listeners and
(later) plaintext buffers — could add `unsafe` with no tripwire, contradicting
the Tier-0 invariant in CLAUDE.md. (F-safe-1 folded in.)

**Fix.** Moved the invariant to a `[workspace.lints.rust] unsafe_code =
"forbid"` table in the root `Cargo.toml`, opted every crate in via
`[lints] workspace = true`, and dropped the now-redundant crate attribute.
All three crates (lib + both binaries) now forbid first-party `unsafe`
uniformly; `forbid` cannot be locally overridden.

**Verification.** `cargo build --all-features` + full gate green with the
workspace lints active.
