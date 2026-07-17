# F-supplychain-repro-1: reproducibility gate proved same-runner, not independent
- Severity: medium
- Status: Verified-Fixed
- Area: supplychain

## Summary
RUSTFLAGS only remapped the workspace, so cargo-registry paths leaked into
panic-location .rodata (the gateway binary is unstripped) — an independent
off-runner rebuilder would get a different digest.

## Fix
RUSTFLAGS now remaps the cargo registry too (workspace remap already covers the
vendored third_party/russh). `[profile] trim-paths` is unstable in Cargo 1.95.0.
Residual: std sysroot path (toolchain + protoc pinned as documented preconditions).
Also: SBOM byte-stability (strip timestamp+serialNumber); job timeout + concurrency.
(T3 reliability F2/F7/F8.)
