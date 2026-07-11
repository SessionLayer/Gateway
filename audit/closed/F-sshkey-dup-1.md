# F-sshkey-dup-1: two ssh-key versions coexist (russh boundary vs our code)
- Severity: low
- Status: Accepted-Risk
- Area: dep

## Observation
Adding `russh` 0.62 pulls `ssh-key = 0.7.0-rc.11` (and RustCrypto `-rc` crates:
`signature 3.0-rc`, `p256 0.14-rc`, `sec1 0.8`, …). Our own code still uses the
stable `ssh-key 0.6`. Both versions are present in the graph.

## Why this is accepted (unavoidable + contained)
russh 0.62 hard-pins `ssh-key =0.7.0-rc.11`; we cannot use russh's `Handler` types
without it, and bumping our S3/S4 signing + mock-CA code onto an rc is a larger,
riskier change than isolating the boundary. The 0.7 types are used **only** at the
russh boundary (`ssh/mod.rs` host key, `ssh/handler.rs` fingerprint/cert-to-wire,
via `russh::keys`); everything else stays on 0.6. `cargo deny` (multiple-versions =
warn) and `cargo audit` both pass; no advisory affects the pulled crates. When
russh releases against a stable `ssh-key 0.7`, the workspace can consolidate.
