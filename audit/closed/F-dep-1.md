# F-dep-1: `rsa` Marvin timing side-channel (RUSTSEC-2023-0071) — uncompiled optional dep of `ssh-key`

- Severity: medium
- Status: Accepted-Risk
- Area: dep

## Summary

`cargo audit` flags **RUSTSEC-2023-0071** — the Marvin timing side-channel in the
`rsa` crate (0.9.10) — because `rsa` appears in `Cargo.lock`. It is pulled in only
as an **optional dependency of `ssh-key` 0.6.7** (added in Session Four for the
inner-leg OpenSSH keypair + certificate handling).

## Why this is Accepted-Risk (not exploitable in the Gateway)

The vulnerable `rsa` code is **never compiled into the Gateway**:

- The Gateway uses **ECDSA P-256 only** — the inner-leg session keypair and the
  mTLS X.509 identity are both P-256. `ssh-key` is enabled with
  `features = ["ecdsa", "p256", "std", "getrandom"]` and `default-features = false`;
  the `rsa` feature is never activated.
- `cargo tree -e features -i rsa` prints **"nothing to print"** — `rsa` is not in
  the compiled feature graph.
- `cargo build --all-features` **never compiles `rsa`** (nor `p384`/`p521`).
- `cargo deny check`, which is **feature-aware**, reports **"advisories ok"** — it
  does not consider `rsa` part of the graph.

`rsa` is present only in `Cargo.lock`'s optional-dependency **superset** (Cargo
records every possible dependency of `ssh-key`, activated or not). `cargo audit`
scans that raw lockfile and cannot tell the feature is off, so it reports a
false positive relative to what is actually built.

- **No fix is available:** the advisory states "No fixed upgrade is available!";
  there is no `rsa` release that resolves the timing side-channel, and no `ssh-key`
  release that drops the optional `rsa` dependency.

## Handling

- `cargo audit` is configured to ignore this single advisory in
  `.cargo/audit.toml`, with the same justification inline. `cargo deny` needs no
  change (it already excludes `rsa`).
- **No gate weakening beyond this one documented, genuinely-unfixable item.**

## Re-evaluation triggers

Revisit and remove the ignore if any of these change:
- `ssh-key` makes `rsa` a non-optional dependency, or the Gateway starts using
  RSA keys anywhere (it should not — the design is ECDSA-only for these paths).
- A fixed `rsa` release ships that resolves RUSTSEC-2023-0071.
