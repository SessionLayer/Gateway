# F-zeroize-1: private key lingered in un-zeroized transient heap buffers in the identity store

- Severity: low
- Status: Verified-Fixed
- Area: identity

## Summary

`gateway-core/src/identity.rs` zeroized the adopted in-memory key
(`ClientIdentity.key_pem`, `KeypairCsr.key_pem`, `IssuedCredential.key_pem` are
all `Zeroizing`), but the persist/load path materialised the private key in
**plain, un-zeroized transient heap buffers**:

- `persist_issued` built the manifest with `issued.key_pem.to_string()` — a plain
  `String` copy of the key — and serialized it into a `serde_json` `Vec<u8>`.
- `load` read the on-disk manifest into a plain `Vec<u8>` (`std::fs::read`) that
  contains the key, and never scrubbed it.
- `CredentialManifest` derived `Debug` while holding the key (latent
  secret-in-log risk if ever formatted) and `Clone`.

A Tier-0 zeroization-consistency gap (CLAUDE.md): key material should be scrubbed
from every heap copy on drop.

## Fix

- `CredentialManifest.key_pem` is now `Zeroizing<String>` via a `#[serde(with =
  "zeroizing_pem")]` adapter, so the persisted-key field is scrubbed on drop and
  the key flows **issued → manifest → Credential entirely as one `Zeroizing`
  buffer** — no plain-`String` copy is ever materialised (the `.to_string()` is
  gone; the field is moved through).
- `persist_issued` zeroizes the serialized `json` buffer after the durable write.
- `load` zeroizes the file-read `bytes` buffer after parsing.
- `CredentialManifest` no longer derives `Debug`/`Clone` (it can no longer be
  formatted into a log, nor cheaply duplicated).

## Completeness (GW-ZEROIZE, T4 re-verify)

The three cited sites are all covered:

1. `load()` file-read `bytes` buffer → `bytes.zeroize()` after parse.
2. `from_manifest` early-`Err` (ca-chain parse) path → `key_pem` is a
   `Zeroizing<String>` field, so the manifest's key is scrubbed on drop even when
   the function returns before moving it out.
3. `persist_issued` → the key is **moved** (never `.to_string()`-copied) from
   `issued → manifest → Credential` as one `Zeroizing` buffer; the serialized
   `serde_json` buffer is `zeroize()`d after the durable write.

`CredentialManifest` is not `#[derive(Zeroize, ZeroizeOnDrop)]` because that impls
`Drop`, which would forbid the partial move of `key_pem` into `Credential`; the
`Zeroizing` field achieves the same scrub-on-drop guarantee while keeping the
move-through (zero-copy) path.

## Verification

- `cargo build` + the full identity unit/integration suite green (persist/load
  roundtrip, simulated-crash recovery, generation increment, single-writer lock,
  0600 perms, renew-ahead loop). Full `scripts/gate.sh` → `gate OK`.
- Residual (accepted): `serde_json`'s internal scratch allocations during
  (de)serialization are not individually zeroizable; the addressable owned
  buffers (manifest field, serialized `Vec`, file-read `Vec`) all are.
