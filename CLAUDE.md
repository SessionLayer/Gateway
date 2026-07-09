# CLAUDE.md — SessionLayer Gateway

Guidance for working in this repository. The Gateway is the platform's **Tier-0
data plane** and the **only component that sees SSH session plaintext** (Design
§1, §15). Correctness and defensibility beat cleverness and speed.

## Scope is per session

This repo is built session by session. **Session One is scaffolding + harness
only**: the async-I/O seam, the CP handshake client generated from the frozen
contract, a health/version surface, and the quality/CI/gate tooling. There is
**no SSH server/client, no PROXY protocol, no recorder, no NodeConnector, no
gRPC auth** yet. If you find yourself implementing an `FR-*` behavior, stop and
confirm it belongs to this session. Product behavior drops in behind the seams
established here.

Source of truth: `../Docs/01-Design.md` and `../Docs/02-Requirements.md`.

## Tier-0 caution (carry into every future change)

- The Gateway will hold **plaintext SSH bytes**. Zeroize plaintext buffers,
  never log or trace plaintext, keep it out of coredumps/swap, and ship audit
  off-box immediately (NFR-5). `#![forbid(unsafe_code)]` is set in `gateway-core`
  — keep it; justify loudly if it must ever be relaxed.
- The CP <-> Gateway plane is **plaintext localhost, dev-only, in Session One**.
  mTLS (channel auth + per-RPC session-bound authorization) arrives in Session
  Four. `rustls` is already a dependency (see `gateway_core::tls`) so its supply
  chain is audited from day one; the provider is installed and the channel built
  in S4. Never ship the plaintext path to production.
- Deny must fail closed. The `AsyncIo` fast-path selection is deny-safe: an
  unavailable io_uring reactor **degrades to epoll**, it never fails the Gateway.

## Runtime: tokio + tokio-uring hybrid, behind `AsyncIo`

`gateway_core::asyncio` defines the reactor-agnostic byte-I/O seam:

- **`EpollIo` (default, portable fallback).** The process runs on a
  multi-threaded **tokio** (epoll) runtime. The whole ecosystem the Gateway
  needs — russh (later), tonic, hyper — assumes a tokio reactor, so epoll is the
  base and the always-available fallback.
- **`UringIo` (opt-in, Linux, `io-uring` feature).** io_uring has lower syscall
  overhead on the hot byte-copy between the two SSH legs. It is selected via
  `select_io(IoBackend)` **only when actually available** (`UringIo::available()`
  == Linux && feature). A `Uring` request on a build/platform without it falls
  back to epoll.

Session One ships the trait + both backends + the selection logic, proven by
unit tests (`asyncio::tests`). No SSH bytes move yet; the copy methods land with
the SSH legs.

## Contract: vendoring, sync, and the N-1 policy

The CP <-> Gateway gRPC contract is **frozen** upstream in
`../ControlPlane-API/contracts/proto/`. **Do not edit the vendored proto to
change the contract.**

- The parent `SessionLayer/` folder is not a git repo and **CI checks out this
  repo alone**, so the proto is **vendored** (committed) under `proto/` and code
  is generated from the vendored copy by `gateway-core/build.rs`
  (`tonic-prost-build`, which shells out to `protoc`).
- Re-sync after a *versioned* contract change with `scripts/sync-contracts.sh`
  (no-op with a note when the source path is absent).
- **Versioning / N-1 (FR-HA-9, D33):** the CP <-> Gateway protocol is explicitly
  versioned (`ProtocolVersion{major,minor}`) and negotiated at connect
  (`Handshake.Negotiate`). The platform commits to an **N-1 window**: a component
  supports peers one minor back within a major line. Resolution is a pure,
  order-independent function (`version::resolve_common_version`); no common
  version **fails closed**. Session One baseline is **1.0** only. See
  `../ControlPlane-API/contracts/VERSIONING.md`.

## Conventions

- **Component name** `SessionLayer Gateway`; **SemVer** `0.1.0`; **protocol**
  `1.0` (`min = max = 1.0`).
- **CP gRPC** at `http://127.0.0.1:9090` (plaintext dev-only). **Ports** (dev,
  parent Makefile): CP REST `:8080`, CP gRPC `:9090`, Postgres `:5432`, NATS
  `:4222/:8222`, MinIO `:9000/:9001`, oidc-mock `:8090`, target-sshd `:2222`.
- Structured logging via `tracing` (`RUST_LOG`, default `info`). Never log
  plaintext.
- Edition 2021, toolchain pinned in `rust-toolchain.toml` (`1.95.0`).

## Gate & CI

`scripts/gate.sh` is the single source of truth (used by CI, `make gw-gate`, and
hooks). It runs:

```
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo audit -D warnings
cargo deny check
```

…then fails if any `audit/F-*.md` of severity **medium or higher** is still
`Open`.

- CI (`.github/workflows/ci.yml`) has **exactly one job id `gate`** (the required
  check — do not rename or add a matrix). All actions are pinned to full commit
  SHAs.
- Build first (`cargo fetch`, then `cargo build --all-features`) before
  clippy/nextest — 2 shared CPU cores make cold builds slow; use generous
  timeouts.

## audit / ROUND gate

- `audit/STATE` is `ROUND_DISCOVERY` during scaffolding/red-team, `ROUND_FINAL`
  only when the gate is clean. Do not go idle in `ROUND_FINAL` with a failing
  gate.
- Finding files `audit/F-<area>-<n>.md` use the exact front-matter documented in
  `audit/README.md`. **Move resolved/accepted findings into `audit/closed/`** —
  the user-scope idle hook counts medium+ severities outside `audit/closed/`
  regardless of status.

## Deferred decisions recorded here

- **russh is NOT a dependency yet.** The SSH legs are a later session; adding
  russh now would be product behavior outside Session One scope and would widen
  the audit surface for no benefit. Staged for the session that implements the
  outer/inner SSH legs.
