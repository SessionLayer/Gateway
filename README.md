# SessionLayer Gateway

The **SessionLayer Gateway** is the platform's Tier-0 data plane: it terminates
the outer SSH leg from stock OpenSSH clients, re-originates the inner leg to the
node, records the session, and enforces the capability set the Control Plane
returns. It is **the only component that sees SSH session plaintext** (Design
§1, §15).

> **Session One = scaffolding only.** This repository currently contains the
> load-bearing seams — nothing that terminates SSH yet. See
> [`CLAUDE.md`](./CLAUDE.md) for scope, architecture rationale, and conventions.

## Workspace

| Crate | Kind | Contents |
|---|---|---|
| `gateway-core` | lib | `AsyncIo` seam (epoll + io_uring), CP handshake client (generated from the frozen contract), version/health/config surface |
| `gateway` | bin | Daemon skeleton (`gateway`) + version-negotiation smoke (`handshake-smoke`) |

## Quick start

```bash
cargo build --all-features                 # warm the build first (slow)
cargo nextest run --all-features           # unit tests (no running CP needed)
./scripts/gate.sh                          # the full quality gate

cargo run -p gateway -- --version          # SemVer + supported protocol range
cargo run -p gateway -- health             # health/version JSON
cargo run -p gateway -- io-backend         # resolved async-I/O backend

# Version-negotiation smoke against a running CP (see the parent `make e2e-smoke`):
cargo run -p gateway --bin handshake-smoke -- --endpoint http://127.0.0.1:9090
```

## Contract

The CP <-> Gateway gRPC contract is **frozen** upstream in
`ControlPlane-API/contracts/proto/`. A committed copy is vendored under
[`proto/`](./proto) and code is generated from it in `build.rs`. Re-sync with
[`scripts/sync-contracts.sh`](./scripts/sync-contracts.sh). See `CLAUDE.md`.

## License

GPL-3.0-only. See [`LICENSE`](./LICENSE).
