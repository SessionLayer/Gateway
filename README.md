# SessionLayer Gateway

The **SessionLayer Gateway** is the platform's Tier-0 data plane: it terminates
the outer SSH leg from stock OpenSSH clients, re-originates the inner leg to the
node, records the session, and enforces the capability set the Control Plane
returns. It is **the only component that sees SSH session plaintext** (Design
§1, §15).

What lives here:

- The outer SSH server (source-IP gate, PROXY protocol v2 fail-closed, the
  cert → pin → OTP → OIDC-device-flow auth ladder) and the inner SSH client
  (ephemeral session certificates — the private key is generated here and never
  leaves; host identity verified against the host CA or pinned keys, never
  TOFU).
- Per-channel capability/lock enforcement, the pushed lock-set with live
  teardown, and the asymmetric-degradation contract: allow may fail open,
  deny always fails closed.
- The recorder: asciicast v2 with keystrokes, SFTP/SCP decode (file names,
  sizes, hashes — never content capture), sealed to the customer's key
  (the platform cannot decrypt it) and uploaded to WORM storage.
- Connectivity: agentless dial and the outbound-Agent dial-back transport, plus
  HA — Postgres presence, NATS signaling (session bytes never touch the bus),
  and direct Gateway↔Gateway relay.
- Tier-0 self-hardening at startup: privilege drop after binding `:22`,
  seccomp, Landlock, coredumps off. Deployment assets: [`deploy/`](deploy/).

## Build & test

```bash
cargo build --release -p gateway   # Rust 1.95 (pinned) + protoc
cargo nextest run --all-features   # unit + integration tests (Docker for the E2Es)
./scripts/gate.sh                  # the full quality gate
```

## Contract

The CP↔Gateway gRPC contract and the Agent↔Gateway wire protocol are frozen
upstream in `ControlPlane-API/contracts/`; byte-identical copies are vendored
under [`proto/`](proto/) and code-generated in `build.rs`. Re-sync with
[`scripts/sync-contracts.sh`](scripts/sync-contracts.sh).

## Documentation

Operator and user documentation for the whole platform lives in the
[Documentation repository](https://github.com/SessionLayer/Documentation) —
installation, the hardened deployment profile, addressing modes, runbooks, and
the security model. Component-local references: [`RUNBOOK.md`](RUNBOOK.md) (log
reasons → actions) and [`docs/addressing.md`](docs/addressing.md).

## License

GPL-3.0-only. See [`LICENSE`](./LICENSE).
