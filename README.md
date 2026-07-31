# SessionLayer Gateway

The platform's Tier-0 data plane: it terminates the outer SSH leg from stock
OpenSSH clients, re-originates the inner leg to the node, records the session,
and enforces the capability set the Control Plane returns. It is the only
component that sees SSH session plaintext.

The outer leg authenticates through a cert, pin, OTP, or OIDC device-flow
ladder; the inner leg verifies the node's host identity against the host CA or
a pinned key, never TOFU. A pushed lock feed can end a session mid-flight: a
deny always fails closed, an allow may fail open. The recorder seals an
asciicast v2 recording to the customer's key, so the platform cannot decrypt
its own recordings.

## Build and test

```bash
cargo build --release -p gateway   # Rust 1.95 (pinned) + protoc
cargo nextest run --all-features   # unit + integration tests (Docker for the E2Es)
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings
cargo audit -D warnings && cargo deny check
```

## Documentation

Installation, the hardened deployment profile, addressing modes, and the
security model live in the
[Documentation repository](https://github.com/SessionLayer/Documentation).
The vendored gRPC contract and its sync workflow are described in
`scripts/vendor-contracts.sh`; deployment assets are under [`deploy/`](deploy/).

## License

GPL-3.0-only. See [`LICENSE`](./LICENSE).
