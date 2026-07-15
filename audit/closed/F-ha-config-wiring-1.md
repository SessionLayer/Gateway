# F-ha-config-wiring-1: the daemon could not be configured — run() hardcoded GatewayConfig::default()
- Severity: high (functional — HA mode / NATS / non-default ports unreachable in the shipped binary)
- Status: Verified-Fixed
- Area: config / daemon

## Summary

`fn run()` (the daemon entrypoint) built its config with `GatewayConfig::default()`, and the CLI had
no `--config` flag. The JSON config loader (`GatewayConfig::load` / `load_from_path`, `SL_GATEWAY_CONFIG`
env — added with the HA config work) existed but was **never connected to the binary**. So the shipped
`gateway` binary always ran the built-in default: it could not be put into HA mode, pointed at NATS,
given a bootstrap credential, or bound to non-default ports.

Masked because the per-repo integration tests drive `ssh::bind` with a programmatically-constructed
`GatewayConfig` (never the binary's config path), and the unit tests exercise `load_from_path`
directly — so nothing exercised `run()`'s config source. Surfaced only when the cross-repo
`ha-e2e.sh` (Part H) first needed to launch two differently-configured real binaries — the same
double-masking class as `F-ha-session-uuid-1`, and exactly what the two-real-binary E2E exists to
catch.

## Location

- `gateway/src/main.rs` — `Cli`, `main()`, `fn run()`.

## Remediation — Verified-Fixed

Added a global `--config <PATH>` arg; `run()` now loads via `GatewayConfig::load(config_path)` with
explicit-`--config` → `$SL_GATEWAY_CONFIG` → built-in-default precedence, fail-closed on a
named-but-unreadable/unparseable file. Committed `48f5908`.

Verified against the real release binary: `gateway --help` lists `--config`; `gateway --config
ha-e2e-gw-a.json` parses every field (`deny_unknown_fields` satisfied), applies HA mode, and drives
into enrollment (failing only on the placeholder CA path). Then proven end-to-end in `ha-e2e.sh`:
gw-A and gw-B both launched via `--config` and stood up in HA mode (serverAuth cert + agent transport
+ peer relay + outer SSH leg), relaying a real session across the two gateways.
