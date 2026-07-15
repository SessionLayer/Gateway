# F-ha-nats-realserver-1 (F2): the hand-rolled NATS client was only proven against InProcess
- Severity: medium (IMPORTANT — test coverage of a bespoke codec)
- Status: Verified-Fixed
- Area: ha-coordination

## Summary

The coordination routing seam was proven only with `InProcessBackend`; the hand-rolled NATS core
client (INFO/CONNECT/SUB/PUB/MSG/PING-PONG parse) had no end-to-end test against a real broker, so
a codec regression could ship green.

## Location

- `gateway-core/src/ha/nats.rs`, `gateway-core/tests/nats_it.rs`

## Remediation — Verified-Fixed

Added a Testcontainers integration test (`nats_it.rs`) driving the real `NatsBackend` against
`nats:2.10-alpine`: one backend subscribes, another publishes, and the decoded `DialBackSignal`
is asserted to arrive verbatim over the hand-rolled MSG parse; a second delayed publish + a
`is_connected()` assertion prove the PING/PONG keepalive keeps the connection healthy. The parse
classification (PING/PONG/MSG/-ERR) is additionally unit-tested (`control_lines_are_classified`).
The test is a plain `tests/` integration test, so `cargo nextest run --all-features` executes it in
the gate (count > 0, not silent-skipped).
