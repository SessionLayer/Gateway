# F-ha-nats-hardening-1 (F1/F3/F7/F8/L3): NATS client — unbounded read, duplicate SUB, no liveness, silent misconfig
- Severity: medium
- Status: Verified-Fixed
- Area: ha-coordination

## Summary

The hand-rolled NATS client had several robustness gaps:
- **F1:** `read_control_line` buffered into a `String` until `\n`, checking the 8 KiB cap AFTER —
  an unterminated line could grow unboundedly. It also ran inside a `select!`, so a control-line
  read cancelled mid-line by an outbound command would desync the stream.
- **F3:** `ensure_subscribed` queued a `SUB` while the connect path also re-SUBbed from the map →
  a subject could be SUBbed twice on one connection → doubled MSG → double `serve_relay`.
- **F8:** a broker advertising `tls_required`/`auth_required` the plaintext client cannot meet was
  met with a silent reconnect loop, not a surfaced error.
- **F7/L3:** no client-side liveness (a black-holed TCP with no RST was never detected); the
  outbound command queue was unbounded (a partition could pile stale signals that flush on
  reconnect).

## Location

- `gateway-core/src/ha/nats.rs`

## Remediation — Verified-Fixed

- **F1:** `read_control_line` reads via `fill_buf`/`consume`, bounded to `MAX_CONTROL_LINE`
  (8 KiB) — errors at the cap. The socket read now lives in a dedicated reader task (not a
  `select!`), so a control line is never cancelled mid-read. Tests
  `an_unterminated_control_line_is_bounded`, `a_control_line_reads_and_trims_crlf`.
- **F3:** the connection manager is the SOLE SUB emitter, deduping by subject on the current
  connection (`subscribed` set); `ensure_subscribed` only mutates the map + sends a best-effort
  `Cmd::Sub`.
- **F8:** `info_requires_unsupported` parses the server INFO; a required TLS/auth capability is a
  FATAL error that STOPS the manager with a single loud log (no reconnect loop). Test
  `info_flags_tls_and_auth_requirements_as_fatal`.
- **F7/L3:** a client PING every `PING_INTERVAL` (20s) with a one-interval PONG deadline trips a
  reconnect on a black-holed connection; the command queue is a bounded `mpsc` (1024) with
  `try_send` (drop + fail closed at the bound), so a partition cannot pile stale signals.
