# F-log-1: Terminal-escape / log injection via unsanitized server-controlled strings
- Severity: low
- Status: Verified-Fixed
- Area: log

**Issue.** `ComponentInfo.name`/`semver` are fully peer-controlled and, in
Session One, arrive over an unauthenticated plaintext channel (any local
process that binds/MITMs 127.0.0.1:9090). `handshake-smoke` printed them raw,
so a hostile "CP" could embed ANSI/control sequences to manipulate the
operator's terminal or forge log lines. (Both auditors flagged this;
F-smoke-1 is folded in here.)

**Fix.** Added `sanitize_diagnostic()` in `handshake.rs` — drops control
characters and caps length to 128 — applied at the source when constructing
`Negotiated`, so every consumer (the smoke print and any future `tracing`)
gets safe values.

**Verification.** Unit test `interpret_sanitizes_hostile_diagnostic_strings`
feeds `\x1b[2J`, newline, DEL, and a C1 byte and asserts the resulting
strings contain no control characters.
