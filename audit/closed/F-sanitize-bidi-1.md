# F-sanitize-bidi-1: sanitize() filters Unicode format/bidi chars, not just Cc
- Severity: low
- Status: Verified-Fixed
- Area: security

## Risk (T3: security + redteam RC-2)
`sanitize()` stripped `char::is_control()` (Cc: C0/C1 controls) but not Unicode
**Cf** format characters — bidi overrides (RLO U+202E), zero-width joiners, the BOM,
etc. A client/CP-supplied string rendered in a log field or on a terminal could
reorder or hide text (bidi spoofing).

## Resolution (Verified-Fixed)
`is_unsafe_display(c)` now filters, in addition to `is_control()`, the format/bidi
ranges: U+200B–U+200F, U+202A–U+202E, U+2060–U+2064, U+2066–U+206F, U+FEFF, U+061C,
U+180E (explicit ranges — no unicode-category crate dependency). `sanitize()`
filters on it and still bounds the length. Applied at every log/terminal sink for
untrusted strings (username, resolved identity, device-flow URL/code).

## Evidence
`ssh/handler.rs` (`is_unsafe_display`, `sanitize`) + the
`sanitize_strips_bidi_and_format_chars` unit test (RLO + ZWJ + BOM all stripped).
