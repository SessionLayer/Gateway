# F-gw-breakglass-secret-zeroize-1: break-glass offline code + token on non-zeroized heap
- Severity: medium
- Status: Accepted-Risk
- Area: breakglass

## Observation (security F3)
The break-glass offline code (`try_break_glass_code`'s `code: &str`, derived from the
keyboard-interactive `Zeroizing<String>` response) and the minted `breakglass_token`
(stored in `SshHandler.breakglass_token: Option<String>` and sent in `AuthorizeRequest`)
live on the regular heap for the auth window. The KI response itself is held in a
`Zeroizing` buffer (scrubbed on drop) and neither the code nor the token is ever logged,
but the `String` copies handed to the cpauth RPC and the stored token are not zeroized on
drop — a coredump/swap-window residual.

## Disposition (Accepted-Risk → S18)
This matches the EXISTING pre-S18 pattern across the Gateway: transient secret/plaintext
heap copies (recorder per-event JSON, inner private-key PEM) are a documented
coredump/swap-only residual tracked to the Session 18 zeroize pass
([[F-recorder-plaintext-zeroize]] / [[F-innerkey-zeroize]]). The break-glass secrets are
short-lived (single auth), single-use (consumed at the CP), and never logged. Carry the
break-glass code + token into the S18 blanket zeroize sweep (wrap in `Zeroizing`, scrub
the token on `SshHandler` drop). Not fixed in-session to keep the S18 zeroize work
consolidated and consistent.
