# F-proxyjump-dos-1: Unbounded ProxyJump direct-tcpip resources (channels / cert cache / host-CA mint)
- Severity: medium
- Status: Verified-Fixed
- Area: proxyjump

## Finding

Session 16 T3 review (both `security-reviewer` and `redteam-auditor`, independently).
The ProxyJump `direct-tcpip` path (`ssh/handler.rs::channel_open_direct_tcpip` →
`ssh/proxyjump.rs::serve_inner_hop`) had **no resource bounds**:

1. `channel_open_direct_tcpip` accepted + `tokio::spawn`ed an inner russh server (+ a
   login-grace watchdog) for every open, WITHOUT the per-connection channel cap that
   `channel_open_session` enforces (`channels_opened` vs
   `inner.max_channels_per_connection`).
2. The per-principal host-cert cache (`ProxyJumpState::certs`, a `HashMap` keyed on the
   fully client-controlled `direct-tcpip` `host_to_connect`) had no size bound / no
   eviction — unbounded process-global growth.
3. The host-cert fetch (`cert_for` → CP `SignGatewayHostCertificate`) mints a host-CA
   cert (+ an audit row) **before** the inner-hop authorization, so a valid outer-leg
   credential with **zero node grants** suffices.

Chained: an authenticated jump connection (feature is opt-in, `ssh.proxy_jump.enabled`,
OFF by default) could script `direct-tcpip` opens to many fake hostnames → Gateway
(Tier-0) memory growth + CP host-CA signing/audit flooding + task/fd pressure, with no
node authorization. Severity reconciled to **medium** (redteam LOW — opt-in + valid
credential required + no integrity/confidentiality impact; security HIGH — OOM/flood).

**Explicitly NOT fixed by gating the mint on node existence** (redteam): the host cert
must mint for ANY principal — refusing unknown principals would reintroduce a node
existence oracle on the cert path (§7.1 regression). The mint-anything behaviour is
deliberate; only the resource bound is the defect.

## Fix (Verified-Fixed)

- **F1a** `ssh/handler.rs::channel_open_direct_tcpip`: increment `channels_opened` and
  refuse over `inner.max_channels_per_connection` before accept/spawn (shared counter
  with `channel_open_session`). This bounds inner-server spawns AND the host-CA mint
  rate to `max_connections × max_channels_per_connection` (× the source-IP gate + outer
  auth requirement) — a finite bound, covering the mint-flood (F1c) too.
- **F1b** `ssh/proxyjump.rs::cert_for`: bound the cache at `MAX_CACHED_HOST_CERTS` (256)
  — evict expired entries first, then the soonest-to-expire before inserting.
- The rest of the path was confirmed sound by both reviewers (outer host-key custody +
  zeroization, Debug-redacted key, no lock-across-await, fail-closed on missing cert /
  no TOFU, CpError renders only the gRPC code, no unwrap/panic on hostile input).

## Retest notes (redteam, post-fix — both bounded/low, no further action)

- F1a caps CONCURRENCY, not lifetime mint count: one connection can serially
  open→mint→close→reopen to mint fresh principals. Fine — F1b bounds memory and the
  signing rate is throttled by how fast a channel can cycle; do not expect F1a alone
  to bound total distinct mints.
- Cache-thrash: an attacker minting >256 distinct principals evicts
  legitimately-cached node certs (soonest-to-expire eviction), forcing re-mints for
  real traffic. Bounded and low (a re-mint still fails closed on CP failure); a mild
  amplification, noted.

## Residual (Accepted, with controls)

A Tier-0 Gateway can still request a host cert for an arbitrary (well-formed) principal
— this is intentional (consensual-MITM anchor; the cert is useless to anyone but a
client that installed the matching `@cert-authority` line, and is bound to the
Gateway's own host key). Bounded by F1a. Defence-in-depth follow-up: the CP
`GatewayHostCertificateService.validatePrincipals` could tighten its charset to an
allowlist (currently rejects control chars) for audit hygiene — not exploitable
(OpenSSH exact-matches principals; the principal never reaches the cert key_id).
