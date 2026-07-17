# F-innerkey-zeroize-1: inner private key survives in un-zeroized transient copies (PEM round-trip + Arc move)
- Severity: low
- Status: Verified-Fixed
- Area: crypto

## S21 resolution (Verified-Fixed) — compensating control delivered
The S18 disposition was **Accepted-Risk pending the S18 Tier-0 memory hardening**
named below as the compensating control. **Session Twenty-One delivers it**, so the
finding closes as Verified-Fixed:
- The load-bearing scalar **is** scrubbed on drop — verified against the crate:
  `ssh-key` 0.6.7 **and** 0.7.0-rc.11 `EcdsaPrivateKey::drop` calls `self.bytes.zeroize()`.
  The `innerleg.rs` comment has been corrected to state this accurately (it had
  wrongly claimed no scrub).
- The residual (un-scrubbed `serde_json`/`ssh_key` encode-decode scratch + moved-from
  stack slot across the 0.6↔0.7 hand-off, [[F-sshkey-dup-1]]) is now covered by
  `hardening::coredump` (`PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0`, default-on), **proven**
  by `tests/hardening_e2e.rs` (`coredumps_disabled_rlimit_zero` +
  `forced_crash_produces_no_core_with_secret`). Swap remains an operational residual
  (disable/encrypt swap on sensitive fleets — RUNBOOK/`deploy/`); the coredump vector
  that made this finding actionable is closed. See [[F-coredump-1]].

## Summary (T3: security-reviewer — inner-key custody, Tier-0 zeroization)
Custody of the inner-leg private key is **provably correct at the trust boundary**:
`signing::build_request` transmits only `public_key_openssh_wire()`; the request
type has no private field; `request_carries_only_the_public_key_and_token` asserts
no private fragment leaks (D2/§15). The primary key holders also zeroize on drop:
`ssh_key`'s `EcdsaPrivateKey<32>::Drop` scrubs the P-256 scalar for both
`InnerKeyPair.private` (dropped at `drop(inner_kp)`) and the russh `PrivateKey`
(dropped at `drop(key)` once the auth future's `Arc` clone releases), and the
intermediate PEM is a `Zeroizing<String>`.

The DoD ("inner-key buffers zeroized") is nonetheless **imperfect**: the P-256
private scalar transits several un-scrubbed transient buffers in
`handler.rs::establish_inner` / `innerleg.rs::establish`:

1. **PEM encode** — `inner_kp.private_key_openssh_pem()` → `ssh_key` 0.6
   `to_openssh()` serializes the scalar into an internal `Vec<u8>` before base64;
   only the *returned* PEM is `Zeroizing`, not that encode scratch.
2. **PEM decode** — `PrivateKey::from_openssh(&pem)` (russh's `ssh_key` 0.7)
   decodes the base64 into an internal buffer holding the raw scalar; not zeroized.
3. **Arc move** — `let key = Arc::new(key)` moves the `PrivateKey`; a Rust move is a
   bitwise copy that does **not** run `Drop` on the source, leaving a copy of the
   scalar in the moved-from stack slot of `establish`.

Root cause is the deliberate cross-version PEM hand-off (`ssh_key` 0.6 in our code
vs 0.7 at the russh boundary, F-sshkey-dup-1, Accepted-Risk): the key is
re-serialized/parsed precisely to cross that boundary. Same residual class as
F-zeroize-1's accepted `serde_json` scratch.

Not remotely exploitable — these are process-local heap/stack bytes, reachable only
via a coredump / swap / a memory-disclosure primitive on the Tier-0 host. Fail-safe
direction throughout.

## Recommended disposition: Accepted-Risk
Genuinely-unfixable without forking `ssh_key` (to zeroize its encode/decode scratch)
or eliminating the cross-version round-trip (blocked by F-sshkey-dup-1 until russh
ships against a stable `ssh_key` 0.7). Compensating control is **S18 Tier-0 memory
hardening** (mlock / disable swap / suppress coredumps / `madvise(DONTDUMP)`), which
neutralizes residual in-memory key bytes platform-wide — the correct layer for this,
not per-buffer scrubbing of library internals.

If closing as Accepted-Risk, record the S18 hardening dependency and the
[[F-sshkey-dup-1]] / [[F-zeroize-1]] precedent, then move to `audit/closed/`.

## Partial hardening available now (optional, does not fully close)
Residual (3) can be shrunk by binding the key straight into the `Arc` at the
`from_openssh` call site (`let key = Arc::new(PrivateKey::from_openssh(&pem)?)`) so no
separately-owned stack `PrivateKey` is moved-from; (1)/(2) remain library-internal.

## Disposition (Accepted-Risk)
The inner private key is provably never transmitted or logged (D2, asserted by `request_carries_only_the_public_key_and_token`) and its primary holders zeroize on drop. The residual un-scrubbed bytes are `ssh_key` encode/decode **library internals** + a moved-from stack slot across the deliberate 0.6↔0.7 PEM hand-off ([[F-sshkey-dup-1]]) — not remotely reachable (coredump/swap only), fail-safe throughout. Compensating control = **S18 Tier-0 memory hardening** (mlock / disable swap / suppress coredumps / madvise(DONTDUMP)), the correct layer. Precedent: [[F-sshkey-dup-1]], [[F-zeroize-1]].
