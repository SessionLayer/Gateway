//! The SLGW1 relay token (Session Fifteen; `gateway-relay-v1.md` §6, FR-HA-8): a
//! **single-use, ingress-signed capability** for exactly one direct Gateway↔Gateway relay.
//!
//! ```text
//! SLGW1.<base64url(payload)>.<base64url(signature)>          (no padding)
//! ```
//!
//! ECDSA P-256 / SHA-256 over `DOMAIN || payload_bytes`. The signing key is generated
//! **per process**, held in memory, never persisted: a token minted by a previous boot or
//! a different Gateway does not verify here. Verification is **verify-then-decode** (the
//! signature is checked over the exact transmitted bytes before they are parsed as
//! protobuf), mirroring the SLDB1 dial-back token. It is minted AND verified by the same
//! ingress Gateway; the owner merely presents it on the relay connection.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::pbgw::RelayTokenPayload;
use crate::ssh::connector::ByteStream;

/// Envelope prefix. A token that does not start with this is refused unparsed.
const ENVELOPE: &str = "SLGW1";

/// Domain separation for the signature (`gateway-relay-v1.md` §6 — note the NUL).
const DOMAIN: &[u8] = b"sessionlayer-gw-relay-v1\0";

/// The per-session bindings a relay is tied to (all required; a mismatch fails closed).
/// Held in the pending ledger at mint and compared against the presented token's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayBinding {
    /// The target node id (the CP node identifier the session authorized against).
    pub node_id: String,
    /// The node's enrollment name (the join key the owner matches its registry against).
    pub node_name: String,
    /// The ingress Gateway session this relay serves.
    pub session_id: String,
    /// The owner Gateway NAME the token is addressed to — MUST equal the authenticated
    /// mTLS peer id on the relay connection.
    pub owner_gateway_id: String,
    /// The resolved Linux principal (audit correlation).
    pub principal: String,
    /// The presence nonce the ingress saw at decision time (the anti-stale-ownership
    /// fencing token — a superseded owner carries a lower nonce and cannot serve).
    pub owner_nonce: u64,
}

/// A relay-token rejection. Reported to the peer as a single coarse `RELAY_REJECT` code
/// (non-disclosure); the specific reason is operator-log only.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayTokenError {
    /// The envelope is not `SLGW1.<b64url>.<b64url>`.
    #[error("malformed relay token envelope")]
    Envelope,
    /// The ECDSA signature did not verify under this process's signing key.
    #[error("relay token signature did not verify")]
    BadSignature,
    /// The signed bytes did not decode as a `RelayTokenPayload`.
    #[error("relay token payload did not decode")]
    Decode,
    /// The token carries another Gateway process's signer fingerprint.
    #[error("relay token was minted by a different signing key")]
    ForeignSigner,
    /// The token names a different ingress than this one.
    #[error("relay token is bound to a different ingress gateway")]
    WrongIngress,
    /// Past `exp_epoch_ms`.
    #[error("relay token is expired")]
    Expired,
    /// The `jti` is not in the pending ledger: unknown, already consumed (replay), or
    /// abandoned when its session gave up.
    #[error("relay token is not pending (replayed, unknown, or abandoned)")]
    NotPending,
    /// The presented token's bindings do not equal the pending entry's.
    #[error("relay token bindings do not match the pending relay")]
    BindingMismatch,
    /// The authenticated mTLS peer is not the owner the token names.
    #[error("relay token was issued for a different owner gateway")]
    WrongOwner,
}

/// The per-process relay signing key. Never persisted; a token from a previous boot is
/// unverifiable by construction.
pub struct RelaySigner {
    key: SigningKey,
    /// Hex SHA-256 of the signing key's SPKI (the `signer_fingerprint` payload field).
    fingerprint: String,
}

impl std::fmt::Debug for RelaySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelaySigner")
            .field("key", &"<redacted>")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl RelaySigner {
    /// Generate this process's relay signing key.
    pub fn generate() -> Self {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let spki = p256::PublicKey::from(VerifyingKey::from(&key))
            .to_public_key_der()
            .expect("a P-256 public key always encodes as SPKI DER");
        let fingerprint = hex(&Sha256::digest(spki.as_bytes()));
        Self { key, fingerprint }
    }

    /// Hex SHA-256 of the signing key's SPKI (DER) — the value carried in the payload.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Mint a token for one relay, returning `(jti, token)`. `ingress_gateway_id` is this
    /// Gateway's NAME. The token is NEVER logged, persisted, or echoed.
    pub fn mint(
        &self,
        ingress_gateway_id: &str,
        binding: &RelayBinding,
        ttl_ms: i64,
        now_ms: i64,
    ) -> (String, String) {
        let jti = random_jti();
        let payload = RelayTokenPayload {
            jti: jti.clone(),
            node_id: binding.node_id.clone(),
            node_name: binding.node_name.clone(),
            session_id: binding.session_id.clone(),
            ingress_gateway_id: ingress_gateway_id.to_string(),
            owner_gateway_id: binding.owner_gateway_id.clone(),
            principal: binding.principal.clone(),
            owner_nonce: binding.owner_nonce,
            exp_epoch_ms: now_ms.saturating_add(ttl_ms),
            signer_fingerprint: self.fingerprint.clone(),
        };
        let bytes = payload.encode_to_vec();
        let sig: Signature = self.key.sign(&signing_input(&bytes));
        let token = format!(
            "{ENVELOPE}.{}.{}",
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes())
        );
        (jti, token)
    }

    /// Verify a presented token's envelope, signature, signer, ingress binding and validity
    /// window (verify-then-decode) and return the decoded payload. `ingress_gateway_id` is
    /// this Gateway's own NAME.
    pub fn verify(
        &self,
        token: &str,
        ingress_gateway_id: &str,
        now_ms: i64,
    ) -> Result<RelayTokenPayload, RelayTokenError> {
        let mut parts = token.split('.');
        let (Some(ENVELOPE), Some(payload_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(RelayTokenError::Envelope);
        };
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| RelayTokenError::Envelope)?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| RelayTokenError::Envelope)?;

        let sig = Signature::from_der(&sig_bytes).map_err(|_| RelayTokenError::BadSignature)?;
        VerifyingKey::from(&self.key)
            .verify(&signing_input(&payload_bytes), &sig)
            .map_err(|_| RelayTokenError::BadSignature)?;

        let payload = RelayTokenPayload::decode(payload_bytes.as_ref())
            .map_err(|_| RelayTokenError::Decode)?;

        if payload.signer_fingerprint != self.fingerprint {
            return Err(RelayTokenError::ForeignSigner);
        }
        if payload.ingress_gateway_id != ingress_gateway_id {
            return Err(RelayTokenError::WrongIngress);
        }
        if now_ms >= payload.exp_epoch_ms {
            return Err(RelayTokenError::Expired);
        }
        Ok(payload)
    }
}

/// `DOMAIN || payload_bytes` — the exact bytes signed and verified.
fn signing_input(payload_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN.len() + payload_bytes.len());
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(payload_bytes);
    msg
}

fn random_jti() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A relay the ingress has signalled and is waiting for. Its presence in the ledger IS
/// the token's single-use right: **removal is consumption**.
struct PendingRelay {
    binding: RelayBinding,
    expires_at_ms: i64,
    ready: oneshot::Sender<Box<dyn ByteStream>>,
}

/// Default cap on outstanding relays (R5): signalled-but-never-redeemed entries would otherwise
/// grow memory. Sized like the agent transport's default connection cap.
const DEFAULT_MAX_PENDING: usize = 4096;

/// The in-memory single-use ledger for issued relay tokens (keyed by `jti`). Only the jti +
/// bindings are held — never token material — so a replay finds nothing and is refused. Bounded
/// (R5): at the cap, [`Self::insert`] fails closed so an unbounded signal rate cannot exhaust
/// memory.
pub struct PendingRelays {
    inner: Mutex<HashMap<String, PendingRelay>>,
    max_pending: usize,
}

impl Default for PendingRelays {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PENDING)
    }
}

/// Recover a poisoned lock rather than propagate a panic — this Tier-0 relay ledger's critical
/// sections run no user code, so the guarded state is always consistent (never wedge relays
/// because an unrelated task panicked).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl PendingRelays {
    /// A ledger bounded to `max_pending` outstanding relays.
    pub fn new(max_pending: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_pending,
        }
    }

    /// Register a pending relay at mint time. Returns `false` when the ledger is at capacity
    /// (fail closed — the caller must not publish a signal it cannot honour).
    #[must_use]
    pub fn insert(
        &self,
        jti: String,
        binding: RelayBinding,
        expires_at_ms: i64,
        ready: oneshot::Sender<Box<dyn ByteStream>>,
    ) -> bool {
        let mut inner = lock(&self.inner);
        if inner.len() >= self.max_pending {
            return false;
        }
        inner.insert(
            jti,
            PendingRelay {
                binding,
                expires_at_ms,
                ready,
            },
        );
        true
    }

    /// **Consume** a pending relay (removal is consumption — a replay of the same `jti`
    /// finds nothing). Returns the sender to hand the accepted relay stream to, only if
    /// every binding matches the presented payload.
    pub fn consume(
        &self,
        payload: &RelayTokenPayload,
    ) -> Result<oneshot::Sender<Box<dyn ByteStream>>, RelayTokenError> {
        let mut inner = lock(&self.inner);
        let entry = inner
            .remove(&payload.jti)
            .ok_or(RelayTokenError::NotPending)?;
        let presented = RelayBinding {
            node_id: payload.node_id.clone(),
            node_name: payload.node_name.clone(),
            session_id: payload.session_id.clone(),
            owner_gateway_id: payload.owner_gateway_id.clone(),
            principal: payload.principal.clone(),
            owner_nonce: payload.owner_nonce,
        };
        // The jti is consumed either way: a mismatched presentation burns the token rather
        // than leaving it redeemable for a second attempt.
        if presented != entry.binding {
            return Err(RelayTokenError::BindingMismatch);
        }
        Ok(entry.ready)
    }

    /// Abandon a pending relay by `jti` (the relay deadline elapsed): the token stops being
    /// redeemable at once, and dropping the sender wakes the waiting connector.
    pub fn abandon(&self, jti: &str) {
        lock(&self.inner).remove(jti);
    }

    /// Drop entries past their expiry (a signalled owner that never dialled back).
    pub fn gc(&self, now_ms: i64) {
        self.inner
            .lock()
            .unwrap()
            .retain(|_, e| e.expires_at_ms > now_ms);
    }

    /// How many relays are outstanding (tests/metrics).
    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }

    /// Whether no relay is outstanding.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Current Unix time in milliseconds (the clock the token window is judged by).
pub fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INGRESS: &str = "gw-A";
    const NOW: i64 = 1_700_000_000_000;
    const TTL: i64 = 30_000;

    fn binding() -> RelayBinding {
        RelayBinding {
            node_id: "node-uuid".into(),
            node_name: "node-a".into(),
            session_id: "sess-1".into(),
            owner_gateway_id: "gw-B".into(),
            principal: "deploy".into(),
            owner_nonce: 7,
        }
    }

    #[test]
    fn valid_token_verifies_and_carries_every_binding() {
        let signer = RelaySigner::generate();
        let (jti, token) = signer.mint(INGRESS, &binding(), TTL, NOW);
        let payload = signer.verify(&token, INGRESS, NOW).unwrap();
        assert_eq!(payload.jti, jti);
        assert_eq!(payload.node_id, "node-uuid");
        assert_eq!(payload.node_name, "node-a");
        assert_eq!(payload.session_id, "sess-1");
        assert_eq!(payload.owner_gateway_id, "gw-B");
        assert_eq!(payload.owner_nonce, 7);
        assert_eq!(payload.ingress_gateway_id, INGRESS);
        assert_eq!(payload.signer_fingerprint, signer.fingerprint());
        assert!(token.starts_with("SLGW1."));
    }

    #[test]
    fn a_token_from_another_gateway_process_never_verifies() {
        let ours = RelaySigner::generate();
        let theirs = RelaySigner::generate();
        let (_, token) = theirs.mint(INGRESS, &binding(), TTL, NOW);
        assert_eq!(
            ours.verify(&token, INGRESS, NOW),
            Err(RelayTokenError::BadSignature)
        );
    }

    #[test]
    fn tampered_payload_fails_the_signature() {
        let signer = RelaySigner::generate();
        let (_, token) = signer.mint(INGRESS, &binding(), TTL, NOW);
        let mut parts = token.split('.');
        let (_, payload_b64, sig_b64) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let mut payload =
            RelayTokenPayload::decode(URL_SAFE_NO_PAD.decode(payload_b64).unwrap().as_ref())
                .unwrap();
        payload.owner_nonce = 999; // try to lift the fencing nonce
        let forged = format!(
            "SLGW1.{}.{sig_b64}",
            URL_SAFE_NO_PAD.encode(payload.encode_to_vec())
        );
        assert_eq!(
            signer.verify(&forged, INGRESS, NOW),
            Err(RelayTokenError::BadSignature)
        );
    }

    #[test]
    fn wrong_ingress_and_expiry_are_refused() {
        let signer = RelaySigner::generate();
        let (_, token) = signer.mint(INGRESS, &binding(), TTL, NOW);
        assert_eq!(
            signer.verify(&token, "gw-other", NOW),
            Err(RelayTokenError::WrongIngress)
        );
        assert!(signer.verify(&token, INGRESS, NOW + TTL - 1).is_ok());
        assert_eq!(
            signer.verify(&token, INGRESS, NOW + TTL),
            Err(RelayTokenError::Expired)
        );
    }

    #[test]
    fn malformed_envelopes_are_refused_before_any_decode() {
        let signer = RelaySigner::generate();
        let (_, token) = signer.mint(INGRESS, &binding(), TTL, NOW);
        let body = token.strip_prefix("SLGW1.").unwrap();
        for bad in [
            "".to_string(),
            "SLGW1".to_string(),
            format!("SLGW2.{body}"),
            format!("SLGW1.{body}.extra"),
            "SLGW1.!!!.@@@".to_string(),
            body.to_string(),
        ] {
            assert_eq!(
                signer.verify(&bad, INGRESS, NOW),
                Err(RelayTokenError::Envelope),
                "must reject {bad:?}"
            );
        }
    }

    fn pending_with(p: &PendingRelays, jti: &str, b: RelayBinding) {
        let (tx, _rx) = oneshot::channel();
        assert!(p.insert(jti.to_string(), b, NOW + TTL, tx));
    }

    #[test]
    fn the_ledger_is_bounded_and_fails_closed_at_capacity() {
        // R5: a signal storm cannot grow the ledger without limit.
        let pending = PendingRelays::new(2);
        pending_with(&pending, "a", binding());
        pending_with(&pending, "b", binding());
        // The 3rd insert is refused (fail closed); its sender is dropped.
        let (tx, _rx) = oneshot::channel();
        assert!(
            !pending.insert("c".into(), binding(), NOW + TTL, tx),
            "at capacity, insert must fail closed"
        );
        assert_eq!(pending.len(), 2);
        // gc frees room again.
        pending.gc(NOW + TTL);
        assert!(pending.is_empty());
        pending_with(&pending, "d", binding());
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn removal_is_consumption_so_a_replay_finds_nothing() {
        let signer = RelaySigner::generate();
        let pending = PendingRelays::default();
        let (jti, token) = signer.mint(INGRESS, &binding(), TTL, NOW);
        pending_with(&pending, &jti, binding());

        let payload = signer.verify(&token, INGRESS, NOW).unwrap();
        assert!(pending.consume(&payload).is_ok(), "first use redeems");
        let payload = signer.verify(&token, INGRESS, NOW).unwrap();
        assert!(matches!(
            pending.consume(&payload),
            Err(RelayTokenError::NotPending)
        ));
        assert!(pending.is_empty());
    }

    #[test]
    fn cross_session_node_owner_and_nonce_bindings_are_refused() {
        let signer = RelaySigner::generate();
        for tamper in [
            RelayBinding {
                session_id: "sess-2".into(),
                ..binding()
            },
            RelayBinding {
                node_id: "node-other".into(),
                ..binding()
            },
            RelayBinding {
                node_name: "node-b".into(),
                ..binding()
            },
            RelayBinding {
                owner_gateway_id: "gw-C".into(),
                ..binding()
            },
            RelayBinding {
                owner_nonce: 6,
                ..binding()
            },
            RelayBinding {
                principal: "root".into(),
                ..binding()
            },
        ] {
            let pending = PendingRelays::default();
            let (jti, token) = signer.mint(INGRESS, &tamper, TTL, NOW);
            pending_with(&pending, &jti, binding());
            let payload = signer.verify(&token, INGRESS, NOW).unwrap();
            assert!(
                matches!(
                    pending.consume(&payload),
                    Err(RelayTokenError::BindingMismatch)
                ),
                "must refuse {tamper:?}"
            );
            assert!(pending.is_empty(), "the jti is burned even on mismatch");
        }
    }

    #[test]
    fn abandon_and_gc_drop_the_token() {
        let pending = PendingRelays::default();
        pending_with(&pending, "a", binding());
        pending.abandon("a");
        assert!(pending.is_empty());

        pending_with(&pending, "b", binding());
        pending.gc(NOW);
        assert_eq!(pending.len(), 1, "not yet expired");
        pending.gc(NOW + TTL);
        assert!(pending.is_empty(), "gc drops expired entries");
    }
}
