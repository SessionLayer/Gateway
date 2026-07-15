//! The SLGW1 Gateway↔Gateway relay token (gateway-relay-v1.md §6, FR-HA-8).
//!
//! A **single-use, ingress-signed capability** for exactly one peer-relay connection —
//! the exact SLDB1 pattern (`crate::agent::token`), profiled for the relay:
//!
//! ```text
//! SLGW1.<base64url(payload)>.<base64url(signature)>          (no padding)
//! ```
//!
//! The signature is ECDSA P-256 / SHA-256 over `DOMAIN || payload_bytes`, so a signature
//! can never be lifted from another context. The signing key is per **ingress process**,
//! held in memory, never persisted: a token minted by another Gateway or a previous boot
//! does not verify here. Verification is **verify-then-decode** — the signature is checked
//! over the transmitted bytes before they are parsed as protobuf.

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

const ENVELOPE: &str = "SLGW1";

/// Domain separation (gateway-relay-v1.md §6): the trailing NUL is part of the prefix.
const DOMAIN: &[u8] = b"sessionlayer-gw-relay-v1\0";

/// Tolerance (ms) on a clock that steps backwards within the ingress process.
const ISSUED_SKEW_MS: i64 = 5_000;

/// The relay bindings an ingress holds for one awaited session and re-checks on the
/// presented token (gateway-relay-v1.md §6). `owner_nonce` is the anti-stale-ownership
/// primitive: the ingress binds the presence nonce it saw at `Authorize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayBinding {
    pub node_id: String,
    pub node_name: String,
    pub session_id: String,
    /// The Gateway this relay is addressed to; the dial-back connection's mTLS peer id
    /// MUST resolve to exactly this Gateway.
    pub owner_gateway_id: String,
    pub principal: String,
    pub owner_nonce: u64,
}

/// A relay-token rejection. Reported to the peer as a coarse `RELAY_REJECT` (§7.1
/// non-disclosure); the specific reason is operator-log only.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayTokenError {
    #[error("malformed relay token envelope")]
    Envelope,
    #[error("relay token signature did not verify")]
    BadSignature,
    #[error("relay token payload did not decode")]
    Decode,
    #[error("relay token was minted by a different signing key")]
    ForeignSigner,
    #[error("relay token is bound to a different ingress")]
    WrongIngress,
    #[error("relay token is expired or not yet valid")]
    Expired,
    #[error("relay token is not pending (replayed, unknown, or abandoned)")]
    NotPending,
    #[error("relay token bindings do not match the awaiting session")]
    BindingMismatch,
    #[error("relay token was issued for a different owner")]
    WrongOwner,
}

/// The per-ingress-process relay signing key (never persisted).
pub struct RelaySigner {
    key: SigningKey,
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

    /// SHA-256 (hex) of the signing key's SPKI — carried in the payload so a token from
    /// another boot or Gateway is refused before its signature is even considered.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Mint a relay token for one dial-back, returning `(jti, token)`. `now_ms` is Unix
    /// epoch milliseconds. The token is NEVER logged, persisted, or echoed.
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

    /// Verify a presented token's envelope, signature, signer, ingress-binding and
    /// validity window (verify-then-decode) and return the decoded payload. The
    /// owner-identity / single-use / binding checks are the caller's (they need the
    /// authenticated peer id and the pending ledger).
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

/// One awaited relay the ingress has signalled. Its presence in the pending map IS the
/// token's single-use right: **removal is consumption**.
struct PendingRelay {
    binding: RelayBinding,
    expires_at_ms: i64,
    ready: oneshot::Sender<Box<dyn ByteStream>>,
}

/// The in-memory single-use ledger for issued relay tokens (only the `jti` and bindings
/// are held — never token material).
#[derive(Default)]
pub struct PendingRelays {
    by_jti: Mutex<HashMap<String, PendingRelay>>,
}

impl PendingRelays {
    /// Register an awaited relay at signal time.
    pub fn insert(
        &self,
        jti: String,
        binding: RelayBinding,
        expires_at_ms: i64,
        ready: oneshot::Sender<Box<dyn ByteStream>>,
    ) {
        self.by_jti.lock().unwrap().insert(
            jti,
            PendingRelay {
                binding,
                expires_at_ms,
                ready,
            },
        );
    }

    /// **Consume** a pending relay (removal is consumption — a replay finds nothing).
    /// `peer_gateway_id` is the authenticated mTLS peer on the relay connection; it MUST
    /// equal both the token's `owner_gateway_id` and the awaiting binding's. Returns the
    /// sender to hand the spliced stream to, only if every binding matches.
    pub fn consume(
        &self,
        payload: &RelayTokenPayload,
        peer_gateway_id: &str,
    ) -> Result<oneshot::Sender<Box<dyn ByteStream>>, RelayTokenError> {
        // The owner authenticates as a Gateway; a compromised/superseded peer cannot serve
        // a relay it does not own (gateway-relay-v1.md §7.4).
        if payload.owner_gateway_id != peer_gateway_id {
            return Err(RelayTokenError::WrongOwner);
        }
        let mut map = self.by_jti.lock().unwrap();
        let entry = map.remove(&payload.jti).ok_or(RelayTokenError::NotPending)?;

        let presented = RelayBinding {
            node_id: payload.node_id.clone(),
            node_name: payload.node_name.clone(),
            session_id: payload.session_id.clone(),
            owner_gateway_id: payload.owner_gateway_id.clone(),
            principal: payload.principal.clone(),
            owner_nonce: payload.owner_nonce,
        };
        // The jti is consumed either way: a mismatched presentation burns the token.
        if presented != entry.binding {
            return Err(RelayTokenError::BindingMismatch);
        }
        Ok(entry.ready)
    }

    /// Abandon a pending relay by `jti` (the relay deadline elapsed): the token stops
    /// being redeemable at once.
    pub fn abandon(&self, jti: &str) {
        self.by_jti.lock().unwrap().remove(jti);
    }

    /// Drop entries past their expiry (a signalled owner that never relayed back).
    pub fn gc(&self, now_ms: i64) {
        self.by_jti
            .lock()
            .unwrap()
            .retain(|_, e| e.expires_at_ms > now_ms);
    }

    pub fn len(&self) -> usize {
        self.by_jti.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Current Unix time in **milliseconds** (the relay token window's unit).
pub fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INGRESS: &str = "gw-a";
    const NOW: i64 = 1_700_000_000_000;
    const TTL: i64 = 10_000;

    fn binding() -> RelayBinding {
        RelayBinding {
            node_id: "node-uuid".into(),
            node_name: "node-a".into(),
            session_id: "sess-1".into(),
            owner_gateway_id: "gw-b".into(),
            principal: "deploy".into(),
            owner_nonce: 7,
        }
    }

    #[test]
    fn valid_token_verifies_and_carries_every_binding() {
        let signer = RelaySigner::generate();
        let (jti, token) = signer.mint(INGRESS, &binding(), TTL, NOW);
        let p = signer.verify(&token, INGRESS, NOW).unwrap();
        assert_eq!(p.jti, jti);
        assert_eq!(p.node_id, "node-uuid");
        assert_eq!(p.session_id, "sess-1");
        assert_eq!(p.owner_gateway_id, "gw-b");
        assert_eq!(p.owner_nonce, 7);
        assert_eq!(p.signer_fingerprint, signer.fingerprint());
        assert!(token.starts_with("SLGW1."));
    }

    #[test]
    fn a_token_from_another_ingress_process_never_verifies() {
        let ours = RelaySigner::generate();
        let theirs = RelaySigner::generate();
        let (_, token) = theirs.mint(INGRESS, &binding(), TTL, NOW);
        assert_eq!(
            ours.verify(&token, INGRESS, NOW),
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
    fn tampered_payload_fails_the_signature() {
        let signer = RelaySigner::generate();
        let (_, token) = signer.mint(INGRESS, &binding(), TTL, NOW);
        let mut parts = token.split('.');
        let (_, payload_b64, sig_b64) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let mut p =
            RelayTokenPayload::decode(URL_SAFE_NO_PAD.decode(payload_b64).unwrap().as_ref())
                .unwrap();
        p.owner_nonce = 9999; // forge a newer ownership claim
        let forged = format!("SLGW1.{}.{sig_b64}", URL_SAFE_NO_PAD.encode(p.encode_to_vec()));
        assert_eq!(
            signer.verify(&forged, INGRESS, NOW),
            Err(RelayTokenError::BadSignature)
        );
    }

    fn pending_with(p: &PendingRelays, jti: &str, b: RelayBinding) {
        let (tx, _rx) = oneshot::channel();
        p.insert(jti.to_string(), b, NOW + TTL, tx);
    }

    #[test]
    fn removal_is_consumption_so_a_replay_finds_nothing() {
        let signer = RelaySigner::generate();
        let pending = PendingRelays::default();
        let (jti, token) = signer.mint(INGRESS, &binding(), TTL, NOW);
        pending_with(&pending, &jti, binding());

        let p = signer.verify(&token, INGRESS, NOW).unwrap();
        assert!(pending.consume(&p, "gw-b").is_ok(), "first use redeems");
        let p = signer.verify(&token, INGRESS, NOW).unwrap();
        assert_eq!(pending.consume(&p, "gw-b"), Err(RelayTokenError::NotPending));
        assert!(pending.is_empty());
    }

    #[test]
    fn a_peer_that_is_not_the_named_owner_is_refused_and_the_token_survives() {
        let signer = RelaySigner::generate();
        let pending = PendingRelays::default();
        let (jti, token) = signer.mint(INGRESS, &binding(), TTL, NOW);
        pending_with(&pending, &jti, binding());
        let p = signer.verify(&token, INGRESS, NOW).unwrap();
        // The relay connection authenticated as gw-c, but the token names gw-b.
        assert_eq!(
            pending.consume(&p, "gw-c"),
            Err(RelayTokenError::WrongOwner)
        );
        assert_eq!(pending.len(), 1, "a wrong-owner peer cannot burn the token");
        assert!(pending.consume(&p, "gw-b").is_ok(), "the real owner still redeems");
    }

    #[test]
    fn a_stale_nonce_or_cross_session_binding_is_refused() {
        let signer = RelaySigner::generate();
        for tamper in [
            RelayBinding {
                owner_nonce: 6,
                ..binding()
            }, // superseded ownership
            RelayBinding {
                session_id: "sess-2".into(),
                ..binding()
            },
            RelayBinding {
                node_id: "node-other".into(),
                ..binding()
            },
        ] {
            let pending = PendingRelays::default();
            let (jti, token) = signer.mint(INGRESS, &tamper, TTL, NOW);
            pending_with(&pending, &jti, binding());
            let p = signer.verify(&token, INGRESS, NOW).unwrap();
            assert_eq!(
                pending.consume(&p, "gw-b"),
                Err(RelayTokenError::BindingMismatch),
                "must refuse {tamper:?}"
            );
            assert!(pending.is_empty(), "the jti is burned, not left redeemable");
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
        assert_eq!(pending.len(), 1);
        pending.gc(NOW + TTL);
        assert!(pending.is_empty());
    }
}
