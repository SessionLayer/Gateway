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

/// Domain separation for the signature - the trailing NUL is part of the domain.
const DOMAIN: &[u8] = b"sessionlayer-gw-relay-v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayBinding {
    pub node_id: String,
    pub node_name: String,
    pub session_id: String,
    pub owner_gateway_id: String,
    pub principal: String,
    pub owner_nonce: u64,
}

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
    #[error("relay token is bound to a different ingress gateway")]
    WrongIngress,
    #[error("relay token is expired")]
    Expired,
    #[error("relay token is not pending (replayed, unknown, or abandoned)")]
    NotPending,
    #[error("relay token bindings do not match the pending relay")]
    BindingMismatch,
    #[error("relay token was issued for a different owner gateway")]
    WrongOwner,
}

/// Never persisted; tokens from a previous boot are unverifiable by construction.
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
    pub fn generate() -> Self {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let spki = p256::PublicKey::from(VerifyingKey::from(&key))
            .to_public_key_der()
            .expect("a P-256 public key always encodes as SPKI DER");
        let fingerprint = hex(&Sha256::digest(spki.as_bytes()));
        Self { key, fingerprint }
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Never logged, persisted, or echoed.
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

    /// Verify-then-decode. Returns the decoded payload.
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

struct PendingRelay {
    binding: RelayBinding,
    expires_at_ms: i64,
    ready: oneshot::Sender<Box<dyn ByteStream>>,
}

const DEFAULT_MAX_PENDING: usize = 4096;

pub struct PendingRelays {
    inner: Mutex<HashMap<String, PendingRelay>>,
    max_pending: usize,
}

impl Default for PendingRelays {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PENDING)
    }
}

/// Fail-closed: recover a poisoned lock (critical section runs no user code).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl PendingRelays {
    pub fn new(max_pending: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_pending,
        }
    }

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
        if presented != entry.binding {
            return Err(RelayTokenError::BindingMismatch);
        }
        Ok(entry.ready)
    }

    pub fn abandon(&self, jti: &str) {
        lock(&self.inner).remove(jti);
    }

    pub fn gc(&self, now_ms: i64) {
        self.inner
            .lock()
            .unwrap()
            .retain(|_, e| e.expires_at_ms > now_ms);
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

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
        payload.owner_nonce = 999;
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
        let pending = PendingRelays::new(2);
        pending_with(&pending, "a", binding());
        pending_with(&pending, "b", binding());
        let (tx, _rx) = oneshot::channel();
        assert!(
            !pending.insert("c".into(), binding(), NOW + TTL, tx),
            "at capacity, insert must fail closed"
        );
        assert_eq!(pending.len(), 2);
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
