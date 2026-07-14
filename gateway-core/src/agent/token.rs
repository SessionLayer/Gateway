//! The dial-back token (contract §6, FR-HA-8): a **single-use, Gateway-signed
//! capability** for exactly one dial-back.
//!
//! ```text
//! SLDB1.<base64url(payload)>.<base64url(signature)>          (no padding)
//! ```
//!
//! The signature is ECDSA P-256 / SHA-256 over `DOMAIN || payload_bytes`, so a
//! signature can never be lifted from another context. The signing key is generated
//! **per process**, held in memory, and never persisted: a token minted by a previous
//! boot or a different Gateway does not verify here at all.
//!
//! Verification is **verify-then-decode** (mirroring [`crate::decisionctx`]): the
//! signature is checked over the exact transmitted bytes *before* they are parsed as
//! protobuf, so an unverified attacker-supplied buffer never reaches the decoder.

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

use crate::pbagent::DialBackTokenPayload;
use crate::ssh::connector::ByteStream;

/// Envelope prefix. A token that does not start with this is refused unparsed.
const ENVELOPE: &str = "SLDB1";

/// Domain separation for the signature (contract §6).
const DOMAIN: &[u8] = b"sessionlayer-dialback-v1:";

/// Tolerance on `issued_at` for a clock that steps backwards mid-process. The
/// issuer and the verifier are the *same* process, so this is belt-and-braces, not
/// a cross-host skew allowance.
const ISSUED_AT_SKEW_SECS: i64 = 5;

/// The five FR-HA-8 bindings (plus the agent binding) a dial-back is tied to. Held
/// in the pending map at issue and compared against the presented token's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialBackBinding {
    /// The node this dial-back serves (the join key to the agent's control channel).
    pub node_name: String,
    /// The Gateway session this dial-back serves.
    pub session_id: String,
    /// The resolved Linux principal (audit + binding; never enforced by the Agent).
    pub principal: String,
    /// The agent the token was issued to. The dial-back connection's mTLS identity
    /// must resolve to exactly this agent.
    pub agent_id: String,
}

/// A dial-back token rejection. Every variant is reported to the peer as the single
/// coarse `UNAUTHORIZED` (§7.1 non-disclosure); the specific reason is operator-log
/// only.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    /// The envelope is not `SLDB1.<b64url>.<b64url>`.
    #[error("malformed dial-back token envelope")]
    Envelope,
    /// The ECDSA signature did not verify under this process's signing key.
    #[error("dial-back token signature did not verify")]
    BadSignature,
    /// The signed bytes did not decode as a `DialBackTokenPayload`.
    #[error("dial-back token payload did not decode")]
    Decode,
    /// The token carries another Gateway process's signer fingerprint.
    #[error("dial-back token was minted by a different signing key")]
    ForeignSigner,
    /// The token was minted for a different Gateway.
    #[error("dial-back token is bound to a different gateway")]
    WrongGateway,
    /// Outside `[issued_at - skew, not_after)`.
    #[error("dial-back token is expired or not yet valid")]
    Expired,
    /// The `jti` is not in the pending map: unknown, already consumed (a replay), or
    /// abandoned when its session timed out.
    #[error("dial-back token is not pending (replayed, unknown, or abandoned)")]
    NotPending,
    /// The presented token's bindings do not equal the pending entry's.
    #[error("dial-back token bindings do not match the pending dial-back")]
    BindingMismatch,
    /// The dial-back connection's mTLS identity is not the agent the token names, or
    /// that agent does not own the node.
    #[error("dial-back token was issued to a different agent")]
    WrongAgent,
    /// The agent is covered by a Lock (re-checked here, not just at registration).
    #[error("agent is locked")]
    Locked,
}

/// The per-process dial-back signing key (contract §6). Never persisted; a token
/// from a previous boot is unverifiable by construction.
pub struct DialBackSigner {
    key: SigningKey,
    fingerprint: Vec<u8>,
}

impl std::fmt::Debug for DialBackSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialBackSigner")
            .field("key", &"<redacted>")
            .field("fingerprint", &hex(&self.fingerprint))
            .finish()
    }
}

impl DialBackSigner {
    /// Generate this process's signing key.
    pub fn generate() -> Self {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let spki = p256::PublicKey::from(VerifyingKey::from(&key))
            .to_public_key_der()
            .expect("a P-256 public key always encodes as SPKI DER");
        let fingerprint = Sha256::digest(spki.as_bytes()).to_vec();
        Self { key, fingerprint }
    }

    /// SHA-256 of the signing key's SPKI (DER) — the value carried in the payload.
    pub fn fingerprint(&self) -> &[u8] {
        &self.fingerprint
    }

    /// Mint a token for one dial-back, returning `(jti, token)`. The `jti` is the
    /// pending-map key; the token itself is NEVER logged, persisted, or echoed.
    pub fn mint(
        &self,
        gateway_id: &str,
        binding: &DialBackBinding,
        ttl_secs: i64,
        now: i64,
    ) -> (String, String) {
        let jti = random_jti();
        let payload = DialBackTokenPayload {
            jti: jti.clone(),
            gateway_id: gateway_id.to_string(),
            node_name: binding.node_name.clone(),
            session_id: binding.session_id.clone(),
            principal: binding.principal.clone(),
            agent_id: binding.agent_id.clone(),
            issued_at_epoch_seconds: now,
            not_after_epoch_seconds: now.saturating_add(ttl_secs),
            signer_key_fingerprint: self.fingerprint.clone(),
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

    /// Verify a presented token's envelope, signature, signer, gateway and validity
    /// window (contract §6 checks 1–3) and return the decoded payload.
    ///
    /// The signature is verified over the **transmitted bytes** first; only then are
    /// they decoded. The signer-fingerprint equality that follows is defense in
    /// depth — a token from another key already fails the signature check, since
    /// this process holds exactly one key and never trusts one from the wire.
    pub fn verify(
        &self,
        token: &str,
        gateway_id: &str,
        now: i64,
    ) -> Result<DialBackTokenPayload, TokenError> {
        let mut parts = token.split('.');
        let (Some(ENVELOPE), Some(payload_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TokenError::Envelope);
        };
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| TokenError::Envelope)?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| TokenError::Envelope)?;

        let sig = Signature::from_der(&sig_bytes).map_err(|_| TokenError::BadSignature)?;
        VerifyingKey::from(&self.key)
            .verify(&signing_input(&payload_bytes), &sig)
            .map_err(|_| TokenError::BadSignature)?;

        let payload =
            DialBackTokenPayload::decode(payload_bytes.as_ref()).map_err(|_| TokenError::Decode)?;

        if payload.signer_key_fingerprint != self.fingerprint {
            return Err(TokenError::ForeignSigner);
        }
        if payload.gateway_id != gateway_id {
            return Err(TokenError::WrongGateway);
        }
        if payload.issued_at_epoch_seconds.saturating_sub(ISSUED_AT_SKEW_SECS) > now
            || now >= payload.not_after_epoch_seconds
        {
            return Err(TokenError::Expired);
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

/// A dial-back the Gateway has signalled and is waiting for. Its presence in the
/// pending map IS the token's single-use right: **removal is consumption**.
struct PendingDialBack {
    binding: DialBackBinding,
    request_id: String,
    expires_at: i64,
    ready: oneshot::Sender<Box<dyn ByteStream>>,
}

/// The in-memory single-use ledger for issued dial-back tokens.
///
/// Only the `jti` and its bindings are held — never token material — so there is no
/// store of secrets to steal. A replay finds nothing here and is refused.
#[derive(Default)]
pub struct PendingDialBacks {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    by_jti: HashMap<String, PendingDialBack>,
    /// `request_id -> jti`, so the Agent's `DIAL_BACK_RESULT` fast-fail can abandon
    /// the right entry without scanning.
    by_request: HashMap<String, String>,
}

impl PendingDialBacks {
    /// Register a pending dial-back at issue time.
    pub fn insert(
        &self,
        jti: String,
        request_id: String,
        binding: DialBackBinding,
        expires_at: i64,
        ready: oneshot::Sender<Box<dyn ByteStream>>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.by_request.insert(request_id.clone(), jti.clone());
        inner.by_jti.insert(
            jti,
            PendingDialBack {
                binding,
                request_id,
                expires_at,
                ready,
            },
        );
    }

    /// **Consume** a pending dial-back (removal is consumption — a replay of the same
    /// `jti` finds nothing). Returns the sender to hand the spliced stream to, only
    /// if every binding matches the presented payload.
    pub fn consume(
        &self,
        payload: &DialBackTokenPayload,
    ) -> Result<oneshot::Sender<Box<dyn ByteStream>>, TokenError> {
        let mut inner = self.inner.lock().unwrap();
        let entry = inner
            .by_jti
            .remove(&payload.jti)
            .ok_or(TokenError::NotPending)?;
        inner.by_request.remove(&entry.request_id);

        let presented = DialBackBinding {
            node_name: payload.node_name.clone(),
            session_id: payload.session_id.clone(),
            principal: payload.principal.clone(),
            agent_id: payload.agent_id.clone(),
        };
        // The jti is consumed either way: a mismatched presentation burns the token
        // rather than leaving it redeemable for a second attempt.
        if presented != entry.binding {
            return Err(TokenError::BindingMismatch);
        }
        Ok(entry.ready)
    }

    /// Abandon a pending dial-back by `jti` (the dial-back deadline elapsed): the
    /// token stops being redeemable at once, without waiting for its expiry.
    pub fn abandon(&self, jti: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.by_jti.remove(jti) {
            inner.by_request.remove(&entry.request_id);
        }
    }

    /// Abandon by `request_id` — the Agent reported a fast-fail (`DIAL_BACK_RESULT`
    /// with `accepted = false`), so the Gateway need not wait out the deadline.
    /// Dropping the entry drops its sender, which wakes the waiting connector.
    pub fn fail_request(&self, request_id: &str) {
        let jti = self.inner.lock().unwrap().by_request.get(request_id).cloned();
        if let Some(jti) = jti {
            self.abandon(&jti);
        }
    }

    /// Drop entries past their expiry (a signalled Agent that never dialled back).
    pub fn gc(&self, now: i64) {
        let mut inner = self.inner.lock().unwrap();
        let expired: Vec<String> = inner
            .by_jti
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(jti, _)| jti.clone())
            .collect();
        for jti in expired {
            if let Some(entry) = inner.by_jti.remove(&jti) {
                inner.by_request.remove(&entry.request_id);
            }
        }
    }

    /// How many dial-backs are outstanding (tests / metrics).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_jti.len()
    }

    /// Whether no dial-back is outstanding.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Current Unix time in seconds (the Gateway clock the token window is judged by).
pub fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GW: &str = "gw-1";
    const NOW: i64 = 1_700_000_000;
    const TTL: i64 = 30;

    fn binding() -> DialBackBinding {
        DialBackBinding {
            node_name: "node-a".into(),
            session_id: "sess-1".into(),
            principal: "deploy".into(),
            agent_id: "agent-1".into(),
        }
    }

    #[test]
    fn valid_token_verifies_and_carries_every_binding() {
        let signer = DialBackSigner::generate();
        let (jti, token) = signer.mint(GW, &binding(), TTL, NOW);
        let payload = signer.verify(&token, GW, NOW).unwrap();
        assert_eq!(payload.jti, jti);
        assert_eq!(payload.node_name, "node-a");
        assert_eq!(payload.session_id, "sess-1");
        assert_eq!(payload.principal, "deploy");
        assert_eq!(payload.agent_id, "agent-1");
        assert_eq!(payload.signer_key_fingerprint, signer.fingerprint());
        assert!(token.starts_with("SLDB1."));
    }

    #[test]
    fn tampered_payload_fails_the_signature() {
        let signer = DialBackSigner::generate();
        let (_, token) = signer.mint(GW, &binding(), TTL, NOW);
        // Re-encode a payload with a different node, keeping the original signature.
        let mut parts = token.split('.');
        let (_, payload_b64, sig_b64) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let mut payload =
            DialBackTokenPayload::decode(URL_SAFE_NO_PAD.decode(payload_b64).unwrap().as_ref())
                .unwrap();
        payload.node_name = "node-victim".into();
        let forged = format!(
            "SLDB1.{}.{sig_b64}",
            URL_SAFE_NO_PAD.encode(payload.encode_to_vec())
        );
        assert_eq!(
            signer.verify(&forged, GW, NOW),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn a_token_from_another_gateway_process_never_verifies() {
        // A different process = a different per-process key. Its token is worthless
        // here (it fails the signature before the fingerprint is even compared).
        let ours = DialBackSigner::generate();
        let theirs = DialBackSigner::generate();
        let (_, token) = theirs.mint(GW, &binding(), TTL, NOW);
        assert_eq!(ours.verify(&token, GW, NOW), Err(TokenError::BadSignature));
        assert_ne!(ours.fingerprint(), theirs.fingerprint());
    }

    #[test]
    fn wrong_gateway_id_is_refused() {
        let signer = DialBackSigner::generate();
        let (_, token) = signer.mint("gw-other", &binding(), TTL, NOW);
        assert_eq!(
            signer.verify(&token, GW, NOW),
            Err(TokenError::WrongGateway)
        );
    }

    #[test]
    fn expired_and_not_yet_valid_tokens_are_refused() {
        let signer = DialBackSigner::generate();
        let (_, token) = signer.mint(GW, &binding(), TTL, NOW);
        assert!(signer.verify(&token, GW, NOW + TTL - 1).is_ok());
        assert_eq!(
            signer.verify(&token, GW, NOW + TTL),
            Err(TokenError::Expired)
        );
        // A clock that jumped far back: outside the small issued_at tolerance.
        assert_eq!(
            signer.verify(&token, GW, NOW - 3600),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn malformed_envelopes_are_refused_before_any_decode() {
        let signer = DialBackSigner::generate();
        let (_, token) = signer.mint(GW, &binding(), TTL, NOW);
        let body = token.strip_prefix("SLDB1.").unwrap();
        for bad in [
            "".to_string(),
            "SLDB1".to_string(),
            format!("SLDB2.{body}"),
            format!("SLDB1.{body}.extra"),
            "SLDB1.!!!.@@@".to_string(),
            body.to_string(),
        ] {
            assert_eq!(
                signer.verify(&bad, GW, NOW),
                Err(TokenError::Envelope),
                "must reject {bad:?}"
            );
        }
    }

    fn pending_with(p: &PendingDialBacks, jti: &str, b: DialBackBinding) {
        let (tx, _rx) = oneshot::channel();
        p.insert(jti.to_string(), format!("req-{jti}"), b, NOW + TTL, tx);
    }

    #[test]
    fn removal_is_consumption_so_a_replay_finds_nothing() {
        let signer = DialBackSigner::generate();
        let pending = PendingDialBacks::default();
        let (jti, token) = signer.mint(GW, &binding(), TTL, NOW);
        pending_with(&pending, &jti, binding());

        let payload = signer.verify(&token, GW, NOW).unwrap();
        assert!(pending.consume(&payload).is_ok(), "first use redeems");
        // The very same, still-unexpired, still-signature-valid token: refused.
        let payload = signer.verify(&token, GW, NOW).unwrap();
        assert!(matches!(
            pending.consume(&payload),
            Err(TokenError::NotPending)
        ));
        assert!(pending.is_empty());
    }

    #[test]
    fn cross_session_and_cross_node_bindings_are_refused() {
        let signer = DialBackSigner::generate();
        for tamper in [
            DialBackBinding {
                session_id: "sess-2".into(),
                ..binding()
            },
            DialBackBinding {
                node_name: "node-b".into(),
                ..binding()
            },
            DialBackBinding {
                principal: "root".into(),
                ..binding()
            },
            DialBackBinding {
                agent_id: "agent-2".into(),
                ..binding()
            },
        ] {
            // The token is signed for `tamper`, but the Gateway's pending entry (the
            // authoritative record of what it asked for) holds `binding()`.
            let pending = PendingDialBacks::default();
            let (jti, token) = signer.mint(GW, &tamper, TTL, NOW);
            pending_with(&pending, &jti, binding());
            let payload = signer.verify(&token, GW, NOW).unwrap();
            assert!(
                matches!(pending.consume(&payload), Err(TokenError::BindingMismatch)),
                "must refuse {tamper:?}"
            );
            // …and the jti is burned, not left redeemable for a second attempt.
            assert!(pending.is_empty());
        }
    }

    #[test]
    fn abandon_fast_fail_and_gc_all_drop_the_token() {
        let pending = PendingDialBacks::default();

        pending_with(&pending, "a", binding());
        pending.abandon("a");
        assert!(pending.is_empty(), "the deadline abandons the token");

        pending_with(&pending, "b", binding());
        pending.fail_request("req-b");
        assert!(pending.is_empty(), "an Agent fast-fail drops the token");

        pending_with(&pending, "c", binding());
        pending.gc(NOW);
        assert_eq!(pending.len(), 1, "not yet expired");
        pending.gc(NOW + TTL);
        assert!(pending.is_empty(), "gc drops expired entries");
    }

    #[test]
    fn a_dropped_pending_entry_wakes_the_waiting_connector() {
        // The connector awaits the oneshot; abandoning must not leave it hanging
        // until its own timeout (that is the point of the fast-fail).
        let pending = PendingDialBacks::default();
        let (tx, rx) = oneshot::channel();
        pending.insert(
            "j".into(),
            "req-j".into(),
            binding(),
            NOW + TTL,
            tx,
        );
        pending.fail_request("req-j");
        assert!(rx.blocking_recv().is_err(), "sender dropped => connector errors");
    }
}
