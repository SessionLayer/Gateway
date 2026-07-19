//! Decision-context verification (Session Ten; the Rust port of S5's
//! `DecisionContextVerifier`).
//!
//! The Gateway trusts a cached decision context for its per-channel-open local
//! checks ONLY because its signature verifies (SESSION §2.3). This mirrors the CP
//! reference exactly: PKIX-validate the `CONTEXT_SIGNER` leaf to the internal mTLS
//! CA the Gateway already pins, require the distinguishing SAN URI marker AND the
//! codeSigning EKU (reject any CA cert), then verify the ECDSA-P256/SHA-256
//! signature over a fixed domain-separation prefix followed by the exact signed
//! bytes. Any failure fails **closed** (the context is rejected).

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::pb::DecisionContext;

/// Domain-separation prefix the CP signs before the canonical context bytes. MUST
/// byte-match the CP's `DecisionContextSigning.DOMAIN_PREFIX` (note the trailing
/// newline).
pub const DOMAIN_PREFIX: &[u8] = b"sessionlayer:decision-context:v1\n";

/// The URI SAN that marks a leaf as the decision-context signer. MUST match the
/// CP's `DecisionContextSigning.SIGNER_URI`.
pub const SIGNER_URI: &str = "sessionlayer://decision-context-signer";

/// The deterministic proto serialization of a context — the exact bytes the CP
/// signs and transmits as `signed_context` (the CP `DecisionContextCodec.canonicalBytes`
/// analogue; no map fields, so encoding is stable across languages). Used by the
/// mock CP harness to produce a signed context.
pub fn canonical_bytes(context: &DecisionContext) -> Vec<u8> {
    <DecisionContext as prost::Message>::encode_to_vec(context)
}

/// A fail-closed rejection reason. The variants exist for operator diagnostics;
/// every one collapses to "reject the context" at the call site.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// No signature material was supplied (a CP that does not sign is rejected).
    #[error("empty signed context, signature, or signer certificate")]
    MissingMaterial,
    /// The signer leaf certificate did not parse as X.509 DER.
    #[error("signer leaf certificate did not parse")]
    LeafParse,
    /// The leaf did not chain to a pinned internal mTLS CA anchor.
    #[error("signer leaf does not chain to the pinned internal mTLS CA")]
    UntrustedChain,
    /// The leaf is outside its own validity window.
    #[error("signer leaf is outside its validity window")]
    LeafExpired,
    /// The leaf is a CA certificate (the context signer must be an end entity).
    #[error("signer leaf is a CA certificate (must be an end-entity code signer)")]
    LeafIsCa,
    /// The leaf lacks the decision-context signer SAN URI marker.
    #[error("signer leaf is missing the decision-context signer SAN marker")]
    MissingSignerMarker,
    /// The leaf lacks the codeSigning extended-key-usage.
    #[error("signer leaf is missing the codeSigning extended-key-usage")]
    NotCodeSigner,
    /// The leaf's public key is not a valid P-256 key.
    #[error("signer leaf public key is not a valid P-256 key")]
    BadSignerKey,
    /// The ECDSA-P256/SHA-256 signature did not verify.
    #[error("decision-context signature did not verify")]
    BadSignature,
    /// The signed bytes did not decode as a `DecisionContext`.
    #[error("signed context bytes did not decode as a DecisionContext")]
    ContextDecode,
}

/// Verify a signed decision context and return the authoritative decoded context.
///
/// `ca_anchors` are the pinned internal mTLS CA certificates (DER) the Gateway
/// already trusts for the CP mTLS channel — the same trust root, no new
/// distribution. The returned context is decoded from `signed_context` (the exact
/// signed bytes), NOT from any unverified convenience copy.
pub fn verify_decision_context(
    signed_context: &[u8],
    signature: &[u8],
    signer_cert_der: &[u8],
    ca_anchors: &[Vec<u8>],
) -> Result<DecisionContext, VerifyError> {
    if signed_context.is_empty() || signature.is_empty() || signer_cert_der.is_empty() {
        return Err(VerifyError::MissingMaterial);
    }

    let (_, leaf) =
        X509Certificate::from_der(signer_cert_der).map_err(|_| VerifyError::LeafParse)?;

    // (1) Chain to a PINNED internal mTLS CA — never the CP-supplied chain. The
    // CONTEXT_SIGNER leaf is issued directly by the internal mTLS CA (a one-level
    // chain, matching the S5 single-TrustAnchor PKIX path). We verify the leaf's
    // signature with each pinned anchor's public key and require the issuer name
    // to match, so the CP cannot smuggle its own anchor via signer_ca_chain.
    if !chains_to_pinned_ca(&leaf, ca_anchors) {
        return Err(VerifyError::UntrustedChain);
    }

    // (2) Expire conservatively: reject a leaf outside its own validity window.
    if !leaf.validity().is_valid() {
        return Err(VerifyError::LeafExpired);
    }

    // (3) Defense in depth (mirrors S5): the SAN marker is NOT sufficient alone —
    // require the codeSigning EKU AND reject any CA cert, so a mis-issued or
    // wrong-purpose leaf cannot masquerade as the context signer.
    if is_ca(&leaf) {
        return Err(VerifyError::LeafIsCa);
    }
    if !has_signer_marker(&leaf) {
        return Err(VerifyError::MissingSignerMarker);
    }
    if !is_code_signer(&leaf) {
        return Err(VerifyError::NotCodeSigner);
    }

    // (4) Verify the ECDSA-P256/SHA-256 signature over {DOMAIN_PREFIX ||
    // signed_context} with the leaf's public key.
    let verifying_key = VerifyingKey::from_public_key_der(leaf.public_key().raw)
        .map_err(|_| VerifyError::BadSignerKey)?;
    let sig = Signature::from_der(signature).map_err(|_| VerifyError::BadSignature)?;
    let mut msg = Vec::with_capacity(DOMAIN_PREFIX.len() + signed_context.len());
    msg.extend_from_slice(DOMAIN_PREFIX);
    msg.extend_from_slice(signed_context);
    verifying_key
        .verify(&msg, &sig)
        .map_err(|_| VerifyError::BadSignature)?;

    // The signed bytes are authoritative: decode the context from them.
    <DecisionContext as prost::Message>::decode(signed_context)
        .map_err(|_| VerifyError::ContextDecode)
}

/// True if `leaf`'s signature verifies under one of the pinned CA anchors AND its
/// issuer name matches that anchor's subject (a direct, one-level chain).
fn chains_to_pinned_ca(leaf: &X509Certificate, ca_anchors: &[Vec<u8>]) -> bool {
    for der in ca_anchors {
        let Ok((_, ca)) = X509Certificate::from_der(der) else {
            continue;
        };
        if leaf.issuer() != ca.subject() {
            continue;
        }
        if leaf.verify_signature(Some(ca.public_key())).is_ok() {
            return true;
        }
    }
    false
}

fn is_ca(leaf: &X509Certificate) -> bool {
    leaf.extensions()
        .iter()
        .any(|ext| matches!(ext.parsed_extension(), ParsedExtension::BasicConstraints(bc) if bc.ca))
}

fn has_signer_marker(leaf: &X509Certificate) -> bool {
    leaf.extensions().iter().any(|ext| {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            san.general_names
                .iter()
                .any(|gn| matches!(gn, GeneralName::URI(uri) if *uri == SIGNER_URI))
        } else {
            false
        }
    })
}

fn is_code_signer(leaf: &X509Certificate) -> bool {
    leaf.extensions().iter().any(|ext| {
        matches!(ext.parsed_extension(), ParsedExtension::ExtendedKeyUsage(eku) if eku.code_signing)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::DecisionContext;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::DecodePrivateKey;

    struct Ca {
        der: Vec<u8>,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    fn make_ca() -> Ca {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["Test mTLS CA".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let der = params.self_signed(&key).unwrap().der().to_vec();
        Ca {
            der,
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// Issue a leaf with the given EKUs and optional URI SAN; return (leaf DER,
    /// signing key over the leaf's key).
    fn issue(
        ca: &Ca,
        ekus: Vec<rcgen::ExtendedKeyUsagePurpose>,
        uri_san: Option<&str>,
    ) -> (Vec<u8>, SigningKey) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "signer");
        params.extended_key_usages = ekus;
        if let Some(uri) = uri_san {
            params.subject_alt_names = vec![rcgen::SanType::URI(
                rcgen::string::Ia5String::try_from(uri).unwrap(),
            )];
        }
        let der = params.signed_by(&key, &ca.issuer).unwrap().der().to_vec();
        let sk = SigningKey::from_pkcs8_der(&key.serialize_der()).unwrap();
        (der, sk)
    }

    fn sample_context() -> DecisionContext {
        DecisionContext {
            node_id: "node-1".into(),
            node_name: "node-1".into(),
            allowed_logins: vec!["deploy".into()],
            capabilities: vec![1, 2],
            principal: "deploy".into(),
            grant_expiry_epoch_seconds: 4_000_000_000,
            policy_epoch: 1,
            decision_ttl_seconds: 45,
            gateway_id: "gw".into(),
            session_id: "sess".into(),
            source_address: "1.2.3.4".into(),
            issued_at_epoch_seconds: 1,
            identity: "alice".into(),
            identity_groups: vec!["admins".into()],
            node_labels: vec!["env=prod".into()],
            access_model: crate::pb::AccessModel::Standing as i32,
            idle_timeout_seconds: 0,
        }
    }

    fn sign(sk: &SigningKey, ctx: &DecisionContext) -> (Vec<u8>, Vec<u8>) {
        let signed = canonical_bytes(ctx);
        let mut msg = DOMAIN_PREFIX.to_vec();
        msg.extend_from_slice(&signed);
        let sig: p256::ecdsa::Signature = sk.sign(&msg);
        (signed, sig.to_der().as_bytes().to_vec())
    }

    fn code_signer(ca: &Ca) -> (Vec<u8>, SigningKey) {
        issue(
            ca,
            vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning],
            Some(SIGNER_URI),
        )
    }

    #[test]
    fn valid_context_verifies_and_decodes() {
        let ca = make_ca();
        let (leaf, sk) = code_signer(&ca);
        let ctx = sample_context();
        let (signed, sig) = sign(&sk, &ctx);
        let out =
            verify_decision_context(&signed, &sig, &leaf, std::slice::from_ref(&ca.der)).unwrap();
        assert_eq!(out.identity, "alice");
        assert_eq!(out.session_id, "sess");
        assert_eq!(out.node_labels, vec!["env=prod".to_string()]);
    }

    #[test]
    fn tampered_signed_context_fails_closed() {
        let ca = make_ca();
        let (leaf, sk) = code_signer(&ca);
        let (mut signed, sig) = sign(&sk, &sample_context());
        signed[0] ^= 0xff; // flip a byte after signing
        assert!(
            verify_decision_context(&signed, &sig, &leaf, std::slice::from_ref(&ca.der)).is_err()
        );
    }

    #[test]
    fn wrong_ca_fails_closed() {
        let ca = make_ca();
        let other = make_ca();
        let (leaf, sk) = code_signer(&ca);
        let (signed, sig) = sign(&sk, &sample_context());
        assert!(matches!(
            verify_decision_context(&signed, &sig, &leaf, std::slice::from_ref(&other.der)),
            Err(VerifyError::UntrustedChain)
        ));
    }

    #[test]
    fn non_signer_leaf_without_marker_is_rejected() {
        let ca = make_ca();
        // A valid server leaf (no signer marker, no codeSigning) cannot masquerade.
        let (leaf, sk) = issue(&ca, vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth], None);
        let (signed, sig) = sign(&sk, &sample_context());
        assert!(
            verify_decision_context(&signed, &sig, &leaf, std::slice::from_ref(&ca.der)).is_err()
        );
    }

    #[test]
    fn marked_leaf_with_wrong_eku_is_rejected() {
        let ca = make_ca();
        // Carries the SAN marker but clientAuth EKU (not codeSigning) → rejected:
        // the marker alone is insufficient (defense in depth, mirrors S5).
        let (leaf, sk) = issue(
            &ca,
            vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth],
            Some(SIGNER_URI),
        );
        let (signed, sig) = sign(&sk, &sample_context());
        assert!(matches!(
            verify_decision_context(&signed, &sig, &leaf, std::slice::from_ref(&ca.der)),
            Err(VerifyError::NotCodeSigner)
        ));
    }

    #[test]
    fn empty_material_fails_closed() {
        let ca = make_ca();
        let (leaf, sk) = code_signer(&ca);
        let (signed, sig) = sign(&sk, &sample_context());
        assert!(matches!(
            verify_decision_context(&[], &sig, &leaf, std::slice::from_ref(&ca.der)),
            Err(VerifyError::MissingMaterial)
        ));
        assert!(matches!(
            verify_decision_context(&signed, &[], &leaf, std::slice::from_ref(&ca.der)),
            Err(VerifyError::MissingMaterial)
        ));
    }
}
