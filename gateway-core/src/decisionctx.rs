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

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("empty signed context, signature, or signer certificate")]
    MissingMaterial,
    #[error("signer leaf certificate did not parse")]
    LeafParse,
    #[error("signer leaf does not chain to the pinned internal mTLS CA")]
    UntrustedChain,
    #[error("signer leaf is outside its validity window")]
    LeafExpired,
    #[error("signer leaf is a CA certificate (must be an end-entity code signer)")]
    LeafIsCa,
    #[error("signer leaf is missing the decision-context signer SAN marker")]
    MissingSignerMarker,
    #[error("signer leaf is missing the codeSigning extended-key-usage")]
    NotCodeSigner,
    #[error("signer leaf public key is not a valid P-256 key")]
    BadSignerKey,
    #[error("decision-context signature did not verify")]
    BadSignature,
    #[error("signed context bytes did not decode as a DecisionContext")]
    ContextDecode,
}

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
    // chain, matching the single-TrustAnchor PKIX path). We verify the leaf's
    // signature with each pinned anchor's public key and require the issuer name
    // to match, so the CP cannot smuggle its own anchor via signer_ca_chain.
    if !chains_to_pinned_ca(&leaf, ca_anchors) {
        return Err(VerifyError::UntrustedChain);
    }

    if !leaf.validity().is_valid() {
        return Err(VerifyError::LeafExpired);
    }

    if is_ca(&leaf) {
        return Err(VerifyError::LeafIsCa);
    }
    if !has_signer_marker(&leaf) {
        return Err(VerifyError::MissingSignerMarker);
    }
    if !is_code_signer(&leaf) {
        return Err(VerifyError::NotCodeSigner);
    }

    let verifying_key = VerifyingKey::from_public_key_der(leaf.public_key().raw)
        .map_err(|_| VerifyError::BadSignerKey)?;
    let sig = Signature::from_der(signature).map_err(|_| VerifyError::BadSignature)?;
    let mut msg = Vec::with_capacity(DOMAIN_PREFIX.len() + signed_context.len());
    msg.extend_from_slice(DOMAIN_PREFIX);
    msg.extend_from_slice(signed_context);
    verifying_key
        .verify(&msg, &sig)
        .map_err(|_| VerifyError::BadSignature)?;

    <DecisionContext as prost::Message>::decode(signed_context)
        .map_err(|_| VerifyError::ContextDecode)
}

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
        signed[0] ^= 0xff;
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
        let (leaf, sk) = issue(&ca, vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth], None);
        let (signed, sig) = sign(&sk, &sample_context());
        assert!(
            verify_decision_context(&signed, &sig, &leaf, std::slice::from_ref(&ca.der)).is_err()
        );
    }

    #[test]
    fn marked_leaf_with_wrong_eku_is_rejected() {
        let ca = make_ca();
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
