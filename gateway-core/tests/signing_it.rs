//! Part C integration tests: the session-bound `SignSessionCertificate` RPC —
//! the happy path plus the cross-gateway / cross-session / expired / replayed /
//! unauthenticated pen-tests. Every rejection is a fail-closed generic denial.

mod support;

use gateway_core::pb::SignContext;
use gateway_core::{identity, mtls, signing};
use std::time::{Duration, Instant};
use support::MockCp;

const CT: Duration = Duration::from_secs(5);
const RT: Duration = Duration::from_secs(10);

/// Enroll a gateway against `cp` and return its credential (keeps the store
/// alive so the data-dir lock is held for the test's duration).
async fn enroll(
    cp: &MockCp,
) -> (
    tempfile::TempDir,
    identity::IdentityStore,
    identity::Credential,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    let cred = identity::enroll(
        &store,
        &cp.channel_params(CT, RT),
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-sign",
    )
    .await
    .unwrap();
    (dir, store, cred)
}

async fn mtls_channel(cp: &MockCp, cred: &identity::Credential) -> tonic::transport::Channel {
    mtls::connect_mtls(
        &cp.channel_params(CT, RT),
        &cred.ca_chain_der,
        &cred.identity,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn valid_token_signs_an_inner_cert() {
    let cp = MockCp::start().await;
    let (_dir, _store, cred) = enroll(&cp).await;
    let token = cp.mint_session_token(
        &cred.gateway_id,
        "sess-1",
        "node-1",
        "deploy",
        Duration::from_secs(60),
    );

    let inner = signing::InnerKeyPair::generate().unwrap();
    let channel = mtls_channel(&cp, &cred).await;
    let cert = signing::sign_session_certificate(channel, &token, &inner, None, RT)
        .await
        .expect("valid session-bound request returns a certificate");

    assert!(cert
        .certificate_line
        .starts_with("ecdsa-sha2-nistp256-cert-v01@openssh.com "));
    assert!(!cert.certificate_blob.is_empty());
    assert_eq!(cert.key_id, "sess-1+deploy");
}

#[tokio::test]
async fn cross_gateway_token_is_rejected() {
    let cp = MockCp::start().await;
    let (_dir, _store, cred) = enroll(&cp).await;
    // A token bound to a DIFFERENT gateway than the caller.
    let token = cp.mint_session_token(
        "gw-someone-else",
        "sess-x",
        "node-1",
        "deploy",
        Duration::from_secs(60),
    );

    let inner = signing::InnerKeyPair::generate().unwrap();
    let channel = mtls_channel(&cp, &cred).await;
    let err = signing::sign_session_certificate(channel, &token, &inner, None, RT)
        .await
        .expect_err("a token bound to another gateway must be rejected");
    assert!(matches!(err, signing::SigningError::Rpc(_)));
}

#[tokio::test]
async fn cross_session_context_is_rejected() {
    let cp = MockCp::start().await;
    let (_dir, _store, cred) = enroll(&cp).await;
    let token = cp.mint_session_token(
        &cred.gateway_id,
        "sess-1",
        "node-1",
        "deploy",
        Duration::from_secs(60),
    );

    // Advisory context disagreeing with the (authoritative) token fails closed.
    let ctx = Some(SignContext {
        session_id: "sess-DIFFERENT".to_string(),
        node_id: String::new(),
        requested_principal: String::new(),
    });
    let inner = signing::InnerKeyPair::generate().unwrap();
    let channel = mtls_channel(&cp, &cred).await;
    let err = signing::sign_session_certificate(channel, &token, &inner, ctx, RT)
        .await
        .expect_err("context that contradicts the token must be rejected");
    assert!(matches!(err, signing::SigningError::Rpc(_)));
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let cp = MockCp::start().await;
    let (_dir, _store, cred) = enroll(&cp).await;
    let token = cp.mint_expired_session_token(&cred.gateway_id, "sess-1", "node-1", "deploy");

    let inner = signing::InnerKeyPair::generate().unwrap();
    let channel = mtls_channel(&cp, &cred).await;
    let err = signing::sign_session_certificate(channel, &token, &inner, None, RT)
        .await
        .expect_err("an expired token must be rejected");
    assert!(matches!(err, signing::SigningError::Rpc(_)));
}

#[tokio::test]
async fn replayed_token_is_rejected() {
    let cp = MockCp::start().await;
    let (_dir, _store, cred) = enroll(&cp).await;
    let token = cp.mint_session_token(
        &cred.gateway_id,
        "sess-1",
        "node-1",
        "deploy",
        Duration::from_secs(60),
    );

    let inner = signing::InnerKeyPair::generate().unwrap();
    let channel = mtls_channel(&cp, &cred).await;
    signing::sign_session_certificate(channel.clone(), &token, &inner, None, RT)
        .await
        .expect("first use of the single-use token succeeds");

    // Reusing the same token is refused (single-use / replay).
    let err = signing::sign_session_certificate(channel, &token, &inner, None, RT)
        .await
        .expect_err("a replayed token must be rejected");
    assert!(matches!(err, signing::SigningError::Rpc(_)));
}

#[tokio::test]
async fn signing_without_client_certificate_is_refused() {
    // The signing RPC requires the mTLS client cert; the bootstrap (server-auth
    // only) channel must be refused.
    let cp = MockCp::start().await;
    let (_dir, _store, cred) = enroll(&cp).await;
    let token = cp.mint_session_token(
        &cred.gateway_id,
        "sess-1",
        "node-1",
        "deploy",
        Duration::from_secs(60),
    );

    let inner = signing::InnerKeyPair::generate().unwrap();
    let channel = mtls::connect_bootstrap(&cp.channel_params(CT, RT), &cp.bootstrap_anchors())
        .await
        .unwrap();
    let err = signing::sign_session_certificate(channel, &token, &inner, None, RT)
        .await
        .expect_err("signing without a client certificate must be refused");
    assert!(matches!(err, signing::SigningError::Rpc(_)));
}

#[tokio::test]
async fn signing_times_out_against_a_hung_cp() {
    // A hung CP must never hang the (future) SSH handshake: the RPC is bounded.
    let cp = MockCp::start().await;
    let (_dir, _store, cred) = enroll(&cp).await;
    cp.set_sign_hangs();
    let token = cp.mint_session_token(
        &cred.gateway_id,
        "sess-1",
        "node-1",
        "deploy",
        Duration::from_secs(60),
    );

    let inner = signing::InnerKeyPair::generate().unwrap();
    let channel = mtls_channel(&cp, &cred).await;
    let bound = Duration::from_millis(400);
    let start = Instant::now();
    let err = signing::sign_session_certificate(channel, &token, &inner, None, bound)
        .await
        .expect_err("a hung CP must yield a bounded timeout, not hang");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "signing must be bounded by its timeout, took {:?}",
        start.elapsed()
    );
    assert!(matches!(err, signing::SigningError::Timeout(_)));
}

#[tokio::test]
async fn locked_gateway_cannot_sign() {
    let cp = MockCp::start().await;
    let (_dir, _store, cred) = enroll(&cp).await;
    cp.lock_gateway(&cred.gateway_id);
    let token = cp.mint_session_token(
        &cred.gateway_id,
        "sess-1",
        "node-1",
        "deploy",
        Duration::from_secs(60),
    );

    let inner = signing::InnerKeyPair::generate().unwrap();
    let channel = mtls_channel(&cp, &cred).await;
    let err = signing::sign_session_certificate(channel, &token, &inner, None, RT)
        .await
        .expect_err("a locked gateway must not obtain a certificate");
    assert!(matches!(err, signing::SigningError::Rpc(_)));
}
