//! Part A integration tests: the tonic **mTLS** client + **version negotiation
//! over the secured channel**, and the fail-closed rejection matrix.
//!
//! Each rejection case proves the client refuses rather than degrading to a
//! plaintext or unauthenticated path (NFR-2), and that a hung peer is bounded by
//! a timeout (§10.3).

mod support;

use gateway_core::{handshake, identity, mtls};
use std::time::{Duration, Instant};
use support::{MockCp, TestCa};

const CT: Duration = Duration::from_secs(5);
const RT: Duration = Duration::from_secs(10);

fn short_params(endpoint: String, server_name: &str) -> mtls::ChannelParams {
    mtls::ChannelParams {
        endpoint,
        server_name: server_name.to_string(),
        connect_timeout: Duration::from_millis(500),
        rpc_timeout: Duration::from_millis(500),
    }
}

#[tokio::test]
async fn valid_bootstrap_channel_negotiates_1_1() {
    let cp = MockCp::start().await;
    let channel = mtls::connect_bootstrap(&cp.channel_params(CT, RT), &cp.bootstrap_anchors())
        .await
        .expect("valid mTLS bootstrap channel connects");
    let negotiated = handshake::negotiate_over_channel(channel)
        .await
        .expect("negotiation over the secured channel succeeds");
    assert_eq!(negotiated.version_string(), "1.1");
}

#[tokio::test]
async fn valid_mtls_channel_after_enroll_negotiates() {
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(CT, RT);
    let cred = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        "gw-a",
    )
    .await
    .expect("enroll");

    // The fully-mutual channel (client cert presented) also negotiates.
    let channel = mtls::connect_mtls(&params, &cred.ca_chain_der, &cred.identity)
        .await
        .expect("mTLS channel connects with the issued client identity");
    let negotiated = handshake::negotiate_over_channel(channel).await.unwrap();
    assert_eq!(negotiated.version_string(), "1.1");
}

#[tokio::test]
async fn n_minus_one_negotiates_1_0() {
    // An un-upgraded CP still on 1.0 resolves 1.0 with this 1.1 build over mTLS.
    let cp = MockCp::builder().server_range((1, 0), (1, 0)).start().await;
    let channel = mtls::connect_bootstrap(&cp.channel_params(CT, RT), &cp.bootstrap_anchors())
        .await
        .unwrap();
    let negotiated = handshake::negotiate_over_channel(channel).await.unwrap();
    assert_eq!(negotiated.version_string(), "1.0");
}

#[tokio::test]
async fn wrong_ca_server_cert_is_refused() {
    let cp = MockCp::start().await;
    // Trust a DIFFERENT CA than the one that issued the CP server certificate.
    let bogus = TestCa::generate("bogus-ca");
    let err = mtls::connect_bootstrap(&cp.channel_params(CT, RT), &[bogus.cert_der().to_vec()])
        .await
        .expect_err("wrong-CA server cert must fail closed");
    assert_connect_or_timeout(err);
}

#[tokio::test]
async fn hostname_mismatch_is_refused() {
    let cp = MockCp::start().await;
    let mut params = cp.channel_params(CT, RT);
    params.server_name = "not.cp.internal".to_string();
    let err = mtls::connect_bootstrap(&params, &cp.bootstrap_anchors())
        .await
        .expect_err("SAN/hostname mismatch must fail closed");
    assert_connect_or_timeout(err);
}

#[tokio::test]
async fn plaintext_peer_is_refused() {
    // The https client must never fall back to a plaintext peer.
    let (endpoint, _guard) = support::spawn_plaintext_server().await;
    let anchor = TestCa::generate("cp").cert_der().to_vec();
    let err = mtls::connect_bootstrap(&short_params(endpoint, "cp.internal"), &[anchor])
        .await
        .expect_err("plaintext peer must be refused");
    assert_connect_or_timeout(err);
}

#[tokio::test]
async fn expired_server_cert_is_refused() {
    let cp = MockCp::start().await;
    // A raw server presenting a cert from the CP's own CA, but long expired.
    let leaf = cp.issue_server_material(
        "cp.internal",
        rcgen::date_time_ymd(2000, 1, 1),
        rcgen::date_time_ymd(2001, 1, 1),
    );
    let cfg = support::raw_server_config(leaf.cert_der, leaf.key_pkcs8_der, None);
    let (endpoint, _guard) = support::spawn_raw_tls_server(cfg).await;
    let err = mtls::connect_bootstrap(
        &short_params(endpoint, "cp.internal"),
        &cp.bootstrap_anchors(),
    )
    .await
    .expect_err("expired server cert must fail closed");
    assert_connect_or_timeout(err);
}

#[tokio::test]
async fn tls12_only_server_is_refused() {
    // TLS 1.3 only (VERSIONING §7): a valid-cert but TLS-1.2-only peer is refused.
    let cp = MockCp::start().await;
    let leaf = cp.issue_server_material(
        "cp.internal",
        rcgen::date_time_ymd(2020, 1, 1),
        rcgen::date_time_ymd(2100, 1, 1),
    );
    let cfg = support::raw_server_config(
        leaf.cert_der,
        leaf.key_pkcs8_der,
        Some(&[&rustls::version::TLS12]),
    );
    let (endpoint, _guard) = support::spawn_raw_tls_server(cfg).await;
    let err = mtls::connect_bootstrap(
        &short_params(endpoint, "cp.internal"),
        &cp.bootstrap_anchors(),
    )
    .await
    .expect_err("TLS 1.2-only peer must be refused");
    assert_connect_or_timeout(err);
}

#[tokio::test]
async fn hung_peer_is_bounded_by_timeout() {
    let (endpoint, _guard) = support::spawn_silent_server().await;
    let anchor = TestCa::generate("cp").cert_der().to_vec();
    let params = mtls::ChannelParams {
        endpoint,
        server_name: "cp.internal".to_string(),
        connect_timeout: Duration::from_millis(300),
        rpc_timeout: Duration::from_millis(300),
    };
    let start = Instant::now();
    let err = mtls::connect_bootstrap(&params, &[anchor])
        .await
        .expect_err("a hung peer must yield a bounded error, not hang");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "connect must be bounded by its timeout, took {:?}",
        start.elapsed()
    );
    assert_connect_or_timeout(err);
}

fn assert_connect_or_timeout(err: mtls::MtlsError) {
    assert!(
        matches!(
            err,
            mtls::MtlsError::Connect { .. } | mtls::MtlsError::Timeout { .. }
        ),
        "expected a fail-closed connect/timeout error, got {err:?}"
    );
}
