//! Session Fifteen — the hand-rolled NATS coordination backend against a REAL NATS server
//! (T3 F2). The InProcess backend proves the routing seam; this proves the Part C claim
//! "the signal reaches the owner VIA NATS" — exercising the hand-rolled INFO/CONNECT/SUB/PUB/
//! MSG/PING-PONG parse against `nats:2.10-alpine`, so a codec regression fails the gate.

mod support;

use std::time::Duration;

use gateway_core::ha::coordination::CoordinationBackend;
use gateway_core::ha::nats::NatsBackend;
use gateway_core::pbgw::DialBackSignal;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use futures_util::stream::BoxStream;
use futures_util::StreamExt;

const NATS_IMAGE: &str = "nats";
const NATS_TAG: &str = "2.10-alpine";
const NATS_PORT: u16 = 4222;

async fn start_nats() -> anyhow::Result<(ContainerAsync<GenericImage>, String)> {
    support::docker::ensure_docker_host();
    // NATS logs "Server is ready" once the client port is accepting connections.
    let container = GenericImage::new(NATS_IMAGE, NATS_TAG)
        .with_wait_for(WaitFor::message_on_stderr("Server is ready"))
        .with_startup_timeout(Duration::from_secs(90))
        .start()
        .await?;
    let port = container.get_host_port_ipv4(NATS_PORT).await?;
    Ok((container, format!("nats://127.0.0.1:{port}")))
}

/// Poll until the backend's connection manager has completed a connect (it retries every ~1s).
async fn wait_connected(backend: &NatsBackend) {
    for _ in 0..300 {
        if backend.is_connected() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("NATS backend did not connect within the bound");
}

/// Publish and await delivery, retrying: core NATS delivers only to CURRENTLY-registered
/// subscribers, so we retry until the SUB has propagated server-side (bounded).
async fn publish_until_received(
    ingress: &NatsBackend,
    sub: &mut BoxStream<'static, DialBackSignal>,
    signal: &DialBackSignal,
) -> DialBackSignal {
    for _ in 0..40 {
        ingress
            .publish_dial_back(&signal.owner_gateway_id, signal)
            .await
            .expect("publish to a live broker succeeds");
        if let Ok(Some(got)) = tokio::time::timeout(Duration::from_millis(400), sub.next()).await {
            return got;
        }
    }
    panic!("the published signal never arrived over NATS");
}

#[tokio::test]
async fn a_signal_reaches_the_owner_via_a_real_nats_server() -> anyhow::Result<()> {
    let (_container, url) = start_nats().await?;

    // Two independent backends over one broker: the owner subscribes, the ingress publishes.
    let owner = NatsBackend::connect(&url, "sl")?;
    let ingress = NatsBackend::connect(&url, "sl")?;
    wait_connected(&owner).await;
    wait_connected(&ingress).await;

    let mut sub = owner.subscribe("gw-B");
    let signal = DialBackSignal {
        node_id: "node-uuid".into(),
        node_name: "web-01".into(),
        session_id: "sess-x".into(),
        ingress_gateway_id: "gw-A".into(),
        ingress_relay_addr: "gw-a.internal:9444".into(),
        owner_gateway_id: "gw-B".into(),
        owner_nonce: 9,
        principal: "deploy".into(),
        relay_token: "SLGW1.aa.bb".into(),
        exp_epoch_ms: 1,
    };

    // The decoded DialBackSignal arrives over the hand-rolled MSG parse — verbatim.
    let got = publish_until_received(&ingress, &mut sub, &signal).await;
    assert_eq!(got.node_name, "web-01");
    assert_eq!(got.owner_gateway_id, "gw-B");
    assert_eq!(got.owner_nonce, 9);
    assert_eq!(got.relay_token, "SLGW1.aa.bb");

    // PING/PONG liveness: after an idle gap the connection is still healthy (a broken keepalive
    // would drop the connection / clear `connected`), and a fresh publish still delivers.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        ingress.is_connected() && owner.is_connected(),
        "connections stay live across an idle gap"
    );
    let got2 = publish_until_received(&ingress, &mut sub, &signal).await;
    assert_eq!(got2.node_name, "web-01");

    Ok(())
}
