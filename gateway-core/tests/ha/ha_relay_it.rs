use std::sync::Arc;
use std::time::Duration;

use crate::support::MockCp;
use gateway_core::agent::registry::AgentRegistry;
use gateway_core::agent::server::{self, PeerRelayServerDeps};
use gateway_core::agent::token::{DialBackSigner, PendingDialBacks};
use gateway_core::cpauth::{CpAuthClient, CpChannelFactory, CredentialSnapshot};
use gateway_core::ha::connector::RemoteGatewayConnector;
use gateway_core::ha::coordination::{CoordinationBackend, InProcessBackend};
use gateway_core::ha::peer_client::{self, PeerClientDeps, ServedRelays};
use gateway_core::ha::presence::OwnerCache;
use gateway_core::ha::relay_token::{PendingRelays, RelaySigner};
use gateway_core::identity;
use gateway_core::pb::ConnectorKind;
use gateway_core::pbgw::DialBackSignal;
use gateway_core::ssh::connector::{
    ByteStream, ConnectFuture, NodeConnectError, NodeConnector, NodeDial,
};
use gateway_core::ssh::locks::LockSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NODE: &str = "node-a";

struct EchoNode;

impl NodeConnector for EchoNode {
    fn connect<'a>(&'a self, _dial: &'a NodeDial) -> ConnectFuture<'a> {
        Box::pin(async move {
            let (node_side, echo_side) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(echo_side);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(Box::new(node_side) as Box<dyn ByteStream>)
        })
    }
}

async fn enroll(cp: &MockCp, name: &str) -> identity::Credential {
    let dir = tempfile::tempdir().unwrap();
    // Leak the tempdir so the data-dir lock outlives this call for the test's lifetime.
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    std::mem::forget(dir);
    let params = cp.channel_params(Duration::from_secs(5), Duration::from_secs(10));
    identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        name,
    )
    .await
    .unwrap()
}

fn cpauth_for(cp: &MockCp, cred: &identity::Credential) -> Arc<CpAuthClient> {
    let params = cp.channel_params(Duration::from_secs(5), Duration::from_secs(10));
    let factory = Arc::new(CpChannelFactory::fixed(
        params,
        cred.identity.clone(),
        cred.ca_chain_der.clone(),
    ));
    Arc::new(CpAuthClient::new(factory, Duration::from_secs(10)))
}

struct Ingress {
    remote: RemoteGatewayConnector,
    _shutdown: tokio::sync::watch::Sender<bool>,
}

async fn start_ingress(cp: &MockCp, coordination: Arc<dyn CoordinationBackend>) -> Ingress {
    let cred = enroll(cp, "gw-A").await;
    let cpauth = cpauth_for(cp, &cred);
    let relay_signer = Arc::new(RelaySigner::generate());
    let pending_relays = Arc::new(PendingRelays::default());
    let lock_set = Arc::new(LockSet::new(30, 30));
    lock_set.replace_snapshot(Vec::new(), 1);

    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
    let transport = server::bind(
        server::AgentTransportDeps {
            cpauth,
            gateway_id: cred.gateway_id.clone(),
            gateway_name: cred.gateway_name.clone(),
            registry: Arc::new(AgentRegistry::new(16)),
            pending: Arc::new(PendingDialBacks::default()),
            signer: Arc::new(DialBackSigner::generate()),
            lock_set,
            peer_relay: Some(PeerRelayServerDeps {
                relay_signer: relay_signer.clone(),
                pending_relays: pending_relays.clone(),
            }),
            config: gateway_core::config::AgentTransportConfig {
                listen_addr: "127.0.0.1:0".into(),
                heartbeat_interval_secs: 1,
                handshake_timeout_secs: 5,
                ..Default::default()
            },
        },
        sd_rx.clone(),
    )
    .await
    .expect("gw-A agent transport binds");
    let addr = transport.local_addr().to_string();
    let mut sd = sd_rx;
    tokio::spawn(transport.run(async move {
        let _ = sd.wait_for(|v| *v).await;
    }));

    let remote = RemoteGatewayConnector::new(
        coordination,
        relay_signer,
        pending_relays,
        cred.gateway_name.clone(),
        addr,
        Duration::from_secs(5),
        Duration::from_secs(30),
    );
    Ingress {
        remote,
        _shutdown: sd_tx,
    }
}

/// The owner (gw-B): the peer-client signal handler with a stub echo node. `owns_in_cache`
/// simulates whether gw-B's heartbeat loop currently believes it owns NODE: `true` ⇒ it
/// serves; `false` (superseded owner) ⇒ it refuses and the ingress fails closed.
async fn start_owner(
    cp: &MockCp,
    coordination: Arc<dyn CoordinationBackend>,
    owns_in_cache: bool,
) -> tokio::sync::watch::Sender<bool> {
    let cred = enroll(cp, "gw-B").await;
    let registry = Arc::new(AgentRegistry::new(16));
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    std::mem::forget(rx);
    let guard = registry.register(NODE, "agent-b", tx).unwrap();
    std::mem::forget(guard);

    let owner_cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
    if owns_in_cache {
        owner_cache.observe(NODE, &cred.gateway_name, "gw-b:9444", 1);
    }

    let (cred_tx, cred_rx) = tokio::sync::watch::channel(CredentialSnapshot {
        identity: cred.identity.clone(),
        ca_chain_der: cred.ca_chain_der.clone(),
    });
    std::mem::forget(cred_tx);

    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
    peer_client::spawn(
        PeerClientDeps {
            coordination,
            self_gateway_id: cred.gateway_name.clone(),
            local_connector: Arc::new(EchoNode),
            registry,
            owner_cache,
            served_relays: Arc::new(ServedRelays::default()),
            credential: cred_rx,
            max_frame_bytes: 64 * 1024,
            handshake_timeout: Duration::from_secs(5),
        },
        sd_rx,
    );
    sd_tx
}

fn remote_dial(owner: &str, nonce: u64) -> NodeDial {
    NodeDial {
        node_id: "node-uuid".into(),
        connector_kind: ConnectorKind::OutboundAgent as i32,
        node_name: NODE.into(),
        session_id: "sess-1".into(),
        principal: "deploy".into(),
        owning_gateway_id: owner.to_string(),
        owner_nonce: nonce,
        ..Default::default()
    }
}

#[tokio::test]
async fn a_remote_owned_node_is_relayed_and_the_bus_carries_no_session_bytes() {
    let cp = MockCp::start().await;
    let bus = Arc::new(RecordingBus::new());
    let coordination: Arc<dyn CoordinationBackend> = bus.clone();

    let ingress = start_ingress(&cp, coordination.clone()).await;
    let _owner_sd = start_owner(&cp, coordination.clone(), true).await;

    let mut stream = ingress
        .remote
        .connect(&remote_dial("gw-B", 1))
        .await
        .expect("the relay stream is returned to the inner leg");

    let secret = b"top-secret-session-plaintext-0123456789";
    stream.write_all(secret).await.unwrap();
    stream.flush().await.unwrap();
    let mut got = vec![0u8; secret.len()];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, secret, "the relay carries the byte stream verbatim");

    bus.assert_no_session_bytes(secret);
}

#[tokio::test]
async fn a_superseded_owner_refuses_and_the_ingress_fails_closed() {
    let cp = MockCp::start().await;
    let coordination: Arc<dyn CoordinationBackend> = Arc::new(InProcessBackend::new());
    let ingress = start_ingress(&cp, coordination.clone()).await;
    let _owner_sd = start_owner(&cp, coordination.clone(), false).await;

    let started = std::time::Instant::now();
    let err = ingress
        .remote
        .connect(&remote_dial("gw-B", 1))
        .await
        .unwrap_err();
    assert!(matches!(err, NodeConnectError::Timeout(_)));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a superseded owner must not hang the ingress - fail closed within the bound"
    );
}

#[tokio::test]
async fn no_owner_subscriber_fails_closed() {
    let cp = MockCp::start().await;
    let coordination: Arc<dyn CoordinationBackend> = Arc::new(InProcessBackend::new());
    let ingress = start_ingress(&cp, coordination.clone()).await;
    let err = ingress
        .remote
        .connect(&remote_dial("gw-B", 1))
        .await
        .unwrap_err();
    assert!(matches!(err, NodeConnectError::RelayUnavailable));
}

#[tokio::test]
async fn an_unreachable_owner_times_out_and_fails_closed() {
    let cp = MockCp::start().await;
    let coordination: Arc<dyn CoordinationBackend> = Arc::new(InProcessBackend::new());
    let ingress = start_ingress(&cp, coordination.clone()).await;
    let mut sink = coordination.subscribe("gw-B");
    tokio::spawn(async move {
        use futures_util::StreamExt;
        let _ = sink.next().await;
        std::future::pending::<()>().await;
    });
    let started = std::time::Instant::now();
    let err = ingress
        .remote
        .connect(&remote_dial("gw-B", 1))
        .await
        .unwrap_err();
    assert!(matches!(err, NodeConnectError::Timeout(_)));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "must fail closed within the bound"
    );
}

struct RecordingBus {
    inner: InProcessBackend,
    published: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl RecordingBus {
    fn new() -> Self {
        Self {
            inner: InProcessBackend::new(),
            published: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn assert_no_session_bytes(&self, secret: &[u8]) {
        let published = self.published.lock().unwrap();
        assert!(
            !published.is_empty(),
            "at least the dial-back signal was published"
        );
        for payload in published.iter() {
            assert!(
                !contains_subsequence(payload, secret),
                "session plaintext must NEVER traverse the coordination bus"
            );
        }
    }
}

impl CoordinationBackend for RecordingBus {
    fn publish_dial_back<'a>(
        &'a self,
        owner_gateway_id: &'a str,
        signal: &'a DialBackSignal,
    ) -> gateway_core::ha::coordination::PublishFuture<'a> {
        use prost::Message;
        self.published.lock().unwrap().push(signal.encode_to_vec());
        self.inner.publish_dial_back(owner_gateway_id, signal)
    }

    fn subscribe(
        &self,
        my_gateway_id: &str,
    ) -> futures_util::stream::BoxStream<'static, DialBackSignal> {
        self.inner.subscribe(my_gateway_id)
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
