use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::{Bytes as WsBytes, Message};
use tokio_tungstenite::{client_async_with_config, WebSocketStream};

use crate::agent::stream::WsByteStream;
use crate::agent::wire::{self, FrameError, MsgType};
use crate::agent::{ws_config, PEER_RELAY_PATH, WIRE_PROTOCOL_MAX, WIRE_PROTOCOL_MIN};
use crate::cpauth::CredentialSnapshot;
use crate::ha::coordination::CoordinationBackend;
use crate::pbagent::AgentHello;
use crate::pbgw::DialBackSignal;
use crate::ssh::connector::{NodeConnector, NodeDial};
use crate::telemetry::metrics::{self, RelayDecline};

const DEFAULT_PER_NODE_RELAY_CAP: usize = 8;

pub struct ServedRelays {
    per_node: Mutex<HashMap<String, usize>>,
    active: AtomicUsize,
    per_node_cap: usize,
}

impl Default for ServedRelays {
    fn default() -> Self {
        Self::new(DEFAULT_PER_NODE_RELAY_CAP)
    }
}

impl ServedRelays {
    pub fn new(per_node_cap: usize) -> Self {
        Self {
            per_node: Mutex::new(HashMap::new()),
            active: AtomicUsize::new(0),
            per_node_cap: per_node_cap.max(1),
        }
    }

    pub fn begin(self: &Arc<Self>, node: &str) -> Option<RelaySlot> {
        let mut map = self.per_node.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(node.to_string()).or_insert(0);
        if *count >= self.per_node_cap {
            return None;
        }
        *count += 1;
        self.active.fetch_add(1, Ordering::SeqCst);
        Some(RelaySlot {
            registry: Arc::clone(self),
            node: node.to_string(),
        })
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

pub struct RelaySlot {
    registry: Arc<ServedRelays>,
    node: String,
}

impl Drop for RelaySlot {
    fn drop(&mut self) {
        let mut map = self
            .registry
            .per_node
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.node) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.node);
            }
        }
        self.registry.active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct PeerClientDeps {
    pub coordination: Arc<dyn CoordinationBackend>,
    pub self_gateway_id: String,
    pub local_connector: Arc<dyn NodeConnector>,
    pub registry: Arc<crate::agent::registry::AgentRegistry>,
    pub owner_cache: Arc<crate::ha::presence::OwnerCache>,
    pub served_relays: Arc<ServedRelays>,
    pub credential: watch::Receiver<CredentialSnapshot>,
    pub max_frame_bytes: usize,
    pub handshake_timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
enum RelayError {
    #[error("this gateway does not own the signalled node")]
    NotOwner,
    #[error("the signal's owner_nonce is older than the current ownership epoch (stale/replay)")]
    StaleNonce,
    #[error("at the per-node concurrent-relay cap")]
    PerNodeCap,
    #[error("the local agent dial-back failed")]
    LocalDial,
    #[error("the ingress relay endpoint could not be reached")]
    Connect,
    #[error("the ingress refused or did not complete the relay handshake")]
    Handshake,
    #[error("building the client TLS configuration failed")]
    Tls,
}

impl RelayError {
    fn decline(&self) -> RelayDecline {
        match self {
            RelayError::NotOwner => RelayDecline::NotOwner,
            RelayError::StaleNonce => RelayDecline::StaleNonce,
            RelayError::PerNodeCap => RelayDecline::PerNodeCap,
            RelayError::LocalDial => RelayDecline::LocalDial,
            RelayError::Connect => RelayDecline::Connect,
            RelayError::Handshake => RelayDecline::Handshake,
            RelayError::Tls => RelayDecline::Tls,
        }
    }
}

/// Subscribe synchronously before returning, so signals published before spawn complete don't drop.
pub fn spawn(deps: PeerClientDeps, shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
    let sub = deps.coordination.subscribe(&deps.self_gateway_id);
    tracing::info!(gateway = %deps.self_gateway_id, "peer-relay signal handler subscribed");
    tokio::spawn(run(deps, sub, shutdown))
}

async fn run(
    deps: PeerClientDeps,
    mut sub: futures_util::stream::BoxStream<'static, DialBackSignal>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        tokio::select! {
            biased;
            res = shutdown.changed() => {
                if res.is_err() {
                    return;
                }
            }
            signal = sub.next() => {
                match signal {
                    Some(signal) => {
                        let deps = deps.clone();
                        tokio::spawn(async move {
                            let node = signal.node_name.clone();
                            if let Err(e) = serve_relay(deps, signal).await {
                                tracing::info!(node = %node, reason = %e, "declined a dial-back signal (ingress will fail closed)");
                            }
                        });
                    }
                    None => return,
                }
            }
        }
    }
}

/// Counts every refusal in one place, so a new fail-closed branch below is counted by
/// construction rather than by remembering to.
async fn serve_relay(deps: PeerClientDeps, signal: DialBackSignal) -> Result<(), RelayError> {
    let result = serve_relay_inner(deps, signal).await;
    if let Err(e) = &result {
        metrics::peer_relay_declined(e.decline());
    }
    result
}

async fn serve_relay_inner(deps: PeerClientDeps, signal: DialBackSignal) -> Result<(), RelayError> {
    let observed = deps.owner_cache.get(&signal.node_name);
    let is_self_owner = observed
        .as_ref()
        .map(|o| o.owner_id == deps.self_gateway_id)
        .unwrap_or(false);
    if !is_self_owner {
        return Err(RelayError::NotOwner);
    }
    if let Some(o) = &observed {
        if signal.owner_nonce < o.nonce {
            return Err(RelayError::StaleNonce);
        }
    }
    if deps.registry.lookup(&signal.node_name).is_err() {
        return Err(RelayError::NotOwner);
    }

    let Some(_slot) = deps.served_relays.begin(&signal.node_name) else {
        return Err(RelayError::PerNodeCap);
    };

    let relay_ws = tokio::time::timeout(deps.handshake_timeout, open_relay(&deps, &signal))
        .await
        .map_err(|_| RelayError::Handshake)??;
    let mut relay_stream = WsByteStream::new(relay_ws.ws, relay_ws.ver, relay_ws.max_frame_bytes);

    let node_dial = NodeDial {
        node_id: signal.node_id.clone(),
        connector_kind: crate::pb::ConnectorKind::OutboundAgent as i32,
        node_name: signal.node_name.clone(),
        session_id: signal.session_id.clone(),
        principal: signal.principal.clone(),
        ..Default::default()
    };
    let mut node_stream = deps
        .local_connector
        .connect(&node_dial)
        .await
        .map_err(|_| RelayError::LocalDial)?;

    tracing::info!(node = %signal.node_name, peer = %signal.ingress_gateway_id, event = "peer_relay_serving", "serving a peer relay as owner");
    pump_relay(&mut node_stream, &mut relay_stream).await;
    tracing::info!(node = %signal.node_name, peer = %signal.ingress_gateway_id, event = "peer_relay_closed", "peer relay closed");
    Ok(())
}

/// The counted region of a served relay: nothing can leave it without closing the relay it
/// opened, so `served - closed` is a true in-flight count rather than two hopeful call sites.
async fn pump_relay<A, B>(node: &mut A, relay: &mut B)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    metrics::peer_relay_served();
    let _ = tokio::io::copy_bidirectional(node, relay).await;
    metrics::peer_relay_closed();
}

struct OpenRelay {
    ws: WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>,
    ver: u8,
    max_frame_bytes: usize,
}

struct Negotiated {
    ver: u8,
    max_frame_bytes: usize,
}

async fn open_relay(
    deps: &PeerClientDeps,
    signal: &DialBackSignal,
) -> Result<OpenRelay, RelayError> {
    let tls_config = client_tls_config(&deps.credential.borrow()).map_err(|_| RelayError::Tls)?;

    let tcp = TcpStream::connect(&signal.ingress_relay_addr)
        .await
        .map_err(|_| RelayError::Connect)?;
    let _ = tcp.set_nodelay(true);
    let server_name =
        ServerName::try_from(signal.ingress_gateway_id.clone()).map_err(|_| RelayError::Tls)?;
    let tls = TlsConnector::from(tls_config)
        .connect(server_name, tcp)
        .await
        .map_err(|_| RelayError::Connect)?;
    let url = format!("wss://{}{PEER_RELAY_PATH}", signal.ingress_gateway_id);
    let (mut ws, _resp) = client_async_with_config(url, tls, Some(ws_config(deps.max_frame_bytes)))
        .await
        .map_err(|_| RelayError::Connect)?;

    let negotiated = preface(&mut ws, deps.max_frame_bytes).await?;
    let ver = negotiated.ver;
    ws.send(Message::Binary(WsBytes::from(wire::encode_msg(
        ver,
        MsgType::RelayOpen,
        &crate::pbgw::RelayOpen {
            token: signal.relay_token.clone(),
        },
    ))))
    .await
    .map_err(|_| RelayError::Handshake)?;

    let frame = next_frame(&mut ws, deps.max_frame_bytes, ver).await?;
    match frame.msg_type {
        MsgType::RelayAccept => Ok(OpenRelay {
            ws,
            ver,
            max_frame_bytes: negotiated.max_frame_bytes,
        }),
        _ => Err(RelayError::Handshake),
    }
}

async fn preface<S>(
    ws: &mut WebSocketStream<S>,
    max_frame_bytes: usize,
) -> Result<Negotiated, RelayError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let hello = AgentHello {
        component: Some(crate::agent::wire_component_info()),
    };
    let ver = WIRE_PROTOCOL_MAX.0 as u8;
    ws.send(Message::Binary(WsBytes::from(wire::encode_msg(
        ver,
        MsgType::Hello,
        &hello,
    ))))
    .await
    .map_err(|_| RelayError::Handshake)?;

    loop {
        let msg = ws.next().await.ok_or(RelayError::Handshake)?;
        match msg.map_err(|_| RelayError::Handshake)? {
            Message::Binary(bytes) => {
                let ack_ver = *bytes.first().ok_or(RelayError::Handshake)?;
                let frame = wire::decode(bytes, max_frame_bytes, ack_ver)
                    .map_err(|_| RelayError::Handshake)?;
                if frame.msg_type != MsgType::HelloAck {
                    return Err(RelayError::Handshake);
                }
                if frame.ver < WIRE_PROTOCOL_MIN.0 as u8 || frame.ver > WIRE_PROTOCOL_MAX.0 as u8 {
                    return Err(RelayError::Handshake);
                }
                let ack: crate::pbagent::GatewayHelloAck =
                    wire::as_hello_ack(&frame).map_err(|_| RelayError::Handshake)?;
                let negotiated_frame = match ack.max_frame_bytes as usize {
                    0 => max_frame_bytes,
                    n => n.min(max_frame_bytes),
                };
                return Ok(Negotiated {
                    ver: frame.ver,
                    max_frame_bytes: negotiated_frame,
                });
            }
            Message::Ping(_) | Message::Pong(_) => {}
            _ => return Err(RelayError::Handshake),
        }
    }
}

async fn next_frame<S>(
    ws: &mut WebSocketStream<S>,
    max_frame_bytes: usize,
    ver: u8,
) -> Result<wire::Frame, RelayError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let msg = ws.next().await.ok_or(RelayError::Handshake)?;
        match msg.map_err(|_| RelayError::Handshake)? {
            Message::Binary(bytes) => {
                return wire::decode(bytes, max_frame_bytes, ver).map_err(|e: FrameError| {
                    tracing::debug!(error = %e, "relay frame decode failed");
                    RelayError::Handshake
                });
            }
            Message::Ping(_) | Message::Pong(_) => {}
            _ => return Err(RelayError::Handshake),
        }
    }
}

fn client_tls_config(cred: &CredentialSnapshot) -> Result<Arc<ClientConfig>, RelayError> {
    crate::tls::install_ring_provider();

    let mut roots = RootCertStore::empty();
    for der in &cred.ca_chain_der {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|_| RelayError::Tls)?;
    }
    if roots.is_empty() {
        return Err(RelayError::Tls);
    }

    let cert_chain: Vec<CertificateDer<'static>> = pem::parse_many(&cred.identity.cert_pem)
        .map_err(|_| RelayError::Tls)?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.into_contents()))
        .collect();
    if cert_chain.is_empty() {
        return Err(RelayError::Tls);
    }
    let key_pem = pem::parse(cred.identity.key_pem.as_bytes()).map_err(|_| RelayError::Tls)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pem.into_contents()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RelayError::Tls)?
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|_| RelayError::Tls)?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    use crate::agent::registry::AgentRegistry;
    use crate::cpauth::CredentialSnapshot;
    use crate::ha::coordination::InProcessBackend;
    use crate::ha::presence::OwnerCache;
    use crate::mtls::ClientIdentity;
    use crate::ssh::connector::{ByteStream, ConnectFuture, NodeConnectError};

    struct SpyConnector(Arc<AtomicBool>);
    impl NodeConnector for SpyConnector {
        fn connect<'a>(&'a self, _dial: &'a NodeDial) -> ConnectFuture<'a> {
            self.0.store(true, Ordering::SeqCst);
            Box::pin(async move {
                Err::<Box<dyn ByteStream>, NodeConnectError>(NodeConnectError::NoAgent)
            })
        }
    }

    fn dummy_credential() -> watch::Receiver<CredentialSnapshot> {
        let (tx, rx) = watch::channel(CredentialSnapshot {
            identity: ClientIdentity {
                cert_pem: Vec::new(),
                key_pem: zeroize::Zeroizing::new(String::new()),
            },
            ca_chain_der: Vec::new(),
        });
        std::mem::forget(tx);
        rx
    }

    #[tokio::test]
    async fn a_stale_nonce_is_dropped_while_still_owner_and_fires_no_node_dial() {
        let dialed = Arc::new(AtomicBool::new(false));

        // We hold a live control channel for web-01 (so the live-channel guard would pass - proving
        // the STALE-NONCE check, not the channel check, is what drops the signal).
        let registry = Arc::new(AgentRegistry::new(4));
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        std::mem::forget(rx);
        std::mem::forget(registry.register("web-01", "agent-b", tx).unwrap());

        let owner_cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
        owner_cache.observe("web-01", "gw-B", "gw-b:9444", 5);

        let deps = PeerClientDeps {
            coordination: Arc::new(InProcessBackend::new()),
            self_gateway_id: "gw-B".into(),
            local_connector: Arc::new(SpyConnector(dialed.clone())),
            registry,
            owner_cache,
            served_relays: Arc::new(ServedRelays::default()),
            credential: dummy_credential(),
            max_frame_bytes: 64 * 1024,
            handshake_timeout: Duration::from_secs(5),
        };

        let signal = DialBackSignal {
            node_id: "node-uuid".into(),
            node_name: "web-01".into(),
            session_id: "sess-1".into(),
            owner_gateway_id: "gw-B".into(),
            owner_nonce: 3,
            ..Default::default()
        };

        let err = serve_relay(deps, signal).await.unwrap_err();
        assert!(
            matches!(err, RelayError::StaleNonce),
            "an older-nonce signal is StaleNonce, got {err:?}"
        );
        assert!(
            !dialed.load(Ordering::SeqCst),
            "a stale-nonce signal must NOT trigger a local node dial-back"
        );
    }

    #[test]
    fn served_relays_caps_per_node_and_counts_active_for_drain() {
        let relays = Arc::new(ServedRelays::new(2));
        assert_eq!(relays.active(), 0);

        let a = relays.begin("web-01").expect("first slot");
        let b = relays.begin("web-01").expect("second slot");
        assert!(
            relays.begin("web-01").is_none(),
            "per-node cap refuses the third"
        );
        let c = relays
            .begin("web-02")
            .expect("other node has its own budget");
        assert_eq!(
            relays.active(),
            3,
            "the drain wait sees every in-flight relay"
        );

        drop(a);
        assert_eq!(relays.active(), 2);
        let _d = relays.begin("web-01").expect("a freed slot is reusable");
        assert_eq!(relays.active(), 3);

        drop(b);
        drop(c);
        drop(_d);
        assert_eq!(relays.active(), 0, "all relays drained");
    }

    #[tokio::test]
    async fn relay_counters_move_on_decline_and_on_a_served_relay() {
        use crate::telemetry::metrics::testutil::CounterProbe;
        use crate::telemetry::metrics::{
            ATTR_REASON, PEER_RELAYS_CLOSED, PEER_RELAYS_DECLINED, PEER_RELAYS_SERVED,
        };

        let probe = CounterProbe::install();
        let stale = [(ATTR_REASON, "stale_nonce")];
        let not_owner = [(ATTR_REASON, "not_owner")];
        assert_eq!(probe.read(PEER_RELAYS_DECLINED, &stale), None);
        assert_eq!(probe.read(PEER_RELAYS_SERVED, &[]), None);
        assert_eq!(probe.read(PEER_RELAYS_CLOSED, &[]), None);

        let registry = Arc::new(AgentRegistry::new(4));
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        std::mem::forget(rx);
        std::mem::forget(registry.register("web-01", "agent-b", tx).unwrap());
        let owner_cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
        owner_cache.observe("web-01", "gw-B", "gw-b:9444", 5);
        let deps = PeerClientDeps {
            coordination: Arc::new(InProcessBackend::new()),
            self_gateway_id: "gw-B".into(),
            local_connector: Arc::new(SpyConnector(Arc::new(AtomicBool::new(false)))),
            registry,
            owner_cache,
            served_relays: Arc::new(ServedRelays::default()),
            credential: dummy_credential(),
            max_frame_bytes: 64 * 1024,
            handshake_timeout: Duration::from_secs(5),
        };
        let stale_signal = DialBackSignal {
            node_name: "web-01".into(),
            owner_gateway_id: "gw-B".into(),
            owner_nonce: 3,
            ..Default::default()
        };
        serve_relay(deps.clone(), stale_signal).await.unwrap_err();
        assert_eq!(probe.read(PEER_RELAYS_DECLINED, &stale), Some(1));
        assert_eq!(
            probe.read(PEER_RELAYS_DECLINED, &not_owner),
            None,
            "the decline is credited to its own cause only"
        );

        let foreign = DialBackSignal {
            node_name: "web-99".into(),
            owner_gateway_id: "gw-B".into(),
            owner_nonce: 1,
            ..Default::default()
        };
        serve_relay(deps, foreign).await.unwrap_err();
        assert_eq!(probe.read(PEER_RELAYS_DECLINED, &not_owner), Some(1));

        let (mut node, mut node_peer) = tokio::io::duplex(64);
        let (mut relay, mut relay_peer) = tokio::io::duplex(64);
        let pump = tokio::spawn(async move { pump_relay(&mut node, &mut relay).await });
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            relay_peer.write_all(b"ping").await.unwrap();
            let mut got = [0u8; 4];
            node_peer.read_exact(&mut got).await.unwrap();
            assert_eq!(
                &got, b"ping",
                "the relay is a byte pump, not a counter stub"
            );
            assert_eq!(probe.read(PEER_RELAYS_SERVED, &[]), Some(1));
            assert_eq!(
                probe.read(PEER_RELAYS_CLOSED, &[]),
                None,
                "an in-flight relay is served but not yet closed"
            );
        }
        drop(node_peer);
        drop(relay_peer);
        pump.await.unwrap();
        assert_eq!(probe.read(PEER_RELAYS_CLOSED, &[]), Some(1));
        assert_eq!(probe.read(PEER_RELAYS_SERVED, &[]), Some(1));
    }
}
