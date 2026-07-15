//! The owner-side peer-relay client + signal handler (Session Fifteen; `gateway-relay-v1.md`
//! §5, FR-HA-4). This Gateway (gw-B) OWNS a node's agent control channel. When an ingress
//! (gw-A) publishes a [`DialBackSignal`](crate::pbgw::DialBackSignal) addressed to it, gw-B
//! produces the node byte stream **locally** (the S14 agent dial-back) and relays it to gw-A
//! over a direct TLS+WS connection.
//!
//! **gw-B is a dumb byte relay** — no inner leg, no recorder, no host verification. All of
//! that runs at the ingress (D21/D23 unchanged). gw-B only splices raw bytes between the
//! node stream and the relay socket.

use std::sync::Arc;
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
use crate::agent::{ws_config, PEER_RELAY_PATH};
use crate::cpauth::CredentialSnapshot;
use crate::ha::coordination::CoordinationBackend;
use crate::pbagent::AgentHello;
use crate::pbgw::DialBackSignal;
use crate::ssh::connector::{NodeConnector, NodeDial};

/// Everything the owner-side signal handler needs. Cheap to clone (all `Arc`).
#[derive(Clone)]
pub struct PeerClientDeps {
    /// The coordination bus (this Gateway subscribes to signals addressed to itself).
    pub coordination: Arc<dyn CoordinationBackend>,
    /// This Gateway's own NAME (the subscribe subject; the ingress addresses signals here).
    pub self_gateway_id: String,
    /// The LOCAL agent connector (S14 `AgentDial`) — produces the node byte stream.
    pub local_connector: Arc<dyn NodeConnector>,
    /// The live agent registry (verify this Gateway owns the node before serving).
    pub registry: Arc<crate::agent::registry::AgentRegistry>,
    /// The shared owner cache the heartbeat loop updates (R1 / FR-HA-5): the owner-side
    /// anti-stale guard checks it currently believes WE own the node before serving.
    pub owner_cache: Arc<crate::ha::presence::OwnerCache>,
    /// The renewing mTLS client credential (presented on the relay connection; its CA chain
    /// verifies the ingress's serverAuth leaf).
    pub credential: watch::Receiver<CredentialSnapshot>,
    /// The negotiated frame bound (must match the transport's).
    pub max_frame_bytes: usize,
    /// Bound on the whole relay handshake (TLS + WS + preface + RELAY_OPEN/ACCEPT).
    pub handshake_timeout: Duration,
}

/// A failure serving a relay for the ingress. Every variant is fail-closed: the owner drops
/// the attempt and the ingress times out ("node offline") — a relay is never forced.
#[derive(Debug, thiserror::Error)]
enum RelayError {
    #[error("this gateway does not own the signalled node")]
    NotOwner,
    #[error("the local agent dial-back failed")]
    LocalDial,
    #[error("the ingress relay endpoint could not be reached")]
    Connect,
    #[error("the ingress refused or did not complete the relay handshake")]
    Handshake,
    #[error("building the client TLS configuration failed")]
    Tls,
}

/// Spawn the signal-handler loop. It serves each inbound relay on its own task, until
/// `shutdown` flips true.
///
/// The subscription is established **synchronously here**, before this returns, so the owner is
/// on the bus before any ingress can publish to it — closing the startup window where an early
/// `DialBackSignal` would be dropped (core NATS / in-process broadcast deliver only to CURRENT
/// subscribers; a message published before subscribe is lost).
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
                                // Fail closed silently for the ingress (it times out); log for us.
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

async fn serve_relay(deps: PeerClientDeps, signal: DialBackSignal) -> Result<(), RelayError> {
    // (1a) Anti-stale ownership recheck (R1 / FR-HA-5). The SLGW1 `owner_nonce` is minted by the
    // INGRESS from its own Authorize, so an ingress-side compare is self-referential — it cannot
    // catch ownership migrating away from us between Authorize and relay. So the owner refuses
    // to serve unless its OWN heartbeat loop currently believes it owns the node (the OwnerCache
    // reflects the last Presence.Heartbeat: is_self_owner). A superseded owner refuses ⇒ the
    // ingress fails closed within relay_timeout ⇒ the client re-routes to the true owner.
    let is_self_owner = deps
        .owner_cache
        .get(&signal.node_name)
        .map(|o| o.owner_id == deps.self_gateway_id)
        .unwrap_or(false);
    if !is_self_owner {
        return Err(RelayError::NotOwner);
    }
    // (1b) …and we must still hold a LIVE agent control channel to the node (the backstop for a
    // truly-dead owner — a gateway without the channel cannot reach the node regardless of any
    // cache). Both guards must hold.
    if deps.registry.lookup(&signal.node_name).is_err() {
        return Err(RelayError::NotOwner);
    }

    // (2) Produce the node byte stream locally (the S14 agent dial-back mints its OWN SLDB1
    // token and splices to the node's loopback sshd — full reuse, no confused deputy).
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

    // (3)(4) Dial the ingress relay endpoint (TLS+WS), preface, present the token, await
    // RELAY_ACCEPT — all bounded so a stalled ingress never parks the node stream.
    let relay_ws = tokio::time::timeout(deps.handshake_timeout, open_relay(&deps, &signal))
        .await
        .map_err(|_| RelayError::Handshake)??;
    let mut relay_stream = WsByteStream::new(relay_ws.ws, relay_ws.ver, deps.max_frame_bytes);

    // (5) Dumb bidirectional copy: node ByteStream ↔ peer-relay STREAM_DATA frames. No inner
    // leg, no recorder — the ingress owns the session + recording.
    let _ = tokio::io::copy_bidirectional(&mut node_stream, &mut relay_stream).await;
    Ok(())
}

/// An established, accepted relay connection to the ingress.
struct OpenRelay {
    ws: WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>,
    ver: u8,
}

async fn open_relay(
    deps: &PeerClientDeps,
    signal: &DialBackSignal,
) -> Result<OpenRelay, RelayError> {
    let tls_config = client_tls_config(&deps.credential.borrow()).map_err(|_| RelayError::Tls)?;

    // TCP → TLS (SNI = the ingress NAME, verified against the internal CA) → WS.
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

    // Preface: HELLO → HELLO_ACK (reuse the shared negotiation); then RELAY_OPEN → RELAY_ACCEPT.
    let ver = preface(&mut ws, deps.max_frame_bytes).await?;
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
        MsgType::RelayAccept => Ok(OpenRelay { ws, ver }),
        // RELAY_REJECT or anything else ⇒ fail closed (the ingress refused the binding).
        _ => Err(RelayError::Handshake),
    }
}

/// Client-side preface: send `HELLO` with our wire component info, read `HELLO_ACK`, return
/// the negotiated wire major. A `VERSION_REJECT` or any other frame fails closed.
async fn preface<S>(ws: &mut WebSocketStream<S>, max_frame_bytes: usize) -> Result<u8, RelayError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let hello = AgentHello {
        component: Some(crate::agent::wire_component_info()),
    };
    let ver = crate::agent::WIRE_PROTOCOL_MAX.0 as u8;
    ws.send(Message::Binary(WsBytes::from(wire::encode_msg(
        ver,
        MsgType::Hello,
        &hello,
    ))))
    .await
    .map_err(|_| RelayError::Handshake)?;

    // The HELLO_ACK carries the negotiated major in its VER byte.
    loop {
        let msg = ws.next().await.ok_or(RelayError::Handshake)?;
        match msg.map_err(|_| RelayError::Handshake)? {
            Message::Binary(bytes) => {
                let ack_ver = *bytes.first().ok_or(RelayError::Handshake)?;
                let frame = wire::decode(bytes, max_frame_bytes, ack_ver)
                    .map_err(|_| RelayError::Handshake)?;
                return match frame.msg_type {
                    MsgType::HelloAck => Ok(frame.ver),
                    _ => Err(RelayError::Handshake), // VERSION_REJECT / anything else: fail closed
                };
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

/// Build the client TLS config from the current credential: present our mTLS client identity,
/// verify the ingress serverAuth leaf against the pinned internal CA, TLS 1.3 only.
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
