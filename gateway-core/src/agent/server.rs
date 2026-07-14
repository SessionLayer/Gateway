//! The agent-facing WSS server (contract §1/§3/§5/§7) — the Gateway's only TLS
//! **server**.
//!
//! One listener, two connection roles distinguished by request path: a long-lived
//! `/agent/v1/control` channel per Agent, and one `/agent/v1/dialback` connection per
//! session. Both require a client certificate chaining to the **internal mTLS CA**
//! (the S12 agent identity); the peer is resolved from its SANs, never from anything
//! it asserts on the wire. A peer covered by a **Lock** is refused at registration and
//! again at every dial-back — deny wins (§8.4).
//!
//! The Gateway's own leaf is a **serverAuth** certificate from
//! `GatewayIdentity.IssueGatewayServerCertificate`, over a keypair generated here and
//! never persisted (key separation from the client identity; the CP chooses the SANs).
//! There is no TOFU on this path either: the Agent verifies it against the same CA it
//! already holds.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::{Bytes as WsBytes, Message};
use tokio_tungstenite::{accept_hdr_async_with_config, WebSocketStream};
use zeroize::Zeroizing;

use crate::agent::registry::{AgentRegistry, ControlOut, RegistryError};
use crate::agent::stream::WsByteStream;
use crate::agent::token::{now_epoch_secs, DialBackSigner, PendingDialBacks, TokenError};
use crate::agent::wire::{self, Frame, FrameError, MsgType};
use crate::agent::{peer_identity, AgentPeer, PeerError, CONTROL_PATH, DIALBACK_PATH};
use crate::config::AgentTransportConfig;
use crate::cpauth::CpAuthClient;
use crate::identity;
use crate::pb::ComponentInfo;
use crate::pbagent::{
    GatewayHelloAck, Ping, StreamOpen, VersionReject, WireErrorCode,
};
use crate::ssh::locks::{LockBindings, LockSet};
use crate::version;

/// The connection kind, decided by the WebSocket request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Control,
    DialBack,
}

/// A failure standing up the agent transport (fail-closed at startup).
#[derive(Debug, thiserror::Error)]
pub enum AgentTransportError {
    /// The listen address could not be bound.
    #[error("agent transport I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The Gateway could not obtain its serverAuth leaf from the CP. Without it the
    /// transport does not start — an Agent must be able to verify this Gateway.
    #[error("could not obtain the agent-facing server certificate from the Control Plane")]
    ServerCertificate,
    /// The rustls server configuration could not be built (bad CA anchors / leaf).
    #[error("agent transport TLS configuration is invalid: {0}")]
    Tls(String),
}

/// Everything the transport needs from the rest of the Gateway.
#[derive(Clone)]
pub struct AgentTransportDeps {
    /// The CP client — the pinned internal mTLS CA chain (the client-cert trust
    /// anchors) and the serverAuth-leaf RPC.
    pub cpauth: Arc<CpAuthClient>,
    /// This Gateway's CP-assigned id (bound into every dial-back token).
    pub gateway_id: String,
    /// This Gateway's enrolled name (the CSR subject; the CP stamps the real SANs).
    pub gateway_name: String,
    /// The live `node_name -> control channel` registry.
    pub registry: Arc<AgentRegistry>,
    /// The single-use dial-back ledger.
    pub pending: Arc<PendingDialBacks>,
    /// This process's dial-back signing key.
    pub signer: Arc<DialBackSigner>,
    /// The actively-pushed lock deny-set (§8.4) — consulted at registration and at
    /// every dial-back.
    pub lock_set: Arc<LockSet>,
    /// Transport bounds.
    pub config: AgentTransportConfig,
}

struct Inner {
    deps: AgentTransportDeps,
    tls: watch::Receiver<Arc<ServerConfig>>,
    handshake_timeout: Duration,
    heartbeat: Duration,
    max_frame_bytes: usize,
}

/// A bound, ready-to-run agent transport.
pub struct BoundAgentTransport {
    listener: TcpListener,
    local_addr: SocketAddr,
    inner: Arc<Inner>,
}

impl BoundAgentTransport {
    /// The address the transport is listening on (useful when bound to port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept agent connections until `shutdown` resolves.
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()>) {
        let inner = self.inner;
        tokio::pin!(shutdown);
        tracing::info!(addr = %self.local_addr, "agent transport listening");
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    tracing::info!("agent transport shutting down");
                    return;
                }
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((tcp, peer)) => {
                            let inner = inner.clone();
                            tokio::spawn(async move {
                                // The whole TLS + WS + preface handshake is bounded, so
                                // a peer that connects and stalls cannot hold a slot.
                                let bound = tokio::time::timeout(
                                    inner.handshake_timeout,
                                    accept_agent(inner.clone(), tcp),
                                ).await;
                                match bound {
                                    Ok(Ok(())) => {}
                                    Ok(Err(e)) => tracing::info!(peer = %peer, error = %e, "agent connection refused"),
                                    Err(_) => tracing::info!(peer = %peer, "agent handshake timed out"),
                                }
                            });
                        }
                        Err(e) => tracing::warn!(error = %e, "agent transport accept failed"),
                    }
                }
            }
        }
    }
}

/// Bind the agent transport: obtain the serverAuth leaf from the CP (fail closed if
/// the CP will not issue one), build the TLS 1.3 / client-cert-required server config,
/// and start the reissue + pending-GC background tasks.
pub async fn bind(
    deps: AgentTransportDeps,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<BoundAgentTransport, AgentTransportError> {
    crate::tls::install_ring_provider();

    let issued = issue_server_config(&deps).await?;
    let (tls_tx, tls_rx) = watch::channel(issued.config);
    spawn_server_cert_renewal(deps.clone(), tls_tx, issued.not_after, shutdown.clone());
    spawn_pending_gc(deps.pending.clone(), shutdown);

    let listener = TcpListener::bind(&deps.config.listen_addr).await?;
    let local_addr = listener.local_addr()?;

    let inner = Arc::new(Inner {
        handshake_timeout: Duration::from_secs(deps.config.handshake_timeout_secs),
        heartbeat: Duration::from_secs(deps.config.heartbeat_interval_secs),
        max_frame_bytes: deps.config.max_frame_bytes,
        tls: tls_rx,
        deps,
    });

    Ok(BoundAgentTransport {
        listener,
        local_addr,
        inner,
    })
}

/// The `wss://` URL an Agent is told to dial back to. Configured explicitly in a real
/// deployment (the Gateway is usually behind an LB); derived from the listener
/// otherwise.
pub fn advertise_url(config: &AgentTransportConfig, local_addr: SocketAddr) -> String {
    if !config.advertise_url.is_empty() {
        return config.advertise_url.clone();
    }
    format!("wss://{local_addr}")
}

// ---- server certificate -------------------------------------------------------

struct IssuedServerConfig {
    config: Arc<ServerConfig>,
    not_before: std::time::SystemTime,
    not_after: std::time::SystemTime,
}

/// Obtain a fresh serverAuth leaf from the CP over a **separate, locally-generated**
/// keypair (D2: only the CSR leaves; the key never touches disk) and build the TLS
/// server config around it.
async fn issue_server_config(
    deps: &AgentTransportDeps,
) -> Result<IssuedServerConfig, AgentTransportError> {
    let kc = identity::generate_keypair_and_csr(&deps.gateway_name)
        .map_err(|_| AgentTransportError::ServerCertificate)?;
    let issued = deps
        .cpauth
        .issue_gateway_server_certificate(kc.csr_der.clone())
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Control Plane refused the agent-facing server certificate");
            AgentTransportError::ServerCertificate
        })?;

    let (not_before, not_after) = identity::validated_window(
        issued.not_before_epoch_seconds,
        issued.not_after_epoch_seconds,
    )
    .map_err(|_| AgentTransportError::ServerCertificate)?;

    // The client-cert trust anchors are the SAME internal mTLS CA the Gateway already
    // pins for the CP channel — no new trust distribution, and renewal-aware.
    let anchors = deps.cpauth.current_ca_chain();
    let config = server_config(
        issued.certificate,
        issued.ca_chain,
        kc.key_pkcs8_der,
        &anchors,
    )?;
    tracing::info!(
        gateway_name = %issued.gateway_name,
        "obtained the agent-facing serverAuth certificate"
    );
    Ok(IssuedServerConfig {
        config,
        not_before,
        not_after,
    })
}

fn server_config(
    leaf_der: Vec<u8>,
    chain_der: Vec<Vec<u8>>,
    key_pkcs8_der: Zeroizing<Vec<u8>>,
    client_ca_anchors: &[Vec<u8>],
) -> Result<Arc<ServerConfig>, AgentTransportError> {
    let mut roots = RootCertStore::empty();
    for der in client_ca_anchors {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| AgentTransportError::Tls(format!("client CA anchor: {e}")))?;
    }
    if roots.is_empty() {
        return Err(AgentTransportError::Tls(
            "no internal mTLS CA anchors: an agent's client certificate could not be verified"
                .to_string(),
        ));
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // Client certificate REQUIRED: neither role is reachable without the S12 identity.
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| AgentTransportError::Tls(format!("client verifier: {e}")))?;

    let mut certs = vec![CertificateDer::from(leaf_der)];
    certs.extend(chain_der.into_iter().map(CertificateDer::from));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8_der.to_vec()));

    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| AgentTransportError::Tls(format!("TLS 1.3 only: {e}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| AgentTransportError::Tls(format!("server leaf: {e}")))?;
    Ok(Arc::new(config))
}

/// Re-issue the serverAuth leaf at a TTL fraction. A failure keeps serving the
/// current (still-valid) certificate and retries — never a silent downgrade.
fn spawn_server_cert_renewal(
    deps: AgentTransportDeps,
    tx: watch::Sender<Arc<ServerConfig>>,
    mut not_after: std::time::SystemTime,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut not_before = std::time::SystemTime::now();
        loop {
            let delay = identity::reissue_delay(std::time::SystemTime::now(), not_before, not_after);
            tokio::select! {
                biased;
                _ = shutdown.wait_for(|v| *v) => return,
                _ = tokio::time::sleep(delay) => {}
            }
            match issue_server_config(&deps).await {
                Ok(issued) => {
                    not_before = issued.not_before;
                    not_after = issued.not_after;
                    let _ = tx.send(issued.config);
                    tracing::info!("re-issued the agent-facing server certificate");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "server-certificate re-issue failed; keeping the current certificate");
                    tokio::select! {
                        biased;
                        _ = shutdown.wait_for(|v| *v) => return,
                        _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    }
                }
            }
        }
    });
}

/// Drop pending dial-backs whose token expired (a signalled Agent that never dialled
/// back), so the ledger cannot grow without bound.
fn spawn_pending_gc(
    pending: Arc<PendingDialBacks>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.wait_for(|v| *v) => return,
                _ = tokio::time::sleep(Duration::from_secs(5)) => pending.gc(now_epoch_secs()),
            }
        }
    });
}

// ---- connection handling ------------------------------------------------------

/// Why an agent connection was refused. Reported to the peer as a coarse code only
/// (§7.1 non-disclosure); the specific reason stays in the operator log.
#[derive(Debug, thiserror::Error)]
enum ConnError {
    #[error("TLS handshake failed: {0}")]
    Tls(std::io::Error),
    #[error("peer identity: {0}")]
    Peer(#[from] PeerError),
    #[error("websocket handshake failed: {0}")]
    Handshake(tokio_tungstenite::tungstenite::Error),
    #[error("unknown request path")]
    UnknownPath,
    #[error("protocol: {0}")]
    Frame(#[from] FrameError),
    #[error("no common protocol version")]
    NoCommonVersion,
    #[error("connection closed before the preface completed")]
    Closed,
    #[error("registry: {0}")]
    Registry(#[from] RegistryError),
    #[error("dial-back token: {0}")]
    Token(#[from] TokenError),
    #[error("agent is covered by a lock")]
    Locked,
}

impl ConnError {
    /// The coarse code the peer is told. Never says whether a node, session, or
    /// identity exists.
    fn code(&self) -> WireErrorCode {
        match self {
            ConnError::Token(_) | ConnError::Locked | ConnError::Peer(_) => {
                WireErrorCode::Unauthorized
            }
            ConnError::Registry(_) => WireErrorCode::Unavailable,
            _ => WireErrorCode::Protocol,
        }
    }
}

async fn accept_agent(inner: Arc<Inner>, tcp: TcpStream) -> Result<(), ConnError> {
    let _ = tcp.set_nodelay(true);
    let acceptor = TlsAcceptor::from(inner.tls.borrow().clone());
    let tls = acceptor.accept(tcp).await.map_err(ConnError::Tls)?;

    // The verifier already required a client certificate; resolve the peer from its
    // CP-stamped SANs (nothing on the wire can assert an identity).
    let peer = {
        let (_, conn) = tls.get_ref();
        let certs = conn.peer_certificates().ok_or(PeerError::NoCertificate)?;
        let leaf = certs.first().ok_or(PeerError::NoCertificate)?;
        peer_identity(leaf.as_ref())?
    };

    // Deny wins (§8.4): a locked agent identity cannot register — and, re-checked
    // below, cannot redeem a dial-back either.
    refuse_if_locked(&inner, &peer)?;

    let mut role = None;
    let ws = accept_hdr_async_with_config(
        tls,
        |req: &Request, resp: Response| match req.uri().path() {
            CONTROL_PATH => {
                role = Some(Role::Control);
                Ok(resp)
            }
            DIALBACK_PATH => {
                role = Some(Role::DialBack);
                Ok(resp)
            }
            _ => Err(ErrorResponse::new(None)),
        },
        Some(crate::agent::ws_config(inner.max_frame_bytes)),
    )
    .await
    .map_err(ConnError::Handshake)?;
    let role = role.ok_or(ConnError::UnknownPath)?;

    let mut ws = ws;
    let ver = match preface(&mut ws, &inner).await {
        Ok(ver) => ver,
        Err(e) => {
            let _ = send_error(&mut ws, version::PROTOCOL_MAX.0 as u8, &e).await;
            return Err(e);
        }
    };

    let outcome = match role {
        Role::Control => run_control(ws, inner, peer, ver).await,
        Role::DialBack => run_dial_back(ws, inner, peer, ver).await,
    };
    outcome
}

fn refuse_if_locked(inner: &Inner, peer: &AgentPeer) -> Result<(), ConnError> {
    let bindings = LockBindings::for_agent(&peer.agent_id, &peer.node_name);
    if let Some(lock) = inner.deps.lock_set.matching(&bindings) {
        tracing::warn!(
            agent_id = %sanitize(&peer.agent_id),
            node = %sanitize(&peer.node_name),
            lock_id = %sanitize(&lock.lock_id),
            "refusing a locked agent (deny wins)"
        );
        return Err(ConnError::Locked);
    }
    Ok(())
}

/// The connection preface (contract §3): the Agent's `HELLO`, then either a
/// `HELLO_ACK` fixing the negotiated bounds or a `VERSION_REJECT` and close.
async fn preface<S>(ws: &mut WebSocketStream<S>, inner: &Inner) -> Result<u8, ConnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let frame = next_frame_any_version(ws, inner.max_frame_bytes).await?;
    if frame.msg_type != MsgType::Hello {
        return Err(ConnError::Frame(FrameError::UnknownType));
    }
    let hello = wire::as_hello(&frame)?;
    let client = hello.component.unwrap_or_default();

    let Some(selected) = negotiate(&client) else {
        let reject = VersionReject {
            gateway_min: Some(version::protocol_version(version::PROTOCOL_MIN)),
            gateway_max: Some(version::protocol_version(version::PROTOCOL_MAX)),
        };
        let payload = wire::encode_msg(
            version::PROTOCOL_MAX.0 as u8,
            MsgType::VersionReject,
            &reject,
        );
        let _ = ws.send(Message::Binary(WsBytes::from(payload))).await;
        let _ = ws.close(None).await;
        return Err(ConnError::NoCommonVersion);
    };

    let ver = selected.0 as u8;
    let ack = GatewayHelloAck {
        component: Some(version::component_info()),
        selected: Some(version::protocol_version(selected)),
        heartbeat_interval_secs: inner.deps.config.heartbeat_interval_secs as u32,
        max_frame_bytes: inner.max_frame_bytes as u32,
    };
    ws.send(Message::Binary(WsBytes::from(wire::encode_msg(
        ver,
        MsgType::HelloAck,
        &ack,
    ))))
    .await
    .map_err(ConnError::Handshake)?;
    Ok(ver)
}

/// Resolve the highest common protocol version, reusing the CP-plane N-1 resolver
/// (VERSIONING §3). No overlap ⇒ fail closed (FR-HA-9).
fn negotiate(client: &ComponentInfo) -> Option<(u32, u32)> {
    let min = client.protocol_min.as_ref().map(|v| (v.major, v.minor))?;
    let max = client.protocol_max.as_ref().map(|v| (v.major, v.minor))?;
    if min.0 != max.0 {
        return None; // a range must never straddle majors (VERSIONING §3)
    }
    version::resolve_common_version(
        version::PROTOCOL_MIN,
        version::PROTOCOL_MAX,
        min,
        max,
    )
}

// ---- control role -------------------------------------------------------------

async fn run_control<S>(
    mut ws: WebSocketStream<S>,
    inner: Arc<Inner>,
    peer: AgentPeer,
    ver: u8,
) -> Result<(), ConnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (tx, mut rx) = mpsc::channel::<ControlOut>(16);
    let registration = match inner.deps.registry.register(&peer.node_name, &peer.agent_id, tx) {
        Ok(r) => r,
        Err(e) => {
            let err = ConnError::Registry(e);
            let _ = send_error(&mut ws, ver, &err).await;
            return Err(err);
        }
    };
    tracing::info!(
        agent_id = %sanitize(&peer.agent_id),
        node = %sanitize(&peer.node_name),
        "agent control channel registered"
    );

    let mut ticker = tokio::time::interval(inner.heartbeat);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // the first tick is immediate
    let mut unanswered_pings = 0u32;
    let mut nonce = 0u64;

    let outcome = loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Two missed intervals ⇒ the peer is dead (contract §7).
                if unanswered_pings >= 2 {
                    tracing::info!(agent_id = %sanitize(&peer.agent_id), node = %sanitize(&peer.node_name), "agent missed two heartbeats; deregistering (node becomes unreachable)");
                    break Ok(());
                }
                // A lock pushed after registration must not leave the channel live.
                if refuse_if_locked(&inner, &peer).is_err() {
                    let _ = send_error(&mut ws, ver, &ConnError::Locked).await;
                    break Err(ConnError::Locked);
                }
                nonce = nonce.wrapping_add(1);
                let ping = wire::encode_msg(ver, MsgType::Ping, &Ping { nonce });
                if ws.send(Message::Binary(WsBytes::from(ping))).await.is_err() {
                    break Ok(());
                }
                unanswered_pings += 1;
            }
            out = rx.recv() => {
                match out {
                    Some(ControlOut::DialBack(req)) => {
                        let frame = wire::encode_msg(ver, MsgType::DialBackRequest, req.as_ref());
                        if ws.send(Message::Binary(WsBytes::from(frame))).await.is_err() {
                            break Ok(());
                        }
                    }
                    Some(ControlOut::Superseded) => {
                        tracing::info!(node = %sanitize(&peer.node_name), "control channel superseded by a newer connection");
                        break Ok(());
                    }
                    None => break Ok(()),
                }
            }
            msg = ws.next() => {
                let Some(msg) = msg else { break Ok(()) };
                let frame = match to_frame(msg, inner.max_frame_bytes, ver) {
                    Ok(Some(f)) => f,
                    Ok(None) => continue,            // a WebSocket control frame
                    Err(ConnError::Closed) => break Ok(()),
                    Err(e) => {
                        let _ = send_error(&mut ws, ver, &e).await;
                        break Err(e);
                    }
                };
                match frame.msg_type {
                    MsgType::Pong => {
                        if wire::as_pong(&frame).map(|p| p.nonce) == Ok(nonce) {
                            unanswered_pings = 0;
                        }
                    }
                    MsgType::DialBackResult => {
                        let result = wire::as_dial_back_result(&frame)?;
                        if !result.accepted {
                            // Fast-fail: drop the pending entry now rather than making
                            // the session wait out the dial-back deadline. The token
                            // stops being redeemable at the same instant.
                            tracing::info!(node = %sanitize(&peer.node_name), error = result.error, "agent refused a dial-back (fast-fail)");
                            inner.deps.pending.fail_request(&result.request_id);
                        }
                    }
                    MsgType::Ping => {
                        let nonce = wire::as_ping(&frame)?.nonce;
                        let pong = wire::encode_msg(ver, MsgType::Pong, &crate::pbagent::Pong { nonce });
                        if ws.send(Message::Binary(WsBytes::from(pong))).await.is_err() {
                            break Ok(());
                        }
                    }
                    MsgType::Error => {
                        // Peer-supplied text is untrusted: log it escaped, never
                        // interpolate it into an error chain (contract §8).
                        let err = wire::as_wire_error(&frame)?;
                        tracing::info!(agent_id = %sanitize(&peer.agent_id), code = err.code, message = %sanitize(&err.message), "agent reported a wire error");
                        break Ok(());
                    }
                    _ => {
                        let e = ConnError::Frame(FrameError::UnknownType);
                        let _ = send_error(&mut ws, ver, &e).await;
                        break Err(e);
                    }
                }
            }
        }
    };

    drop(registration); // the node is now offline until the Agent reconnects
    let _ = ws.close(None).await;
    outcome
}

// ---- dial-back role -----------------------------------------------------------

async fn run_dial_back<S>(
    mut ws: WebSocketStream<S>,
    inner: Arc<Inner>,
    peer: AgentPeer,
    ver: u8,
) -> Result<(), ConnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ready = match authorize_dial_back(&mut ws, &inner, &peer, ver).await {
        Ok(ready) => ready,
        Err(e) => {
            // Any failure ⇒ ERROR(UNAUTHORIZED) + close. The specific reason goes to
            // the operator log ONLY, and the token itself is never echoed.
            tracing::warn!(
                agent_id = %sanitize(&peer.agent_id),
                node = %sanitize(&peer.node_name),
                reason = %e,
                "dial-back refused (fail closed)"
            );
            let _ = send_error(&mut ws, ver, &e).await;
            let _ = ws.close(None).await;
            return Err(e);
        }
    };

    // The stream is handed to the inner leg ONLY after STREAM_OPEN — i.e. only once
    // the Agent's loopback splice is actually live, never before.
    let frame = next_frame(&mut ws, inner.max_frame_bytes, ver).await?;
    if frame.msg_type != MsgType::StreamOpen {
        let e = ConnError::Frame(FrameError::UnknownType);
        let _ = send_error(&mut ws, ver, &e).await;
        return Err(e);
    }
    let _: StreamOpen = wire::as_stream_open(&frame)?;

    let stream = WsByteStream::new(ws, ver, inner.max_frame_bytes);
    if ready.send(Box::new(stream)).is_err() {
        // The connector gave up (its deadline elapsed) — drop the splice.
        tracing::info!(node = %sanitize(&peer.node_name), "dial-back arrived after the connector gave up; dropping");
    }
    Ok(())
}

/// Contract §6: accept the dial-back only if ALL seven checks hold.
async fn authorize_dial_back<S>(
    ws: &mut WebSocketStream<S>,
    inner: &Inner,
    peer: &AgentPeer,
    ver: u8,
) -> Result<tokio::sync::oneshot::Sender<Box<dyn crate::ssh::connector::ByteStream>>, ConnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let frame = next_frame(ws, inner.max_frame_bytes, ver).await?;
    if frame.msg_type != MsgType::DialBackAuth {
        return Err(ConnError::Frame(FrameError::UnknownType));
    }
    let auth = wire::as_dial_back_auth(&frame)?;

    // (1)(2)(3) Envelope + signature over the transmitted bytes + this process's
    // signer + this Gateway + the validity window. Verify-then-decode.
    let payload = inner
        .deps
        .signer
        .verify(&auth.token, &inner.deps.gateway_id, now_epoch_secs())?;

    // (5) The connection's mTLS identity IS the agent the token was issued to, and
    // that agent owns the node. A token captured by a different Agent — even a valid,
    // unlocked one — is worthless to it.
    if payload.agent_id != peer.agent_id
        || payload.node_name != peer.node_name
        || !inner
            .deps
            .registry
            .owns(&peer.agent_id, &payload.node_name)
    {
        return Err(ConnError::Token(TokenError::WrongAgent));
    }

    // (7) Not locked — re-checked here, not just at registration.
    refuse_if_locked(inner, peer)?;

    // (4)(6) The jti is pending — and removing it IS consumption — and the pending
    // entry's {node, session, principal, agent} equal the payload's. Consumed LAST so
    // a rogue presentation cannot burn a legitimate agent's token.
    let ready = inner.deps.pending.consume(&payload)?;

    ws.send(Message::Binary(WsBytes::from(wire::encode_msg(
        ver,
        MsgType::DialBackAccept,
        &crate::pbagent::DialBackAccept {},
    ))))
    .await
    .map_err(ConnError::Handshake)?;
    Ok(ready)
}

// ---- frame plumbing -----------------------------------------------------------

/// Convert one WebSocket message to a frame. `Ok(None)` is a WebSocket control frame
/// (ping/pong) that tungstenite handles itself.
fn to_frame(
    msg: Result<Message, tokio_tungstenite::tungstenite::Error>,
    max_frame_bytes: usize,
    ver: u8,
) -> Result<Option<Frame>, ConnError> {
    match msg.map_err(ConnError::Handshake)? {
        Message::Binary(bytes) => Ok(Some(wire::decode(
            bytes::Bytes::copy_from_slice(&bytes),
            max_frame_bytes,
            ver,
        )?)),
        Message::Ping(_) | Message::Pong(_) => Ok(None),
        Message::Close(_) => Err(ConnError::Closed),
        Message::Text(_) => Err(ConnError::Frame(FrameError::NotBinary)),
        Message::Frame(_) => Err(ConnError::Frame(FrameError::UnknownType)),
    }
}

async fn next_frame<S>(
    ws: &mut WebSocketStream<S>,
    max_frame_bytes: usize,
    ver: u8,
) -> Result<Frame, ConnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let msg = ws.next().await.ok_or(ConnError::Closed)?;
        if let Some(frame) = to_frame(msg, max_frame_bytes, ver)? {
            return Ok(frame);
        }
    }
}

/// Read the preface `HELLO`, which carries the **sender's** protocol major in `VER`
/// (contract §3) — so the version check cannot be applied yet.
async fn next_frame_any_version<S>(
    ws: &mut WebSocketStream<S>,
    max_frame_bytes: usize,
) -> Result<Frame, ConnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let msg = ws.next().await.ok_or(ConnError::Closed)?;
        match msg.map_err(ConnError::Handshake)? {
            Message::Binary(bytes) => {
                let bytes = bytes::Bytes::copy_from_slice(&bytes);
                let ver = *bytes.first().ok_or(ConnError::Frame(FrameError::Short))?;
                return Ok(wire::decode(bytes, max_frame_bytes, ver)?);
            }
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => return Err(ConnError::Closed),
            Message::Text(_) => return Err(ConnError::Frame(FrameError::NotBinary)),
            Message::Frame(_) => return Err(ConnError::Frame(FrameError::UnknownType)),
        }
    }
}

/// Send a coarse `WireError` (§7.1 non-disclosure: the peer learns the class, never
/// which check failed or whether anything exists).
async fn send_error<S>(
    ws: &mut WebSocketStream<S>,
    ver: u8,
    err: &ConnError,
) -> Result<(), tokio_tungstenite::tungstenite::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let code = err.code();
    let message = match code {
        WireErrorCode::Unauthorized => "unauthorized",
        WireErrorCode::Unavailable => "unavailable",
        _ => "protocol error",
    };
    let payload = wire::encode_error(ver, code, message);
    ws.send(Message::Binary(WsBytes::from(payload))).await
}

/// Strip control/ANSI characters from untrusted peer-supplied text before it reaches
/// a log sink (log-injection / terminal-escape guard).
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::ProtocolVersion;

    fn info(min: (u32, u32), max: (u32, u32)) -> ComponentInfo {
        ComponentInfo {
            name: "SessionLayer Agent".into(),
            semver: "0.1.0".into(),
            protocol_min: Some(ProtocolVersion {
                major: min.0,
                minor: min.1,
            }),
            protocol_max: Some(ProtocolVersion {
                major: max.0,
                minor: max.1,
            }),
        }
    }

    #[test]
    fn negotiation_picks_the_highest_common_version() {
        // Baseline: both ship 1.0-1.1 today.
        assert_eq!(negotiate(&info((1, 0), (1, 1))), Some((1, 1)));
        // N-1: a 1.0-only Agent still connects.
        assert_eq!(negotiate(&info((1, 0), (1, 0))), Some((1, 0)));
    }

    #[test]
    fn no_common_version_fails_closed() {
        // A different major has no overlap → VERSION_REJECT, never a guess.
        assert_eq!(negotiate(&info((2, 0), (2, 0))), None);
        // A range that straddles majors is malformed.
        assert_eq!(negotiate(&info((1, 0), (2, 0))), None);
        // A HELLO with no version range at all.
        assert_eq!(negotiate(&ComponentInfo::default()), None);
    }

    #[test]
    fn error_codes_are_coarse() {
        assert_eq!(
            ConnError::Token(TokenError::NotPending).code(),
            WireErrorCode::Unauthorized
        );
        assert_eq!(ConnError::Locked.code(), WireErrorCode::Unauthorized);
        assert_eq!(
            ConnError::Peer(PeerError::NotOneAgent).code(),
            WireErrorCode::Unauthorized
        );
        assert_eq!(
            ConnError::Registry(RegistryError::AtCapacity).code(),
            WireErrorCode::Unavailable
        );
        assert_eq!(
            ConnError::Frame(FrameError::TooLarge).code(),
            WireErrorCode::Protocol
        );
    }

    #[test]
    fn peer_error_text_is_sanitized_before_logging() {
        assert_eq!(sanitize("evil\n\u{1b}[2Jinjected"), "evil[2Jinjected");
    }

    #[test]
    fn advertise_url_falls_back_to_the_listener() {
        let addr: SocketAddr = "127.0.0.1:9444".parse().unwrap();
        let cfg = AgentTransportConfig::default();
        assert_eq!(advertise_url(&cfg, addr), "wss://127.0.0.1:9444");
        let cfg = AgentTransportConfig {
            advertise_url: "wss://gw.internal:9444".into(),
            ..Default::default()
        };
        assert_eq!(advertise_url(&cfg, addr), "wss://gw.internal:9444");
    }
}
