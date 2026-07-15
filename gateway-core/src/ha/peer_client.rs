//! The owner-side peer-relay client + signal handler (Session Fifteen; `gateway-relay-v1.md`
//! §5, FR-HA-4). This Gateway (gw-B) OWNS a node's agent control channel. When an ingress
//! (gw-A) publishes a [`DialBackSignal`](crate::pbgw::DialBackSignal) addressed to it, gw-B
//! produces the node byte stream **locally** (the S14 agent dial-back) and relays it to gw-A
//! over a direct TLS+WS connection.
//!
//! **gw-B is a dumb byte relay** — no inner leg, no recorder, no host verification. All of
//! that runs at the ingress (D21/D23 unchanged). gw-B only splices raw bytes between the
//! node stream and the relay socket.

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

/// Default per-node ceiling on concurrently-served relays (§8/§7.6, F4). Bounds the
/// signalling-amplification an attacker with bus-publish access can drive: even authorized to
/// publish, they cannot make the owner perform unbounded concurrent node dial-backs for one node.
const DEFAULT_PER_NODE_RELAY_CAP: usize = 8;

/// Tracks in-flight served relays, for two purposes:
///   * a **per-node concurrency cap** (§7.6 / F4) so a flood of `DialBackSignal`s for one node
///     cannot amplify into unbounded local node dial-backs, and
///   * the **graceful-drain wait** (M2): a draining owner finishes its live relays to the drain
///     deadline instead of cutting them instantly (the relay path has no session registry of its
///     own — these detached tasks would otherwise be dropped the moment the process exits).
///
/// Cheap to share (`Arc`). A [`RelaySlot`] guard releases its reservation on drop.
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
    /// A registry with an explicit per-node cap.
    pub fn new(per_node_cap: usize) -> Self {
        Self {
            per_node: Mutex::new(HashMap::new()),
            active: AtomicUsize::new(0),
            per_node_cap: per_node_cap.max(1),
        }
    }

    /// Reserve a slot for `node`, or `None` if the per-node cap is already reached (fail closed
    /// — the signal is dropped, the ingress times out). The returned guard releases on drop.
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

    /// Total relays in flight across every node — the graceful drain waits for this to reach 0.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

/// An in-flight served-relay reservation; releasing it (on drop) decrements the per-node and
/// total counters.
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
    /// In-flight served-relay registry: the per-node concurrency cap (F4) and the graceful-drain
    /// wait (M2).
    pub served_relays: Arc<ServedRelays>,
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
    let observed = deps.owner_cache.get(&signal.node_name);
    let is_self_owner = observed
        .as_ref()
        .map(|o| o.owner_id == deps.self_gateway_id)
        .unwrap_or(false);
    if !is_self_owner {
        return Err(RelayError::NotOwner);
    }
    // (1b) Drop a stale/replayed signal whose `owner_nonce` is OLDER than the ownership epoch we
    // last observed (§8, F4): a failover has advanced the nonce past this signal, so serving it
    // would relay a superseded route. Dropping here means NO node dial-back for a replayed signal.
    if let Some(o) = &observed {
        if signal.owner_nonce < o.nonce {
            return Err(RelayError::StaleNonce);
        }
    }
    // (1c) …and we must still hold a LIVE agent control channel to the node (the backstop for a
    // truly-dead owner — a gateway without the channel cannot reach the node regardless of any
    // cache). Both guards must hold.
    if deps.registry.lookup(&signal.node_name).is_err() {
        return Err(RelayError::NotOwner);
    }

    // (1d) Reserve a per-node relay slot (F4 concurrency cap) BEFORE any costly work, and register
    // the relay so the graceful drain (M2) waits for it. The guard releases on every return path.
    let Some(_slot) = deps.served_relays.begin(&signal.node_name) else {
        return Err(RelayError::PerNodeCap);
    };

    // (2) Validate the INGRESS FIRST (redteam SSRF reorder). Establish the relay connection —
    // TCP + TLS (the ingress serverAuth leaf MUST chain to our pinned internal CA and match
    // `ingress_gateway_id`) + preface + RELAY_OPEN/ACCEPT — BEFORE producing the node byte
    // stream. `ingress_relay_addr` is bus-controlled, so a forged address must not be able to
    // make us dial a node: it fails the TLS certificate check and aborts here. The residual (a
    // bounded blind TCP-connect + ClientHello to a wire address) needs bus-publish authorization
    // (§8) and cannot complete without a valid internal-CA gateway certificate — Accepted-Risk.
    // All bounded so a stalled ingress never parks anything.
    let relay_ws = tokio::time::timeout(deps.handshake_timeout, open_relay(&deps, &signal))
        .await
        .map_err(|_| RelayError::Handshake)??;
    let mut relay_stream = WsByteStream::new(relay_ws.ws, relay_ws.ver, relay_ws.max_frame_bytes);

    // (3) Only now — the ingress cryptographically proven — produce the node byte stream locally
    // (the S14 agent dial-back mints its OWN SLDB1 token and splices to the node's loopback sshd;
    // full reuse, no confused deputy). A failure here fails closed: the relay stream is dropped,
    // the ingress's inner leg sees EOF and denies the session.
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

    // (4) Dumb bidirectional copy: node ByteStream ↔ peer-relay STREAM_DATA frames. No inner
    // leg, no recorder — the ingress owns the session + recording. Structured outcome logs give
    // interim relay-throughput visibility until the metrics framework lands (item 19).
    tracing::info!(node = %signal.node_name, peer = %signal.ingress_gateway_id, event = "peer_relay_serving", "serving a peer relay as owner");
    let _ = tokio::io::copy_bidirectional(&mut node_stream, &mut relay_stream).await;
    tracing::info!(node = %signal.node_name, peer = %signal.ingress_gateway_id, event = "peer_relay_closed", "peer relay closed");
    Ok(())
}

/// An established, accepted relay connection to the ingress.
struct OpenRelay {
    ws: WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>,
    ver: u8,
    /// The frame bound to decode the relay stream with — the HELLO_ACK-negotiated value clamped
    /// to our configured ceiling (F10b), so it agrees with what the ingress will frame.
    max_frame_bytes: usize,
}

/// What the HELLO_ACK negotiated: the wire major (in the VER byte) and the ingress's max frame.
struct Negotiated {
    ver: u8,
    max_frame_bytes: usize,
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
        // RELAY_REJECT or anything else ⇒ fail closed (the ingress refused the binding).
        _ => Err(RelayError::Handshake),
    }
}

/// Client-side preface: send `HELLO` with our wire component info, read `HELLO_ACK`, and return
/// the negotiated wire major + frame bound. A `VERSION_REJECT`, a major outside the wire range
/// (F6), or any other frame fails closed.
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

    // The HELLO_ACK carries the negotiated major in its VER byte and the ingress's proposed
    // frame bound in its payload.
    loop {
        let msg = ws.next().await.ok_or(RelayError::Handshake)?;
        match msg.map_err(|_| RelayError::Handshake)? {
            Message::Binary(bytes) => {
                let ack_ver = *bytes.first().ok_or(RelayError::Handshake)?;
                let frame = wire::decode(bytes, max_frame_bytes, ack_ver)
                    .map_err(|_| RelayError::Handshake)?;
                if frame.msg_type != MsgType::HelloAck {
                    return Err(RelayError::Handshake); // VERSION_REJECT / anything else: fail closed
                }
                // (F6) Refuse a negotiated major outside the wire range — moot at 1.0, load-bearing
                // the moment the wire profile gains a minor. Never proceed on a version we cannot
                // actually speak.
                if frame.ver < WIRE_PROTOCOL_MIN.0 as u8 || frame.ver > WIRE_PROTOCOL_MAX.0 as u8 {
                    return Err(RelayError::Handshake);
                }
                // (F10b) Adopt the ingress's HELLO_ACK-negotiated frame bound, clamped to our
                // configured ceiling so the decode bound never exceeds our WS-layer cap. `0`
                // (an ack without the field) falls back to our configured value.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_relays_caps_per_node_and_counts_active_for_drain() {
        let relays = Arc::new(ServedRelays::new(2));
        assert_eq!(relays.active(), 0);

        // Two concurrent relays for one node are allowed; the third is refused (fail closed).
        let a = relays.begin("web-01").expect("first slot");
        let b = relays.begin("web-01").expect("second slot");
        assert!(
            relays.begin("web-01").is_none(),
            "per-node cap refuses the third"
        );
        // A DIFFERENT node is independent (the cap is per-node, not global).
        let c = relays
            .begin("web-02")
            .expect("other node has its own budget");
        assert_eq!(
            relays.active(),
            3,
            "the drain wait sees every in-flight relay"
        );

        // Releasing a slot frees per-node capacity and decrements the drain counter.
        drop(a);
        assert_eq!(relays.active(), 2);
        let _d = relays.begin("web-01").expect("a freed slot is reusable");
        assert_eq!(relays.active(), 3);

        drop(b);
        drop(c);
        drop(_d);
        assert_eq!(relays.active(), 0, "all relays drained");
    }
}
