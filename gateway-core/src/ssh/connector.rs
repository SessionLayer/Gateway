//! The `NodeConnector` seam (Design §9.1) and the agentless dialer (Part A).
//!
//! Everything above this seam — the inner-leg SSH client, host verification,
//! cert presentation, the byte bridge, the recorder tap — is identical
//! regardless of how the node is reached. The connector's sole job is to yield a
//! byte stream to the node's `sshd`. Session Eight implements [`AgentlessDial`]
//! (Gateway → `node:22` directly, FR-CONN-2); the outbound-agent dial-back is
//! Session Thirteen and plugs in at the same seam.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::pb::{ConnectorKind, DecisionContext};

/// A bidirectional byte stream to a node's `sshd` — the object the inner leg
/// drives the russh client over. Aligned with the [`AsyncIo`](crate::asyncio)
/// reactor seam that backs the hot byte-copy.
pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ByteStream for T {}

/// Opaque by design: a byte stream carries session plaintext, so it renders as a
/// placeholder and never its contents.
impl std::fmt::Debug for dyn ByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ByteStream")
    }
}

/// The target node the outer leg resolved for this connection.
#[derive(Debug, Clone)]
pub struct NodeTarget {
    /// The CP node identifier the decision is bound to.
    pub node_id: String,
    /// The resolved Linux login (inner-leg cert principal).
    pub principal: String,
}

/// How to reach the node — the CP-resolved connector kind + whatever that kind needs
/// (Design §9.2). Selection is per-node (FR-CONN-3): a fleet mixes both models.
#[derive(Debug, Clone)]
pub struct NodeDial {
    /// The CP node identifier (for correlation/logging).
    pub node_id: String,
    /// `host:port` of the node's `sshd` (agentless model only).
    pub dial_address: String,
    /// The CP-declared connector model (proto `ConnectorKind`). `UNSPECIFIED` or an
    /// unknown value is an explicit deny — never an accidental fallthrough.
    pub connector_kind: i32,
    /// The node's stable enrollment **name** — the join key between a session and the
    /// Agent that owns the node (outbound-agent model; matched against the dNSName SAN
    /// of the agent's certificate).
    pub node_name: String,
    /// The Gateway session this dial serves (bound into the dial-back token).
    pub session_id: String,
    /// The resolved Linux principal (bound into the dial-back token; enforcement lives
    /// in the inner-leg certificate, never in the Agent).
    pub principal: String,
}

/// What a successful outer leg hands the inner leg: the CP's signed decision
/// context and the single-use **session-signing token**. Session Eight presents
/// this token to `SessionSigning.SignSessionCertificate` to mint the inner-leg
/// cert (D2/§15 — the Gateway generates the inner key locally; the CP signs it).
///
/// Not `Debug`-derived: the token is a single-use bearer secret; the manual impl
/// redacts it.
#[derive(Clone)]
pub struct SessionGrant {
    /// The minted single-use session-signing token (bearer; never logged).
    pub session_token: String,
    /// The signed, TTL'd decision context (allowed logins, capabilities, expiry).
    pub context: Option<DecisionContext>,
}

impl std::fmt::Debug for SessionGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionGrant")
            .field("session_token", &"<redacted>")
            .field("has_context", &self.context.is_some())
            .finish()
    }
}

/// A failure reaching the node (fail-closed; §7.1 post-authz "node unreachable").
#[derive(Debug, thiserror::Error)]
pub enum NodeConnectError {
    /// The agentless node has no dial address (misconfiguration / wrong kind).
    #[error("node has no dial address")]
    NoAddress,
    /// The dial address could not be resolved / parsed.
    #[error("invalid node dial address {0:?}")]
    BadAddress(String),
    /// The TCP dial failed (node offline / unreachable).
    #[error("node dial failed: {0}")]
    Dial(#[source] std::io::Error),
    /// The dial did not complete within the bounded connect timeout.
    #[error("node dial timed out after {0:?}")]
    Timeout(Duration),
    /// An outbound-agent node whose CP record carries no enrollment name: there is no
    /// join key to any Agent, so refuse rather than guess (FR-CONN-3).
    #[error("outbound-agent node has no enrollment name")]
    NoNodeName,
    /// No Agent is registered for this node (never connected, disconnected, or its
    /// control channel died). The node is simply offline (§7.1 / FR-SESS-5).
    #[error("no agent is connected for this node")]
    NoAgent,
    /// The Agent is covered by a Lock (deny wins, §8.4).
    #[error("the node's agent is locked")]
    AgentLocked,
    /// The Agent declined the dial-back, or its own dial to the node's `sshd` failed.
    #[error("the agent refused or could not serve the dial-back")]
    AgentRefused,
    /// The CP declared a connector model this Gateway does not implement — including
    /// `UNSPECIFIED`. Fail closed; never fall back to another model.
    #[error("unsupported connector kind {0}")]
    UnsupportedConnector(i32),
    /// The node is outbound-agent but this Gateway has no agent transport configured.
    #[error("the agent transport is not enabled on this Gateway")]
    AgentTransportDisabled,
}

/// The boxed future returned by [`NodeConnector::connect`].
pub type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn ByteStream>, NodeConnectError>> + Send + 'a>>;

/// Reaches a node's `sshd` as a byte stream (Design §9.1). Selection is per-node
/// via inventory; the session core above the seam is carriage-agnostic.
pub trait NodeConnector: Send + Sync {
    /// Dial `dial` and yield a byte stream to the node's `sshd`.
    fn connect<'a>(&'a self, dial: &'a NodeDial) -> ConnectFuture<'a>;
}

/// Agentless model: dial `node:22` directly over TCP with a bounded connect
/// timeout (FR-CONN-2). Fail-closed on an unreachable node.
#[derive(Debug, Clone)]
pub struct AgentlessDial {
    connect_timeout: Duration,
}

impl AgentlessDial {
    /// Build an agentless dialer bounding each connect by `connect_timeout`.
    pub fn new(connect_timeout: Duration) -> Self {
        Self { connect_timeout }
    }
}

impl NodeConnector for AgentlessDial {
    fn connect<'a>(&'a self, dial: &'a NodeDial) -> ConnectFuture<'a> {
        Box::pin(async move {
            if dial.dial_address.is_empty() {
                return Err(NodeConnectError::NoAddress);
            }
            // Resolve without a blocking lookup: node addresses are IP:port. If a
            // hostname is ever used, tokio's connect resolves it, but we parse a
            // SocketAddr first for a clean early error on a malformed address.
            let addr = dial.dial_address.clone();
            let connect = async {
                match addr.parse::<SocketAddr>() {
                    Ok(sa) => TcpStream::connect(sa).await,
                    // Fall back to tokio's resolver for a host:port form.
                    Err(_) => TcpStream::connect(addr.as_str()).await,
                }
            };
            match tokio::time::timeout(self.connect_timeout, connect).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    Ok(Box::new(stream) as Box<dyn ByteStream>)
                }
                Ok(Err(e)) => Err(NodeConnectError::Dial(e)),
                Err(_) => Err(NodeConnectError::Timeout(self.connect_timeout)),
            }
        })
    }
}

/// Per-node connector selection (FR-CONN-3, Design §9.2): the CP declares the model
/// per node and a fleet mixes both. An `UNSPECIFIED` or unrecognised kind is an
/// **explicit deny** — before Session Fourteen such a node fell through to an
/// agentless dial with an empty address and died as `NoAddress`, which was fail-closed
/// by accident rather than by design.
pub struct DispatchConnector {
    agentless: Arc<dyn NodeConnector>,
    /// `None` when this Gateway has no agent transport configured.
    agent: Option<Arc<dyn NodeConnector>>,
}

impl DispatchConnector {
    /// Dispatch between the agentless dialer and (optionally) the outbound-agent one.
    pub fn new(agentless: Arc<dyn NodeConnector>, agent: Option<Arc<dyn NodeConnector>>) -> Self {
        Self { agentless, agent }
    }
}

impl NodeConnector for DispatchConnector {
    fn connect<'a>(&'a self, dial: &'a NodeDial) -> ConnectFuture<'a> {
        match ConnectorKind::try_from(dial.connector_kind) {
            Ok(ConnectorKind::Agentless) => self.agentless.connect(dial),
            Ok(ConnectorKind::OutboundAgent) => match &self.agent {
                Some(agent) => agent.connect(dial),
                None => Box::pin(std::future::ready(Err(
                    NodeConnectError::AgentTransportDisabled,
                ))),
            },
            Ok(ConnectorKind::Unspecified) | Err(_) => {
                let kind = dial.connector_kind;
                Box::pin(std::future::ready(Err(
                    NodeConnectError::UnsupportedConnector(kind),
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `NodeDial` for the agentless model (the S8 shape).
    fn agentless_dial(addr: &str) -> NodeDial {
        NodeDial {
            node_id: "n1".into(),
            dial_address: addr.into(),
            connector_kind: ConnectorKind::Agentless as i32,
            node_name: "node-1".into(),
            session_id: "sess-1".into(),
            principal: "deploy".into(),
        }
    }

    #[tokio::test]
    async fn agentless_dial_reaches_a_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dialer = AgentlessDial::new(Duration::from_secs(2));
        let dial = agentless_dial(&addr.to_string());
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let stream = dialer.connect(&dial).await;
        assert!(stream.is_ok(), "dial to a live listener must succeed");
        let _ = accept.await;
    }

    #[tokio::test]
    async fn agentless_dial_to_dead_port_fails_closed() {
        // Reserve a port then drop the listener so the connect is refused.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let dialer = AgentlessDial::new(Duration::from_millis(500));
        assert!(
            dialer
                .connect(&agentless_dial(&addr.to_string()))
                .await
                .is_err(),
            "an unreachable node must fail closed"
        );
    }

    #[tokio::test]
    async fn empty_address_is_rejected() {
        let dialer = AgentlessDial::new(Duration::from_secs(1));
        assert!(matches!(
            dialer.connect(&agentless_dial("")).await,
            Err(NodeConnectError::NoAddress)
        ));
    }

    /// A connector that records whether it was reached (never actually dials).
    struct Spy(&'static str);

    impl NodeConnector for Spy {
        fn connect<'a>(&'a self, _dial: &'a NodeDial) -> ConnectFuture<'a> {
            let which = self.0;
            Box::pin(async move { Err(NodeConnectError::BadAddress(which.to_string())) })
        }
    }

    fn dispatcher(with_agent: bool) -> DispatchConnector {
        DispatchConnector::new(
            Arc::new(Spy("agentless")),
            with_agent.then(|| Arc::new(Spy("agent")) as Arc<dyn NodeConnector>),
        )
    }

    fn dial_of_kind(kind: i32) -> NodeDial {
        NodeDial {
            connector_kind: kind,
            ..agentless_dial("10.0.0.5:22")
        }
    }

    #[tokio::test]
    async fn dispatch_selects_the_connector_declared_per_node() {
        let d = dispatcher(true);
        // A mixed fleet: each node reaches its own model, in the same process.
        assert!(matches!(
            d.connect(&dial_of_kind(ConnectorKind::Agentless as i32)).await,
            Err(NodeConnectError::BadAddress(w)) if w == "agentless"
        ));
        assert!(matches!(
            d.connect(&dial_of_kind(ConnectorKind::OutboundAgent as i32)).await,
            Err(NodeConnectError::BadAddress(w)) if w == "agent"
        ));
    }

    #[tokio::test]
    async fn an_unspecified_or_unknown_connector_kind_is_an_explicit_deny() {
        // Never an accidental fallthrough to the agentless dial: a node whose model
        // the CP did not declare must not be reachable by guessing.
        let d = dispatcher(true);
        for kind in [ConnectorKind::Unspecified as i32, 7, -1, i32::MAX] {
            assert!(
                matches!(
                    d.connect(&dial_of_kind(kind)).await,
                    Err(NodeConnectError::UnsupportedConnector(k)) if k == kind
                ),
                "kind {kind} must be denied explicitly"
            );
        }
    }

    #[tokio::test]
    async fn an_agent_node_on_a_gateway_without_the_transport_fails_closed() {
        let d = dispatcher(false);
        assert!(matches!(
            d.connect(&dial_of_kind(ConnectorKind::OutboundAgent as i32))
                .await,
            Err(NodeConnectError::AgentTransportDisabled)
        ));
        // …while agentless nodes on the same Gateway still work.
        assert!(matches!(
            d.connect(&dial_of_kind(ConnectorKind::Agentless as i32)).await,
            Err(NodeConnectError::BadAddress(w)) if w == "agentless"
        ));
    }

    #[test]
    fn session_grant_debug_redacts_token() {
        let g = SessionGrant {
            session_token: "super-secret-token".into(),
            context: None,
        };
        assert!(!format!("{g:?}").contains("super-secret-token"));
    }
}
