//! NodeConnector seam: pluggable node-reach strategy (agentless or outbound-agent).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::pb::{ConnectorKind, DecisionContext};

pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ByteStream for T {}

impl std::fmt::Debug for dyn ByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ByteStream")
    }
}

#[derive(Debug, Clone)]
pub struct NodeTarget {
    pub node_id: String,
    pub principal: String,
}

#[derive(Debug, Clone, Default)]
pub struct NodeDial {
    pub node_id: String,
    pub dial_address: String,
    /// CP-declared connector model; UNSPECIFIED or unknown value is explicit deny.
    pub connector_kind: i32,
    pub node_name: String,
    pub session_id: String,
    pub principal: String,
    pub owning_gateway_id: String,
    pub owning_gateway_addr: String,
    pub owner_nonce: u64,
}

#[derive(Clone)]
pub struct SessionGrant {
    pub session_token: String,
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

#[derive(Debug, thiserror::Error)]
pub enum NodeConnectError {
    #[error("node has no dial address")]
    NoAddress,
    #[error("invalid node dial address {0:?}")]
    BadAddress(String),
    #[error("node dial failed: {0}")]
    Dial(#[source] std::io::Error),
    #[error("node dial timed out after {0:?}")]
    Timeout(Duration),
    #[error("outbound-agent node has no enrollment name")]
    NoNodeName,
    #[error("no agent is connected for this node")]
    NoAgent,
    /// The Agent is covered by a Lock (deny wins, §8.4).
    #[error("the node's agent is locked")]
    AgentLocked,
    #[error("the agent refused or could not serve the dial-back")]
    AgentRefused,
    #[error("the node's agent control channel is saturated")]
    AgentBusy,
    #[error("unsupported connector kind {0}")]
    UnsupportedConnector(i32),
    #[error("the agent transport is not enabled on this Gateway")]
    AgentTransportDisabled,
    #[error("the owning gateway could not be reached for the relay")]
    RelayUnavailable,
}

pub type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn ByteStream>, NodeConnectError>> + Send + 'a>>;

pub trait NodeConnector: Send + Sync {
    fn connect<'a>(&'a self, dial: &'a NodeDial) -> ConnectFuture<'a>;
}

#[derive(Debug, Clone)]
pub struct AgentlessDial {
    connect_timeout: Duration,
}

impl AgentlessDial {
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
            let addr = dial.dial_address.clone();
            let connect = async {
                match addr.parse::<SocketAddr>() {
                    Ok(sa) => TcpStream::connect(sa).await,
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

pub struct DispatchConnector {
    agentless: Arc<dyn NodeConnector>,
    /// `None` when this Gateway has no agent transport configured.
    agent: Option<Arc<dyn NodeConnector>>,
}

impl DispatchConnector {
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

    fn agentless_dial(addr: &str) -> NodeDial {
        NodeDial {
            node_id: "n1".into(),
            dial_address: addr.into(),
            connector_kind: ConnectorKind::Agentless as i32,
            node_name: "node-1".into(),
            session_id: "sess-1".into(),
            principal: "deploy".into(),
            ..Default::default()
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
