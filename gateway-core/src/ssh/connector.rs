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
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::pb::DecisionContext;

/// A bidirectional byte stream to a node's `sshd` — the object the inner leg
/// drives the russh client over. Aligned with the [`AsyncIo`](crate::asyncio)
/// reactor seam that backs the hot byte-copy.
pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ByteStream for T {}

/// The target node the outer leg resolved for this connection.
#[derive(Debug, Clone)]
pub struct NodeTarget {
    /// The CP node identifier the decision is bound to.
    pub node_id: String,
    /// The resolved Linux login (inner-leg cert principal).
    pub principal: String,
}

/// How to reach the node — the CP-resolved connector kind + dial address
/// (Design §9.2). Session Eight dials only the agentless address.
#[derive(Debug, Clone)]
pub struct NodeDial {
    /// The CP node identifier (for correlation/logging).
    pub node_id: String,
    /// `host:port` of the node's `sshd` (agentless model).
    pub dial_address: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn agentless_dial_reaches_a_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dialer = AgentlessDial::new(Duration::from_secs(2));
        let dial = NodeDial {
            node_id: "n1".into(),
            dial_address: addr.to_string(),
        };
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
        let dial = NodeDial {
            node_id: "n1".into(),
            dial_address: addr.to_string(),
        };
        assert!(
            dialer.connect(&dial).await.is_err(),
            "an unreachable node must fail closed"
        );
    }

    #[tokio::test]
    async fn empty_address_is_rejected() {
        let dialer = AgentlessDial::new(Duration::from_secs(1));
        let dial = NodeDial {
            node_id: "n1".into(),
            dial_address: String::new(),
        };
        assert!(matches!(
            dialer.connect(&dial).await,
            Err(NodeConnectError::NoAddress)
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
