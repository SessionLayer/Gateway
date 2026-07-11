//! The `NodeConnector` seam (Design §9.1) and its Session-Seven stub.
//!
//! Everything above this seam — the inner-leg SSH client, cert presentation, the
//! byte bridge, the recorder — is identical regardless of how the node is
//! reached (agentless dial vs outbound-agent). Session Seven builds only the
//! **outer** leg: on a successful authenticate + authorize it obtains the CP
//! decision + session token and hands them to a [`NodeConnector`], then closes
//! the SSH session cleanly. The stub here reports the inner leg is not built yet;
//! **Session Eight attaches the real connector** (generate the inner keypair,
//! call `SessionSigning.SignSessionCertificate` with the [`SessionGrant`] token,
//! verify node host identity, and bridge the two legs).

use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::pb::DecisionContext;

/// A bidirectional byte stream to a node's `sshd` — the object the inner leg
/// bridges against. An alias over the tokio duplex traits, aligned with the
/// [`AsyncIo`](crate::asyncio) reactor seam that backs the hot byte-copy.
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

/// What a successful outer leg hands the connector: the CP's signed decision
/// context and the single-use **session-signing token**. Session Eight presents
/// this token to `SessionSigning.SignSessionCertificate` to mint the inner-leg
/// cert (D2/§15 — the Gateway generates the inner key locally; the CP signs it).
///
/// Not `Debug`: the token is a single-use bearer secret and must never be logged.
#[derive(Clone)]
pub struct SessionGrant {
    /// The minted single-use session-signing token (bearer; never logged).
    pub session_token: String,
    /// The signed, TTL'd decision context (allowed logins, capabilities, expiry).
    /// Session Ten verifies its signature for the per-channel local checks.
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

/// A failure reaching (or, in Session Eight, dialing) the node.
#[derive(Debug, thiserror::Error)]
pub enum NodeConnectError {
    /// Session Seven stops at the seam: the inner leg is not implemented yet.
    /// The outer leg surfaces this as a clean, generic close (not an error to
    /// the user) — a stock `ssh login%node@gw` authenticates, authorizes, and
    /// disconnects cleanly here.
    #[error("inner leg pending (Session Eight)")]
    InnerLegPending,
}

/// The boxed future returned by [`NodeConnector::connect`] — a byte stream to the
/// node, or a connect error. Boxed so the trait stays object-safe (the Gateway
/// holds `Arc<dyn NodeConnector>` and swaps the implementation per node later).
pub type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn ByteStream>, NodeConnectError>> + Send + 'a>>;

/// Reaches a node's `sshd` as a byte stream (Design §9.1). Selection is per-node
/// via inventory; the session core above the seam is carriage-agnostic.
pub trait NodeConnector: Send + Sync {
    /// Connect to `node`, authorized by `grant`.
    fn connect<'a>(&'a self, node: &'a NodeTarget, grant: &'a SessionGrant) -> ConnectFuture<'a>;
}

/// The Session-Seven stub: always returns [`NodeConnectError::InnerLegPending`].
/// The outer leg treats this as the clean stopping point (Session Eight attaches
/// the agentless-dial / outbound-agent connectors here).
#[derive(Debug, Clone, Copy, Default)]
pub struct PendingInnerLeg;

impl NodeConnector for PendingInnerLeg {
    fn connect<'a>(&'a self, _node: &'a NodeTarget, _grant: &'a SessionGrant) -> ConnectFuture<'a> {
        Box::pin(async { Err(NodeConnectError::InnerLegPending) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_reports_inner_leg_pending() {
        let node = NodeTarget {
            node_id: "node-1".into(),
            principal: "deploy".into(),
        };
        let grant = SessionGrant {
            session_token: "tok".into(),
            context: None,
        };
        match PendingInnerLeg.connect(&node, &grant).await {
            Err(NodeConnectError::InnerLegPending) => {}
            Ok(_) => panic!("stub never connects in Session Seven"),
        }
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
