//! The inner-leg SSH client (Parts B+D): host verification during the handshake,
//! ephemeral-cert authentication, and per-channel open/replay.
//!
//! The Gateway drives a russh **client** over the [`ByteStream`] the connector
//! yields. The node's host identity is verified in [`Handler::check_server_key`]
//! (no TOFU — [`HostVerifier`]); only then does the client present the ephemeral
//! inner cert (D2 — the private key is used here and dropped/zeroized right
//! after). Channels opened above this are split into a read half (relayed to the
//! outer leg by [`bridge::pump_inner_to_outer`](crate::ssh::bridge)) and a write
//! half (fed from the outer [`Handler::data`](russh::server::Handler::data)).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Handle, Msg};
use russh::keys::{Certificate, PrivateKey, PublicKey};
use russh::{Channel, ChannelReadHalf, ChannelWriteHalf, Pty};

use crate::ssh::connector::ByteStream;
use crate::ssh::hostverify::{HostVerified, HostVerifier, HostVerifyError};

pub(crate) type InnerReadHalf = ChannelReadHalf;
pub(crate) type InnerWriteHalf = ChannelWriteHalf<Msg>;

/// Inner-leg bounds (fail-closed timeouts + flow-control sizing).
#[derive(Debug, Clone)]
pub(crate) struct InnerLegConfig {
    /// Bound on completing the inner SSH transport handshake.
    pub handshake_timeout: Duration,
    /// Inner-channel initial window (flow-control / backpressure).
    pub window_size: u32,
    /// Inner-channel maximum packet size.
    pub max_packet_size: u32,
    /// Idle bound on the inner transport (Tier-0 hygiene).
    pub idle_timeout: Duration,
}

/// The channel the outer leg asked for, replayed to the node.
#[derive(Debug, Clone)]
pub(crate) enum ChannelKind {
    Shell,
    Exec(Vec<u8>),
    Subsystem(String),
}

/// PTY parameters stashed from the outer `pty_request`, replayed to the node so
/// the interactive terminal matches (Part D).
#[derive(Debug, Clone)]
pub(crate) struct PtyParams {
    pub term: String,
    pub col: u32,
    pub row: u32,
    pub pix_w: u32,
    pub pix_h: u32,
    pub modes: Vec<(Pty, u32)>,
}

/// An inner-leg failure. The `Display` is for the **operator** log; the user
/// always sees the generic node-unreachable / policy outcome (§7.1).
#[derive(Debug, thiserror::Error)]
pub(crate) enum InnerLegError {
    #[error("node host-identity verification failed: {0}")]
    HostVerification(#[source] HostVerifyError),
    #[error("inner SSH handshake failed: {0}")]
    Handshake(String),
    #[error("inner SSH handshake timed out")]
    HandshakeTimeout,
    #[error("node rejected the inner-leg certificate")]
    AuthRejected,
    #[error("inner channel open/replay failed: {0}")]
    ChannelOpen(String),
}

/// The connected, authenticated inner-leg client (one per outer connection).
pub(crate) struct InnerClient {
    handle: Handle<InnerHandler>,
    verified: HostVerified,
    /// Fail-closed bound on post-transport node round-trips (userauth already
    /// applied in `establish`; channel-open here), so a node that passes KEX +
    /// host-verify but then stalls cannot park the outer connection on the idle
    /// timer (F-innertimeout-1).
    op_timeout: Duration,
}

impl InnerClient {
    /// Which anchor verified the node (host-CA vs pinned) — for the operator log.
    pub fn verified(&self) -> HostVerified {
        self.verified
    }

    /// Complete the inner handshake over `stream`: verify the node host identity
    /// (no TOFU), then authenticate with the ephemeral cert. The private `key` is
    /// dropped (zeroized) immediately after authentication.
    pub async fn establish(
        stream: Box<dyn ByteStream>,
        verifier: HostVerifier,
        principal: &str,
        cert: Certificate,
        key: PrivateKey,
        cfg: &InnerLegConfig,
    ) -> Result<Self, InnerLegError> {
        let config = Arc::new(client::Config {
            window_size: cfg.window_size,
            maximum_packet_size: cfg.max_packet_size,
            inactivity_timeout: Some(cfg.idle_timeout),
            keepalive_interval: None,
            ..Default::default()
        });

        let outcome = Arc::new(Mutex::new(None));
        let handler = InnerHandler {
            verifier,
            outcome: outcome.clone(),
        };

        let connect = client::connect_stream(config, stream, handler);
        let mut handle = match tokio::time::timeout(cfg.handshake_timeout, connect).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                // A host-verify rejection surfaces as its specific reason (abort);
                // any other handshake failure is a generic transport error.
                if let Some(Err(hv)) = outcome.lock().unwrap().take() {
                    return Err(InnerLegError::HostVerification(hv));
                }
                return Err(InnerLegError::Handshake(e.to_string()));
            }
            Err(_) => return Err(InnerLegError::HandshakeTimeout),
        };

        let verified = match outcome.lock().unwrap().take() {
            Some(Ok(v)) => v,
            Some(Err(hv)) => return Err(InnerLegError::HostVerification(hv)),
            // The transport completed without ever presenting a host key — refuse.
            None => {
                return Err(InnerLegError::Handshake(
                    "node presented no host key".to_string(),
                ))
            }
        };

        // Bound userauth too (not just KEX): a node that passes host-verify but
        // stalls at userauth must fail closed within handshake_timeout, not park
        // the outer connection on the idle timer (F-innertimeout-1).
        let key = Arc::new(key);
        let auth_call = handle.authenticate_openssh_cert(principal, key.clone(), cert);
        let auth = match tokio::time::timeout(cfg.handshake_timeout, auth_call).await {
            Ok(r) => r.map_err(|e| InnerLegError::Handshake(e.to_string())),
            Err(_) => Err(InnerLegError::HandshakeTimeout),
        };
        drop(key); // zeroize the inner private key immediately after the handshake
        if !auth?.success() {
            return Err(InnerLegError::AuthRejected);
        }
        Ok(Self {
            handle,
            verified,
            op_timeout: cfg.handshake_timeout,
        })
    }

    /// Open a session channel on the node, replay the PTY (if any) and the
    /// requested kind. Returns the raw channel for the caller to split + bridge.
    pub async fn open_channel(
        &self,
        kind: ChannelKind,
        pty: Option<&PtyParams>,
    ) -> Result<Channel<Msg>, InnerLegError> {
        // Bound channel-open + replay by the op timeout so a stalled node cannot
        // park the (shared) handler task on the idle timer (F-innertimeout-1).
        let open = async {
            let channel = self
                .handle
                .channel_open_session()
                .await
                .map_err(|e| InnerLegError::ChannelOpen(e.to_string()))?;

            if let Some(p) = pty {
                channel
                    .request_pty(false, &p.term, p.col, p.row, p.pix_w, p.pix_h, &p.modes)
                    .await
                    .map_err(|e| InnerLegError::ChannelOpen(e.to_string()))?;
            }

            let result = match kind {
                ChannelKind::Shell => channel.request_shell(false).await,
                ChannelKind::Exec(cmd) => channel.exec(false, cmd).await,
                ChannelKind::Subsystem(name) => channel.request_subsystem(false, name).await,
            };
            result.map_err(|e| InnerLegError::ChannelOpen(e.to_string()))?;
            Ok(channel)
        };
        match tokio::time::timeout(self.op_timeout, open).await {
            Ok(r) => r,
            Err(_) => Err(InnerLegError::ChannelOpen(
                "node channel-open timed out".into(),
            )),
        }
    }
}

/// Split an opened inner channel into the halves the bridge uses.
pub(crate) fn split_channel(channel: Channel<Msg>) -> (InnerReadHalf, InnerWriteHalf) {
    channel.split()
}

/// The inner-leg client handler. Its only job is **host-identity verification**
/// during the handshake; channel data is consumed via the channel objects, not
/// here. `check_server_key` records the verdict so `establish` can surface the
/// specific no-TOFU reason on abort.
struct InnerHandler {
    verifier: HostVerifier,
    outcome: Arc<Mutex<Option<Result<HostVerified, HostVerifyError>>>>,
}

impl client::Handler for InnerHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let result = self.verifier.verify(server_public_key);
        let accept = result.is_ok();
        *self.outcome.lock().unwrap() = Some(result);
        // Returning false makes russh abort the handshake (fail closed, no TOFU).
        Ok(accept)
    }
}
