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

use russh::client::{self, ChannelOpenHandle, Handle, Msg};
use russh::keys::{Certificate, PrivateKey, PublicKey};
use russh::{Channel, ChannelReadHalf, ChannelWriteHalf, Pty};
use tokio::sync::mpsc;

use crate::ssh::connector::ByteStream;
use crate::ssh::hostverify::{HostVerified, HostVerifier, HostVerifyError};

pub(crate) type InnerReadHalf = ChannelReadHalf;
pub(crate) type InnerWriteHalf = ChannelWriteHalf<Msg>;

/// A channel the NODE opened back toward the Gateway on the inner (client) leg,
/// as a consequence of an already-granted forward (Session 29, FR-SESS-2):
/// - `ForwardedTcpip`: a connection hit a `ssh -R` listener the node bound at the
///   Gateway's request (`tcpip_forward`) — RFC 4254 §7.2.
/// - `X11`: the node's sshd opened an X11 channel after we relayed the client's
///   `x11-req` — RFC 4254 §6.3.2.
///
/// The Gateway relays each to the real client on the OUTER leg and bridges bytes
/// opaquely (metadata-only recording; see [`crate::ssh::forward`]). The inner
/// channel is already accepted when it arrives here.
pub(crate) enum ReverseOpen {
    ForwardedTcpip {
        channel: Channel<Msg>,
        connected_address: String,
        connected_port: u32,
        originator_address: String,
        originator_port: u32,
    },
    X11 {
        channel: Channel<Msg>,
        originator_address: String,
        originator_port: u32,
    },
}

/// X11 forwarding request parameters (RFC 4254 §6.3.1), stashed from the outer
/// `x11-req` and relayed UNCHANGED to the node's session channel. The Gateway is a
/// pure pass-through: the fake-cookie / real-cookie substitution is the endpoints'
/// job (the node's sshd and the client's `ssh`), never the relay's.
#[derive(Debug, Clone)]
pub(crate) struct X11Params {
    pub single_connection: bool,
    pub auth_protocol: String,
    pub auth_cookie: String,
    pub screen_number: u32,
}

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
        reverse_tx: Option<mpsc::Sender<ReverseOpen>>,
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
            reverse_tx,
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
        // Drop the inner private key the instant the handshake no longer needs it,
        // minimizing its residency (F-innerkey-zeroize). This is the last `Arc`
        // ref (the auth future's clone is already released), so the drop runs
        // `ssh_key::EcdsaPrivateKey`'s zeroizing `Drop`, scrubbing the P-256
        // scalar; the source PEM is `Zeroizing`. The residual — un-scrubbed
        // transient encode/decode scratch across the ssh_key 0.6↔0.7 PEM hand-off
        // ([[F-sshkey-dup-1]]) — is library-internal, reachable only via a
        // coredump/swap, and now covered by the S21 process hardening
        // (PR_SET_DUMPABLE=0 + RLIMIT_CORE=0, `hardening::coredump`, NFR-5).
        drop(key);
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
        x11: Option<&X11Params>,
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

            // Relay the client's x11-req UNCHANGED to the node before the shell
            // (matches OpenSSH ordering). Pure pass-through: no cookie rewriting
            // (RFC 4254 §6.3.1 — the endpoints own the fake/real cookie swap).
            if let Some(x) = x11 {
                channel
                    .request_x11(
                        false,
                        x.single_connection,
                        x.auth_protocol.clone(),
                        x.auth_cookie.clone(),
                        x.screen_number,
                    )
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

    /// Local forward (`ssh -L`, Session 29): ask the NODE — as its SSH client — to
    /// dial `host:port` and open a `direct-tcpip` channel to it (RFC 4254 §7.2).
    /// The dial happens FROM THE NODE'S NETWORK, so a granted forward can only
    /// reach what the node itself can reach (no Gateway-side SSRF escape). Bounded
    /// by the op timeout so a stalled node cannot park the handler.
    pub async fn open_direct_tcpip(
        &self,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<Channel<Msg>, InnerLegError> {
        let open = self.handle.channel_open_direct_tcpip(
            host_to_connect.to_string(),
            port_to_connect,
            originator_address.to_string(),
            originator_port,
        );
        match tokio::time::timeout(self.op_timeout, open).await {
            Ok(r) => r.map_err(|e| InnerLegError::ChannelOpen(e.to_string())),
            Err(_) => Err(InnerLegError::ChannelOpen(
                "node direct-tcpip open timed out".into(),
            )),
        }
    }

    /// Remote forward (`ssh -R`, Session 29): ask the NODE to bind a listener for
    /// `address:port` (RFC 4254 §7.1). The listener lives on the NODE's side (real
    /// `ssh -R`-through-a-bastion semantics), so no Gateway-side listener leaks
    /// across sessions/nodes. `port == 0` lets the node pick; the chosen port is
    /// returned to report back to the client.
    pub async fn remote_forward(&self, address: &str, port: u32) -> Result<u32, InnerLegError> {
        let call = self.handle.tcpip_forward(address.to_string(), port);
        match tokio::time::timeout(self.op_timeout, call).await {
            Ok(r) => r.map_err(|e| InnerLegError::ChannelOpen(e.to_string())),
            Err(_) => Err(InnerLegError::ChannelOpen(
                "node tcpip-forward timed out".into(),
            )),
        }
    }

    /// Unbind a remote-forward listener on the node (`cancel-tcpip-forward`).
    pub async fn cancel_remote_forward(
        &self,
        address: &str,
        port: u32,
    ) -> Result<(), InnerLegError> {
        let call = self.handle.cancel_tcpip_forward(address.to_string(), port);
        match tokio::time::timeout(self.op_timeout, call).await {
            Ok(r) => r.map_err(|e| InnerLegError::ChannelOpen(e.to_string())),
            Err(_) => Err(InnerLegError::ChannelOpen(
                "node cancel-tcpip-forward timed out".into(),
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
    /// Sink for node-initiated reverse channels (remote-forward / X11). `None`
    /// when the session was granted no reverse-capable forward: such a channel is
    /// then REJECTED (fail closed — the node must never open one unbidden).
    reverse_tx: Option<mpsc::Sender<ReverseOpen>>,
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

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // Dropping `reply` rejects; accept only when a forward was granted and the
        // outer relay is still live.
        let Some(tx) = &self.reverse_tx else {
            return Ok(());
        };
        reply.accept().await;
        let _ = tx
            .send(ReverseOpen::ForwardedTcpip {
                channel,
                connected_address: connected_address.to_string(),
                connected_port,
                originator_address: originator_address.to_string(),
                originator_port,
            })
            .await;
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        channel: Channel<Msg>,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let Some(tx) = &self.reverse_tx else {
            return Ok(());
        };
        reply.accept().await;
        let _ = tx
            .send(ReverseOpen::X11 {
                channel,
                originator_address: originator_address.to_string(),
                originator_port,
            })
            .await;
        Ok(())
    }
}
