use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Node-initiated reverse open rejected unless requested: a broad forwarding grant is
/// not itself a request, so an unsolicited reverse open from the node is refused.
#[derive(Default)]
pub(crate) struct ReverseAllowed {
    remote_ports: Mutex<HashMap<u32, u32>>,
    x11: AtomicBool,
    x11_single_connection: AtomicBool,
    // `single_connection` (RFC 4254 §6.3.2) is relayed to the node in the x11-req, but
    // the node is the least-trusted party here, same as every other reverse-open check
    // in this file -- trusting it to police its own single-use promise would let a
    // compromised node ride the forwarded cookie past its first use. Claimed
    // exactly once via `compare_exchange` so two near-simultaneous opens can't both win.
    x11_consumed: AtomicBool,
}

impl ReverseAllowed {
    pub fn bind(&self, port: u32) {
        *self.remote_ports.lock().unwrap().entry(port).or_insert(0) += 1;
    }

    pub fn unbind(&self, port: u32) {
        let mut ports = self.remote_ports.lock().unwrap();
        if let Some(n) = ports.get_mut(&port) {
            *n -= 1;
            if *n == 0 {
                ports.remove(&port);
            }
        }
    }

    pub fn port_bound(&self, port: u32) -> bool {
        self.remote_ports.lock().unwrap().contains_key(&port)
    }

    pub fn request_x11(&self, single_connection: bool) {
        self.x11_single_connection
            .store(single_connection, Ordering::SeqCst);
        self.x11.store(true, Ordering::SeqCst);
    }

    pub fn try_admit_x11(&self) -> bool {
        if !self.x11.load(Ordering::SeqCst) {
            return false;
        }
        if !self.x11_single_connection.load(Ordering::SeqCst) {
            return true;
        }
        self.x11_consumed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct X11Params {
    pub single_connection: bool,
    pub auth_protocol: String,
    pub auth_cookie: String,
    pub screen_number: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct InnerLegConfig {
    pub handshake_timeout: Duration,
    pub window_size: u32,
    pub max_packet_size: u32,
    pub idle_timeout: Duration,
}

#[derive(Debug, Clone)]
pub(crate) enum ChannelKind {
    Shell,
    Exec(Vec<u8>),
    Subsystem(String),
}

#[derive(Debug, Clone)]
pub(crate) struct PtyParams {
    pub term: String,
    pub col: u32,
    pub row: u32,
    pub pix_w: u32,
    pub pix_h: u32,
    pub modes: Vec<(Pty, u32)>,
}

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

pub(crate) struct InnerClient {
    handle: Handle<InnerHandler>,
    verified: HostVerified,
    op_timeout: Duration,
    reverse_allowed: Arc<ReverseAllowed>,
}

impl InnerClient {
    pub fn verified(&self) -> HostVerified {
        self.verified
    }

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
        let reverse_allowed = Arc::new(ReverseAllowed::default());
        let handler = InnerHandler {
            verifier,
            outcome: outcome.clone(),
            reverse_tx,
            reverse_allowed: reverse_allowed.clone(),
        };

        let connect = client::connect_stream(config, stream, handler);
        let mut handle = match tokio::time::timeout(cfg.handshake_timeout, connect).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
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
            None => {
                return Err(InnerLegError::Handshake(
                    "node presented no host key".to_string(),
                ))
            }
        };

        let key = Arc::new(key);
        let auth_call = handle.authenticate_openssh_cert(principal, key.clone(), cert);
        let auth = match tokio::time::timeout(cfg.handshake_timeout, auth_call).await {
            Ok(r) => r.map_err(|e| InnerLegError::Handshake(e.to_string())),
            Err(_) => Err(InnerLegError::HandshakeTimeout),
        };
        // Drop the inner private key the instant the handshake no longer needs it,
        // minimizing its residency. This is the last `Arc` ref (the auth future's
        // clone is already released), so the drop runs
        // `ssh_key::EcdsaPrivateKey`'s zeroizing `Drop`, scrubbing the P-256
        // scalar; the source PEM is `Zeroizing`. The residual — un-scrubbed
        // transient encode/decode scratch across the ssh_key 0.6↔0.7 PEM hand-off —
        // is library-internal, reachable only via a coredump/swap, and covered by
        // the process hardening (PR_SET_DUMPABLE=0 + RLIMIT_CORE=0,
        // `hardening::coredump`).
        drop(key);
        if !auth?.success() {
            return Err(InnerLegError::AuthRejected);
        }
        Ok(Self {
            handle,
            verified,
            op_timeout: cfg.handshake_timeout,
            reverse_allowed,
        })
    }

    pub async fn open_channel(
        &self,
        kind: ChannelKind,
        pty: Option<&PtyParams>,
        x11: Option<&X11Params>,
    ) -> Result<Channel<Msg>, InnerLegError> {
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
                self.reverse_allowed.request_x11(x.single_connection);
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

    pub async fn remote_forward(&self, address: &str, port: u32) -> Result<u32, InnerLegError> {
        if port != 0 {
            self.reverse_allowed.bind(port);
        }
        let call = self.handle.tcpip_forward(address.to_string(), port);
        let result = match tokio::time::timeout(self.op_timeout, call).await {
            Ok(r) => r.map_err(|e| InnerLegError::ChannelOpen(e.to_string())),
            Err(_) => Err(InnerLegError::ChannelOpen(
                "node tcpip-forward timed out".into(),
            )),
        };
        match result {
            Ok(bound) => {
                if port == 0 {
                    self.reverse_allowed.bind(bound);
                }
                Ok(bound)
            }
            Err(e) => {
                if port != 0 {
                    self.reverse_allowed.unbind(port);
                }
                Err(e)
            }
        }
    }

    /// Cancel a remote-forward listener on the node. `Err`'s `bool` is `true` when
    /// the node never answered (timed out) rather than explicitly rejecting the
    /// request -- RFC 4254 has no way to retract an in-flight global request once
    /// sent, so a stalling node would otherwise let the caller's per-connection
    /// listener-count bookkeeping hold this slot for the rest of the connection no
    /// matter how many times the operator asks to cancel it. The caller uses
    /// this to release that bookkeeping on timeout specifically, without treating an
    /// explicit node rejection the same way.
    pub async fn cancel_remote_forward(
        &self,
        address: &str,
        port: u32,
    ) -> Result<(), (bool, InnerLegError)> {
        let call = self.handle.cancel_tcpip_forward(address.to_string(), port);
        match tokio::time::timeout(self.op_timeout, call).await {
            Ok(Ok(())) => {
                self.reverse_allowed.unbind(port);
                Ok(())
            }
            Ok(Err(e)) => Err((false, InnerLegError::ChannelOpen(e.to_string()))),
            Err(_) => Err((
                true,
                InnerLegError::ChannelOpen("node cancel-tcpip-forward timed out".into()),
            )),
        }
    }
}

pub(crate) fn split_channel(channel: Channel<Msg>) -> (InnerReadHalf, InnerWriteHalf) {
    channel.split()
}

struct InnerHandler {
    verifier: HostVerifier,
    outcome: Arc<Mutex<Option<Result<HostVerified, HostVerifyError>>>>,
    reverse_tx: Option<mpsc::Sender<ReverseOpen>>,
    reverse_allowed: Arc<ReverseAllowed>,
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
        let Some(tx) = &self.reverse_tx else {
            return Ok(());
        };
        if !self.reverse_allowed.port_bound(connected_port) {
            tracing::warn!(
                port = connected_port,
                outcome = "reverse_refused",
                reason = "unrequested_forward",
                "unsolicited forwarded-tcpip from the node rejected (RFC 4254 §7.2)"
            );
            return Ok(());
        }
        reply.accept().await;
        let _ = tx.try_send(ReverseOpen::ForwardedTcpip {
            channel,
            connected_address: connected_address.to_string(),
            connected_port,
            originator_address: originator_address.to_string(),
            originator_port,
        });
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
        if !self.reverse_allowed.try_admit_x11() {
            tracing::warn!(
                outcome = "reverse_refused",
                reason = "unrequested_or_single_connection_exhausted_x11",
                "x11 channel from the node rejected (unsolicited, or single-connection already used; RFC 4254 §6.3.2)"
            );
            return Ok(());
        }
        reply.accept().await;
        let _ = tx.try_send(ReverseOpen::X11 {
            channel,
            originator_address: originator_address.to_string(),
            originator_port,
        });
        Ok(())
    }

    // russh's client-role defaults for the channel types below `reply.accept()`
    // unconditionally, unlike its server-role defaults which reject by dropping
    // `reply`. The node is the least-trusted party here, so inheriting an
    // accepting default would let it open channels we never asked for. We open
    // every legitimate inner-leg channel ourselves; nothing the node initiates
    // beyond the two gated types above is ever wanted. Dropping `reply` rejects.
    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse_node_initiated("session");
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse_node_initiated("direct-tcpip");
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        _reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse_node_initiated("direct-streamlocal");
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        _reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse_node_initiated("forwarded-streamlocal");
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: Channel<Msg>,
        _reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse_node_initiated("auth-agent");
        Ok(())
    }
}

fn refuse_node_initiated(channel_type: &str) {
    tracing::warn!(
        channel_type,
        outcome = "reverse_refused",
        reason = "node_initiated_channel_type_never_permitted",
        "unsolicited node-initiated channel-open rejected"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_opens_admitted_only_for_requested_forwards() {
        let a = ReverseAllowed::default();
        assert!(!a.port_bound(15222), "nothing requested → nothing admitted");
        assert!(!a.try_admit_x11(), "x11 not requested → not admitted");

        a.bind(15222);
        assert!(a.port_bound(15222));
        assert!(!a.port_bound(15223), "only the requested port admits");

        a.unbind(15222);
        assert!(!a.port_bound(15222), "cancel closes the gate");

        a.request_x11(false);
        assert!(
            a.try_admit_x11(),
            "requested without single_connection → admitted"
        );
    }

    #[test]
    fn x11_single_connection_admits_exactly_once() {
        let a = ReverseAllowed::default();
        assert!(!a.try_admit_x11(), "nothing requested → nothing admitted");

        a.request_x11(true);
        assert!(
            a.try_admit_x11(),
            "first open after a single-connection grant admits"
        );
        assert!(
            !a.try_admit_x11(),
            "a second open after the grant is consumed must be refused"
        );
        assert!(
            !a.try_admit_x11(),
            "refusal is durable, not a one-shot glitch"
        );
    }

    #[test]
    fn x11_without_single_connection_admits_repeatedly() {
        let a = ReverseAllowed::default();
        a.request_x11(false);
        assert!(a.try_admit_x11());
        assert!(
            a.try_admit_x11(),
            "no single-connection grant → unbounded by this gate"
        );
        assert!(a.try_admit_x11());
    }

    #[test]
    fn shared_port_number_survives_one_cancel() {
        let a = ReverseAllowed::default();
        a.bind(8080);
        a.bind(8080);
        a.unbind(8080);
        assert!(a.port_bound(8080));
        a.unbind(8080);
        assert!(!a.port_bound(8080));
        a.unbind(8080);
        assert!(!a.port_bound(8080));
    }

    #[test]
    fn every_accepting_client_callback_is_overridden() {
        const RUSSH_CLIENT: &str = include_str!("../../../third_party/russh/src/client/mod.rs");
        const INNERLEG: &str = include_str!("innerleg.rs");

        let mut accepting = Vec::new();
        let mut current: Option<&str> = None;
        for line in RUSSH_CLIENT.lines() {
            let line = line.trim();
            // Every callback's doc comment quotes `reply.accept().await` while
            // explaining the contract, so counting comment lines attributes an accept
            // to whichever callback was declared above the prose.
            if line.starts_with("//") {
                continue;
            }
            if let Some(rest) = line.strip_prefix("fn server_channel_open_") {
                current = rest.split('(').next();
            } else if line.contains("reply.accept().await") {
                if let Some(name) = current.take() {
                    accepting.push(name);
                }
            }
        }
        assert!(
            accepting.len() >= 7,
            "scraper found only {} accepting callbacks — the parse likely broke, \
             which would make this guard vacuous: {accepting:?}",
            accepting.len()
        );

        let missing: Vec<_> = accepting
            .iter()
            .filter(|name| !INNERLEG.contains(&format!("fn server_channel_open_{name}(")))
            .collect();
        assert!(
            missing.is_empty(),
            "InnerHandler leaves {missing:?} at russh's accepting client-role default, \
             so a malicious node can open those channels unbidden"
        );
    }
}
