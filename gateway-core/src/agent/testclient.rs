//! A client-side peer for the frozen wire contract — **test-only** (feature
//! `test-agent`), never compiled into a production build.
//!
//! It stands in for the real SessionLayer Agent so the Gateway's transport can be
//! driven end-to-end: it dials **out**, registers a control channel with its S12 mTLS
//! identity, answers `PING`, and on a `DIAL_BACK_REQUEST` opens a second connection,
//! presents the token, and splices the returned byte stream to its own locally
//! configured `127.0.0.1:22`.
//!
//! **The splice target comes from local configuration, never from the wire** — exactly
//! as the contract requires. `DIAL_BACK_REQUEST` carries no target, so there is nothing
//! here for a hostile Gateway to redirect.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::{Bytes as WsBytes, Message};
use tokio_tungstenite::{client_async_with_config, WebSocketStream};

use crate::agent::stream::WsByteStream;
use crate::agent::wire::{self, Frame, MsgType};
use crate::agent::{ws_config, CONTROL_PATH, DIALBACK_PATH};
use crate::pbagent::{
    AgentHello, DialBackAuth, DialBackErrorCode, DialBackRequest, DialBackResult, Pong, StreamOpen,
};
use crate::version;

/// The WebSocket a client peer speaks over.
pub type ClientWs = WebSocketStream<TlsStream<TcpStream>>;

/// Everything the test agent needs. All of it is *local* configuration.
#[derive(Clone)]
pub struct AgentClient {
    /// `wss://host:port` of the Gateway's agent transport (the control channel).
    pub endpoint: String,
    /// The Gateway's enrolled name — the server name its certificate is verified
    /// against. There is no TOFU on this path either.
    pub server_name: String,
    /// The internal mTLS CA (DER) the Agent already holds.
    pub ca_der: Vec<Vec<u8>>,
    /// The Agent's identity leaf (DER) — the S12 credential.
    pub cert_der: Vec<u8>,
    /// The identity's private key (PKCS#8 DER).
    pub key_pkcs8_der: Vec<u8>,
    /// The node this Agent is bound to (its own certificate's dNSName SAN).
    pub node_name: String,
    /// The node's local sshd. **Local config, never from the wire.**
    pub splice_addr: String,
    /// The frame bound to assume before `HELLO_ACK` negotiates one.
    pub max_frame_bytes: usize,
}

/// What the Gateway's `HELLO_ACK` fixed for this connection.
#[derive(Debug, Clone, Copy)]
pub struct Negotiated {
    /// The frame `VER` byte for every subsequent frame.
    pub ver: u8,
    /// The cadence at which the Gateway will PING (2 missed ⇒ dead).
    pub heartbeat_interval_secs: u32,
    /// The frame bound both peers must honour.
    pub max_frame_bytes: usize,
}

impl AgentClient {
    fn tls_config(&self) -> anyhow::Result<Arc<ClientConfig>> {
        crate::tls::install_ring_provider();
        let mut roots = RootCertStore::empty();
        for der in &self.ca_der {
            roots.add(CertificateDer::from(der.clone()))?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![CertificateDer::from(self.cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8_der.clone())),
            )?;
        Ok(Arc::new(config))
    }

    /// Open one TLS + WebSocket connection to `path` on `endpoint`. No preface yet, so
    /// adversarial tests can drive the framing themselves.
    pub async fn connect(&self, endpoint: &str, path: &str) -> anyhow::Result<ClientWs> {
        let authority = endpoint
            .strip_prefix("wss://")
            .ok_or_else(|| anyhow::anyhow!("dial-back endpoint must be wss://: {endpoint}"))?
            .trim_end_matches('/');
        let tcp = TcpStream::connect(authority).await?;
        tcp.set_nodelay(true)?;

        let name = ServerName::try_from(self.server_name.clone())?;
        let tls = TlsConnector::from(self.tls_config()?)
            .connect(name, tcp)
            .await?;

        // The Host header carries the Gateway's NAME (what its certificate says), while
        // the TCP connection went to the address the signal carried.
        let url = format!("wss://{}{path}", self.server_name);
        let (ws, _resp) =
            client_async_with_config(url, tls, Some(ws_config(self.max_frame_bytes))).await?;
        Ok(ws)
    }

    /// Send `HELLO` and consume the Gateway's `HELLO_ACK` (contract §3).
    pub async fn hello(&self, ws: &mut ClientWs) -> anyhow::Result<Negotiated> {
        let hello = AgentHello {
            component: Some(version::component_info()),
        };
        // The preface frame carries the SENDER's protocol major.
        let ver = version::PROTOCOL_MAX.0 as u8;
        ws.send(Message::Binary(WsBytes::from(wire::encode_msg(
            ver,
            MsgType::Hello,
            &hello,
        ))))
        .await?;

        let frame = self.next_frame(ws, ver).await?;
        match frame.msg_type {
            MsgType::HelloAck => {
                let ack = wire::as_hello_ack(&frame)?;
                let selected = ack
                    .selected
                    .ok_or_else(|| anyhow::anyhow!("HELLO_ACK carried no version"))?;
                Ok(Negotiated {
                    ver: selected.major as u8,
                    heartbeat_interval_secs: ack.heartbeat_interval_secs,
                    max_frame_bytes: ack.max_frame_bytes as usize,
                })
            }
            // Fail closed: never retry with a guessed version (FR-HA-9).
            MsgType::VersionReject => anyhow::bail!("gateway rejected our protocol version"),
            other => anyhow::bail!("unexpected preface frame {other:?}"),
        }
    }

    /// Read the next wire frame. `pub` so an adversarial test can drive the framing
    /// itself (a replayed token, an oversized frame, a bad version) instead of using
    /// the well-behaved loops below.
    pub async fn next_frame(&self, ws: &mut ClientWs, ver: u8) -> anyhow::Result<Frame> {
        loop {
            let msg = ws
                .next()
                .await
                .ok_or_else(|| anyhow::anyhow!("connection closed"))??;
            match msg {
                Message::Binary(bytes) => {
                    let bytes = bytes::Bytes::copy_from_slice(&bytes);
                    // The preface reply may carry the Gateway's own major; accept the
                    // byte as-is and let the caller judge.
                    let seen = *bytes.first().unwrap_or(&ver);
                    return Ok(wire::decode(bytes, self.max_frame_bytes, seen)?);
                }
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Close(_) => anyhow::bail!("gateway closed the connection"),
                other => anyhow::bail!("unexpected websocket message: {other:?}"),
            }
        }
    }

    /// Run the control channel until `shutdown`: register, answer `PING`, and serve
    /// every `DIAL_BACK_REQUEST` on its own task (so a slow dial-back never blocks
    /// liveness).
    pub async fn run_control(
        &self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<()> {
        let mut ws = self.connect(&self.endpoint, CONTROL_PATH).await?;
        let negotiated = self.hello(&mut ws).await?;
        let ver = negotiated.ver;
        tracing::info!(node = %self.node_name, ver, "agent control channel registered");

        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => return Ok(()),
                msg = ws.next() => {
                    let Some(msg) = msg else { return Ok(()) };
                    let Message::Binary(bytes) = msg? else { continue };
                    let frame = wire::decode(bytes::Bytes::copy_from_slice(&bytes), negotiated.max_frame_bytes, ver)?;
                    match frame.msg_type {
                        MsgType::Ping => {
                            let nonce = wire::as_ping(&frame)?.nonce;
                            ws.send(Message::Binary(WsBytes::from(wire::encode_msg(ver, MsgType::Pong, &Pong { nonce })))).await?;
                        }
                        MsgType::DialBackRequest => {
                            let req = wire::as_dial_back_request(&frame)?;
                            // A Gateway must not be able to task this Agent for another
                            // node: refuse anything that is not the node we are bound to.
                            if req.node_name != self.node_name {
                                ws.send(Message::Binary(WsBytes::from(wire::encode_msg(ver, MsgType::DialBackResult, &DialBackResult {
                                    request_id: req.request_id,
                                    accepted: false,
                                    error: DialBackErrorCode::Refused as i32,
                                })))).await?;
                                continue;
                            }
                            ws.send(Message::Binary(WsBytes::from(wire::encode_msg(ver, MsgType::DialBackResult, &DialBackResult {
                                request_id: req.request_id.clone(),
                                accepted: true,
                                error: DialBackErrorCode::Unspecified as i32,
                            })))).await?;

                            let me = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = me.serve_dial_back(req).await {
                                    tracing::warn!(error = %e, "dial-back failed");
                                }
                            });
                        }
                        MsgType::Error => {
                            let err = wire::as_wire_error(&frame)?;
                            anyhow::bail!("gateway wire error (code {})", err.code);
                        }
                        other => anyhow::bail!("unexpected control frame {other:?}"),
                    }
                }
            }
        }
    }

    /// Send one raw frame (adversarial tests build their own).
    pub async fn send_frame(
        &self,
        ws: &mut ClientWs,
        ver: u8,
        msg_type: MsgType,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        ws.send(Message::Binary(WsBytes::from(wire::encode(
            ver, msg_type, payload,
        ))))
        .await?;
        Ok(())
    }

    /// One dial-back: open the connection, present the token, and splice the byte
    /// stream to the node's own local `sshd`.
    pub async fn serve_dial_back(&self, req: DialBackRequest) -> anyhow::Result<()> {
        let mut ws = self.connect(&req.dial_back_endpoint, DIALBACK_PATH).await?;
        let negotiated = self.hello(&mut ws).await?;
        let ver = negotiated.ver;

        ws.send(Message::Binary(WsBytes::from(wire::encode_msg(
            ver,
            MsgType::DialBackAuth,
            &DialBackAuth {
                token: req.token,
                request_id: req.request_id,
            },
        ))))
        .await?;

        let frame = self.next_frame(&mut ws, ver).await?;
        if frame.msg_type != MsgType::DialBackAccept {
            anyhow::bail!("dial-back refused: {:?}", frame.msg_type);
        }

        // The splice target is OURS, not the Gateway's. Nothing on that wire named it.
        let mut node = TcpStream::connect(&self.splice_addr).await?;
        node.set_nodelay(true)?;

        ws.send(Message::Binary(WsBytes::from(wire::encode_msg(
            ver,
            MsgType::StreamOpen,
            &StreamOpen {},
        ))))
        .await?;

        // Opaque bytes in both directions: this Agent structurally cannot read what it
        // carries (the SSH session is end-to-end between the Gateway and the node).
        let mut spliced = WsByteStream::new(ws, ver, negotiated.max_frame_bytes);
        let _ = tokio::io::copy_bidirectional(&mut spliced, &mut node).await;
        Ok(())
    }

    /// Reconnect with exponential backoff + jitter, indefinitely (contract §7). A
    /// reconnect re-runs the full TLS + mTLS + preface + registration path; there is no
    /// resumption and no cached authorization.
    pub async fn run_forever(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut backoff = Duration::from_millis(200);
        loop {
            let sd = {
                let mut sd = shutdown.clone();
                async move {
                    let _ = sd.wait_for(|v| *v).await;
                }
            };
            match self.run_control(sd).await {
                Ok(()) => backoff = Duration::from_millis(200),
                Err(e) => tracing::warn!(error = %e, "control channel dropped; reconnecting"),
            }
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                biased;
                _ = shutdown.wait_for(|v| *v) => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(5));
        }
    }
}
