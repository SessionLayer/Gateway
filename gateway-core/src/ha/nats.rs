//! A hand-rolled minimal **NATS core** pub/sub client — the HA coordination reference backend
//! (Session Fifteen; FR-HA-3, Design §10.2). Only the signaling subset: `INFO`/`CONNECT`,
//! `SUB`, `PUB`, `PING`/`PONG`, `MSG`. No JetStream, no request-reply, no TLS. **Zero extra
//! dependencies** (tokio + prost only) — the repo's ring-only / no-webpki-roots supply-chain
//! posture (cf. the hand-rolled SigV4 + WORM PUT) rules out `async-nats`' TLS tree, which drags
//! in live `rustls-webpki` advisories and MPL-2.0 `webpki-roots`.
//!
//! ## Security posture
//!
//! Plaintext core NATS is acceptable for the reference backend **on a trusted internal
//! network** because (a) session bytes NEVER traverse the bus — only the [`DialBackSignal`]
//! does (Design §10.2 anti-requirement), and (b) the signal's relay token (SLGW1) is
//! single-use AND bound to the owner's mTLS **gateway identity**: an eavesdropper who reads
//! the bus cannot redeem it without presenting the owner's client certificate. Operators
//! SHOULD run NATS on a trusted network (or NATS-over-TLS via a sidecar/mesh) in production.
//!
//! Delivery is best-effort (core NATS, no durability): a lost signal just means the ingress
//! times out and fails the session closed — exactly the [`InProcessBackend`] contract.
//!
//! [`InProcessBackend`]: super::coordination::InProcessBackend

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::stream::BoxStream;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

use super::coordination::{CoordinationBackend, CoordinationError, PublishFuture};
use crate::pbgw::DialBackSignal;

/// Per-subject broadcast capacity (a signal is tiny and consumed immediately; this only
/// bounds a burst before the single subscriber drains it — an overrun drops the oldest, and
/// those sessions time out and fail closed, never a byte-path effect).
const CHANNEL_CAPACITY: usize = 256;

/// Reconnect backoff bound (a partitioned broker: keep retrying so ownership signalling
/// recovers when NATS comes back; while down, publishes fail and the ingress fails closed).
const RECONNECT_BACKOFF: Duration = Duration::from_secs(1);

/// The subject family (`{prefix}.dialback.{gateway_name}`) HA signalling uses.
fn dialback_subject(prefix: &str, gateway_id: &str) -> String {
    format!("{prefix}.dialback.{gateway_id}")
}

/// The minimal NATS coordination backend. Cheap to share (`Arc`); holds a persistent
/// connection managed by a background task with automatic reconnect + re-subscribe.
pub struct NatsBackend {
    subject_prefix: String,
    /// Raw NATS command bytes to write to the socket (`PUB`/`SUB`). Drained by the writer.
    cmd_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Subject -> the fan-out every local subscriber of that subject reads from. Re-SUBscribed
    /// on each (re)connect.
    subs: Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>>,
    connected: Arc<AtomicBool>,
}

impl NatsBackend {
    /// Connect to `url` (`nats://host:port`), spawning the connection manager (which connects,
    /// reconnects, and re-subscribes). Returns immediately; the first connect happens in the
    /// background so a briefly-unavailable broker does not block startup.
    pub fn connect(url: &str, subject_prefix: &str) -> Result<Self, CoordinationError> {
        let host_port = url
            .strip_prefix("nats://")
            .unwrap_or(url)
            .trim_end_matches('/')
            .to_string();
        if host_port.is_empty() {
            return Err(CoordinationError::Transport(format!(
                "invalid NATS url {url:?}"
            )));
        }
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let subs = Arc::new(Mutex::new(HashMap::new()));
        let connected = Arc::new(AtomicBool::new(false));
        tokio::spawn(connection_manager(
            host_port,
            cmd_rx,
            subs.clone(),
            connected.clone(),
        ));
        Ok(Self {
            subject_prefix: subject_prefix.to_string(),
            cmd_tx,
            subs,
            connected,
        })
    }

    fn ensure_subscribed(&self, subject: &str) -> broadcast::Receiver<DialBackSignal> {
        let mut map = lock(&self.subs);
        if let Some(tx) = map.get(subject) {
            return tx.subscribe();
        }
        let (tx, rx) = broadcast::channel(CHANNEL_CAPACITY);
        map.insert(subject.to_string(), tx);
        // Send SUB now (a no-op on the wire if disconnected — the connection manager re-SUBs
        // every subject on the next connect).
        let sid = map.len();
        let _ = self
            .cmd_tx
            .send(format!("SUB {subject} {sid}\r\n").into_bytes());
        rx
    }
}

impl CoordinationBackend for NatsBackend {
    fn publish_dial_back<'a>(
        &'a self,
        owner_gateway_id: &'a str,
        signal: &'a DialBackSignal,
    ) -> PublishFuture<'a> {
        let subject = dialback_subject(&self.subject_prefix, owner_gateway_id);
        let payload = signal.encode_to_vec();
        let connected = self.connected.load(Ordering::SeqCst);
        let cmd_tx = self.cmd_tx.clone();
        Box::pin(async move {
            if !connected {
                // Broker unreachable: fail closed at once (better than the ingress timeout).
                return Err(CoordinationError::Transport(
                    "NATS not connected".to_string(),
                ));
            }
            let mut cmd = format!("PUB {subject} {}\r\n", payload.len()).into_bytes();
            cmd.extend_from_slice(&payload);
            cmd.extend_from_slice(b"\r\n");
            cmd_tx
                .send(cmd)
                .map_err(|_| CoordinationError::Transport("NATS writer gone".to_string()))
        })
    }

    fn subscribe(&self, my_gateway_id: &str) -> BoxStream<'static, DialBackSignal> {
        let subject = dialback_subject(&self.subject_prefix, my_gateway_id);
        let rx = self.ensure_subscribed(&subject);
        Box::pin(broadcast_stream(rx))
    }
}

fn broadcast_stream(
    rx: broadcast::Receiver<DialBackSignal>,
) -> impl futures_util::Stream<Item = DialBackSignal> {
    futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(sig) => return Some((sig, rx)),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

/// Recover a poisoned lock rather than propagate the panic — the relay-signalling critical
/// sections run no user code, so the guarded state is always consistent (Tier-0: never wedge
/// signalling because an unrelated task panicked).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Connect, handshake, re-subscribe, and pump until the connection drops; then reconnect.
async fn connection_manager(
    addr: String,
    mut cmd_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    subs: Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>>,
    connected: Arc<AtomicBool>,
) {
    loop {
        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                if let Err(e) = run_connection(stream, &mut cmd_rx, &subs, &connected).await {
                    tracing::info!(addr = %addr, error = %e, "NATS connection ended; reconnecting");
                }
                connected.store(false, Ordering::SeqCst);
            }
            Err(e) => {
                tracing::info!(addr = %addr, error = %e, "NATS connect failed; retrying");
            }
        }
        tokio::time::sleep(RECONNECT_BACKOFF).await;
    }
}

async fn run_connection(
    stream: TcpStream,
    cmd_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    subs: &Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>>,
    connected: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    // The server greets with INFO first; then we CONNECT (verbose off so there are no +OK acks
    // to interleave with MSG).
    let info = read_control_line(&mut rd).await?;
    if !info.starts_with("INFO") {
        return Err(std::io::Error::other("expected NATS INFO greeting"));
    }
    wr.write_all(
        b"CONNECT {\"verbose\":false,\"pedantic\":false,\"name\":\"sessionlayer-gateway\"}\r\n",
    )
    .await?;

    // (Re)subscribe every subject a local subscriber wants.
    let subjects: Vec<String> = lock(subs).keys().cloned().collect();
    for (i, subject) in subjects.iter().enumerate() {
        wr.write_all(
            format!("SUB {subject} {}\r\n", i + 1)
                .into_bytes()
                .as_slice(),
        )
        .await?;
    }
    connected.store(true, Ordering::SeqCst);

    loop {
        tokio::select! {
            biased;
            // Outbound commands (PUB from publish, SUB from a late subscribe).
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(bytes) => wr.write_all(&bytes).await?,
                    None => return Ok(()), // the backend was dropped
                }
            }
            // Inbound protocol.
            line = read_control_line(&mut rd) => {
                let line = line?;
                if line.starts_with("PING") {
                    wr.write_all(b"PONG\r\n").await?;
                } else if line.starts_with("MSG ") {
                    handle_msg(&line, &mut rd, subs).await?;
                } else if let Some(err) = line.strip_prefix("-ERR") {
                    // A protocol error from the server (e.g. a bad subject): log, keep going.
                    tracing::warn!(error = %err.trim(), "NATS -ERR");
                }
                // +OK / PONG / INFO updates: ignore.
            }
        }
    }
}

/// Read one CRLF-terminated NATS control line. The line is short (a header); a broken server
/// sending an unterminated line is bounded by the caller trusting the broker (see the security
/// note) — we still cap the accepted length as hygiene.
async fn read_control_line<R: tokio::io::AsyncBufRead + Unpin>(
    rd: &mut R,
) -> std::io::Result<String> {
    use tokio::io::AsyncBufReadExt;
    let mut line = String::new();
    let n = rd.read_line(&mut line).await?;
    if n == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    if line.len() > 8192 {
        return Err(std::io::Error::other("oversized NATS control line"));
    }
    Ok(line.trim_end().to_string())
}

/// `MSG <subject> <sid> [reply] <#bytes>\r\n<payload>\r\n` — read the payload, decode the
/// signal, and dispatch it to the subject's local fan-out.
async fn handle_msg<R: tokio::io::AsyncRead + Unpin>(
    line: &str,
    rd: &mut R,
    subs: &Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>>,
) -> std::io::Result<()> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    // MSG <subject> <sid> <#bytes>  OR  MSG <subject> <sid> <reply> <#bytes>
    let (subject, len_str) = match parts.as_slice() {
        [_, subject, _sid, len] => (*subject, *len),
        [_, subject, _sid, _reply, len] => (*subject, *len),
        _ => return Err(std::io::Error::other("malformed NATS MSG")),
    };
    let len: usize = len_str
        .parse()
        .map_err(|_| std::io::Error::other("bad NATS payload length"))?;
    // Bound the payload (the signal is small; a huge length is a broken/hostile server).
    if len > 1024 * 1024 {
        return Err(std::io::Error::other("oversized NATS payload"));
    }
    let mut buf = vec![0u8; len];
    rd.read_exact(&mut buf).await?;
    // Trailing CRLF after the payload.
    let mut crlf = [0u8; 2];
    let _ = rd.read_exact(&mut crlf).await;

    // Verify-then-nothing: decode the signal; a bad payload is dropped (fail closed — the
    // ingress times out). Verification of the SLGW1 token happens at the relay, not here.
    if let Ok(signal) = DialBackSignal::decode(buf.as_slice()) {
        if let Some(tx) = lock(subs).get(subject) {
            let _ = tx.send(signal); // no subscriber ⇒ dropped ⇒ ingress fails closed
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_layout_is_prefixed_and_per_gateway() {
        assert_eq!(dialback_subject("sl", "gw-B"), "sl.dialback.gw-B");
        assert_eq!(dialback_subject("prod", "gw-a-ha"), "prod.dialback.gw-a-ha");
    }

    #[test]
    fn an_invalid_url_is_rejected() {
        assert!(NatsBackend::connect("nats://", "sl").is_err());
    }

    /// The MSG frame parser reassembles the payload and decodes the signal end-to-end against a
    /// real prost-encoded `DialBackSignal` (the risk-carrying part of the hand-rolled codec).
    #[tokio::test]
    async fn msg_frame_decodes_and_dispatches_the_signal() {
        let subs: Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (tx, mut rx) = broadcast::channel(16);
        lock(&subs).insert("sl.dialback.gw-B".to_string(), tx);

        let signal = DialBackSignal {
            node_name: "node-a".into(),
            owner_gateway_id: "gw-B".into(),
            relay_token: "SLGW1.x.y".into(),
            owner_nonce: 7,
            ..Default::default()
        };
        let payload = signal.encode_to_vec();
        // The caller consumes the control line; handle_msg reads the payload + trailing CRLF
        // from the reader. `&[u8]` implements tokio's AsyncRead.
        let line = format!("MSG sl.dialback.gw-B 1 {}", payload.len());
        let mut body = payload.clone();
        body.extend_from_slice(b"\r\n");
        let mut reader: &[u8] = &body;
        handle_msg(&line, &mut reader, &subs).await.unwrap();

        let got = rx.recv().await.unwrap();
        assert_eq!(got.node_name, "node-a");
        assert_eq!(got.owner_nonce, 7);
        assert_eq!(got.relay_token, "SLGW1.x.y");
    }

    /// A subject with no local subscriber drops the signal (⇒ the ingress times out and fails
    /// closed), never a panic.
    #[tokio::test]
    async fn msg_for_an_unknown_subject_is_dropped() {
        let subs: Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let payload = DialBackSignal::default().encode_to_vec();
        let line = format!("MSG sl.dialback.nobody 1 {}", payload.len());
        let mut body = payload.clone();
        body.extend_from_slice(b"\r\n");
        let mut reader: &[u8] = &body;
        handle_msg(&line, &mut reader, &subs).await.unwrap(); // must not panic
    }
}
