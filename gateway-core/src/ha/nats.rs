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
//! SHOULD run NATS on a trusted network (or NATS-over-TLS via a sidecar/mesh) in production;
//! this plaintext client **fails loudly** (F8) if the broker advertises `tls_required` /
//! `auth_required` it cannot satisfy, so a misconfiguration surfaces at once rather than as a
//! silent reconnect loop.
//!
//! Delivery is best-effort (core NATS, no durability): a lost signal just means the ingress
//! times out and fails the session closed — exactly the [`InProcessBackend`] contract.
//!
//! [`InProcessBackend`]: super::coordination::InProcessBackend

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::stream::BoxStream;
use prost::Message;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};

use super::coordination::{CoordinationBackend, CoordinationError, PublishFuture};
use crate::pbgw::DialBackSignal;

/// Per-subject broadcast capacity (a signal is tiny and consumed immediately; this only
/// bounds a burst before the single subscriber drains it — an overrun drops the oldest, and
/// those sessions time out and fail closed, never a byte-path effect).
const CHANNEL_CAPACITY: usize = 256;

/// Reconnect backoff bound (a partitioned broker: keep retrying so ownership signalling
/// recovers when NATS comes back; while down, publishes fail and the ingress fails closed).
const RECONNECT_BACKOFF: Duration = Duration::from_secs(1);

/// Bounded outbound command queue (L3): a broker partition must not let PUB/SUB commands pile
/// up unboundedly and then flush a burst of STALE signals on reconnect. `try_send` drops (fails
/// closed) at the bound rather than blocking the SSH handshake.
const CMD_QUEUE_CAP: usize = 1024;

/// Client-initiated liveness PING cadence (F7): a black-holed TCP connection (no RST) is
/// detected by a missed PONG within one interval, tripping a reconnect. Cheap on a signalling
/// bus.
const PING_INTERVAL: Duration = Duration::from_secs(20);

/// Hard cap on one NATS control line (F1): a broken/hostile broker sending an unterminated
/// line errors at ~this bound instead of growing a `String` without limit.
const MAX_CONTROL_LINE: usize = 8192;

/// The unauthenticated plaintext CONNECT (verbose off so there are no `+OK` acks to interleave
/// with MSG). See the security note — production supplies TLS/auth via a sidecar.
const CONNECT: &[u8] =
    b"CONNECT {\"verbose\":false,\"pedantic\":false,\"name\":\"sessionlayer-gateway\"}\r\n";

/// An outbound command for the connection writer. `Sub` is emitted by the connection manager as
/// the SOLE SUB source (F3 dedup) so a queued subscribe cannot double a `SUB` the reconnect
/// re-emits from the map.
enum Cmd {
    Pub(Vec<u8>),
    Sub(String),
}

/// The subject family (`{prefix}.dialback.{gateway_name}`) HA signalling uses.
fn dialback_subject(prefix: &str, gateway_id: &str) -> String {
    format!("{prefix}.dialback.{gateway_id}")
}

/// The minimal NATS coordination backend. Cheap to share (`Arc`); holds a persistent
/// connection managed by a background task with automatic reconnect + re-subscribe.
pub struct NatsBackend {
    subject_prefix: String,
    /// Bounded outbound command channel (`PUB`/`SUB`). Drained by the connection writer.
    cmd_tx: mpsc::Sender<Cmd>,
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
        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_QUEUE_CAP);
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

    /// Whether the connection manager currently holds a live NATS connection (used by tests and
    /// as the fast fail-closed gate in `publish_dial_back`).
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    fn ensure_subscribed(&self, subject: &str) -> broadcast::Receiver<DialBackSignal> {
        let mut map = lock(&self.subs);
        if let Some(tx) = map.get(subject) {
            return tx.subscribe();
        }
        let (tx, rx) = broadcast::channel(CHANNEL_CAPACITY);
        map.insert(subject.to_string(), tx);
        // Best-effort: ask the connection manager (the SOLE SUB emitter, F3) to subscribe now.
        // If disconnected or the queue is full, the next (re)connect re-SUBs every map subject.
        let _ = self.cmd_tx.try_send(Cmd::Sub(subject.to_string()));
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
            // F9: unlike the in-process backend, a core-NATS PUB to a subject with NO subscriber
            // SUCCEEDS silently — the broker cannot tell the ingress "no owner". So a genuinely
            // absent owner is NOT surfaced here; `relay_timeout` at the connector is the backstop
            // (the ingress waits out the bound and fails closed). This is by design (best-effort
            // signalling); durability/ack would need JetStream, which is out of scope.
            let mut cmd = format!("PUB {subject} {}\r\n", payload.len()).into_bytes();
            cmd.extend_from_slice(&payload);
            cmd.extend_from_slice(b"\r\n");
            // `try_send` never blocks the SSH handshake; a full queue (L3 bound) fails closed.
            cmd_tx.try_send(Cmd::Pub(cmd)).map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => {
                    CoordinationError::Transport("NATS publish queue full".to_string())
                }
                mpsc::error::TrySendError::Closed(_) => {
                    CoordinationError::Transport("NATS writer gone".to_string())
                }
            })
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

/// A NATS connection error. `Fatal` is a misconfiguration the plaintext client can never meet
/// (F8) — the manager stops and logs loudly rather than reconnect-looping forever; `Io` is a
/// transient failure that triggers a bounded reconnect.
#[derive(Debug)]
enum NatsError {
    Io(std::io::Error),
    Fatal(String),
}

impl From<std::io::Error> for NatsError {
    fn from(e: std::io::Error) -> Self {
        NatsError::Io(e)
    }
}

/// The run_connection Ok result: the backend was dropped (cmd channel closed) ⇒ stop the
/// manager. Any transient/fatal condition is an `Err(NatsError)`.
struct BackendDropped;

/// Connect, handshake, re-subscribe, and pump until the connection drops; then reconnect.
async fn connection_manager(
    addr: String,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    subs: Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>>,
    connected: Arc<AtomicBool>,
) {
    loop {
        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                match run_connection(stream, &mut cmd_rx, &subs, &connected).await {
                    Ok(BackendDropped) => {
                        connected.store(false, Ordering::SeqCst);
                        return; // the NatsBackend was dropped: stop the manager
                    }
                    Err(NatsError::Fatal(reason)) => {
                        connected.store(false, Ordering::SeqCst);
                        tracing::error!(addr = %addr, reason = %reason, "NATS broker requires a capability this plaintext reference client cannot provide (run a TLS/auth sidecar or substitute a TLS-capable CoordinationBackend); stopping — HA signalling is DOWN and remote-owned sessions will fail closed");
                        return; // F8: fail loud, do NOT reconnect-loop against a misconfig
                    }
                    Err(NatsError::Io(e)) => {
                        tracing::info!(addr = %addr, error = %e, "NATS connection ended; reconnecting");
                    }
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
    cmd_rx: &mut mpsc::Receiver<Cmd>,
    subs: &Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>>,
    connected: &Arc<AtomicBool>,
) -> Result<BackendDropped, NatsError> {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    // The server greets with INFO first; then we CONNECT.
    let info = read_control_line(&mut rd).await?;
    if !info.starts_with("INFO") {
        return Err(NatsError::Io(std::io::Error::other(
            "expected NATS INFO greeting",
        )));
    }
    // F8: a broker demanding TLS/auth we cannot satisfy is a fatal misconfiguration, not a
    // transient error — surface it loudly instead of a silent reconnect loop.
    if let Some(reason) = info_requires_unsupported(&info) {
        return Err(NatsError::Fatal(reason.to_string()));
    }
    wr.write_all(CONNECT).await?;

    // (Re)subscribe every subject a local subscriber wants — the connection manager is the SOLE
    // SUB emitter (F3), tracking which subjects are already SUB'd on THIS connection so a queued
    // `Cmd::Sub` cannot double one.
    let mut subscribed: HashSet<String> = HashSet::new();
    let mut next_sid: u64 = 0;
    // Collect + drop the guard BEFORE the await loop (the guard is not Send).
    let subjects: Vec<String> = lock(subs).keys().cloned().collect();
    for subject in subjects {
        next_sid += 1;
        wr.write_all(format!("SUB {subject} {next_sid}\r\n").as_bytes())
            .await?;
        subscribed.insert(subject);
    }
    connected.store(true, Ordering::SeqCst);

    // Move the socket READ into its own task so a control-line read is never cancelled mid-line
    // by the writer's select (which would desync the stream). The reader dispatches MSG itself,
    // answers a server PING via `ctl_tx`, and clears `awaiting_pong` on a PONG.
    let (ctl_tx, mut ctl_rx) = mpsc::channel::<Vec<u8>>(8);
    let (dead_tx, mut dead_rx) = oneshot::channel::<std::io::Error>();
    let awaiting_pong = Arc::new(AtomicBool::new(false));
    let reader = tokio::spawn(reader_loop(
        rd,
        subs.clone(),
        ctl_tx,
        awaiting_pong.clone(),
        dead_tx,
    ));

    // Writer + liveness loop.
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await; // the first tick is immediate — consume it
    let outcome = loop {
        tokio::select! {
            biased;
            // The reader hit EOF / a read error: reconnect.
            err = &mut dead_rx => {
                break Err(NatsError::Io(err.unwrap_or_else(|_| std::io::Error::other("NATS reader task gone"))));
            }
            // A PONG the reader asked us to send in reply to a server PING.
            Some(pong) = ctl_rx.recv() => {
                if let Err(e) = wr.write_all(&pong).await { break Err(NatsError::Io(e)); }
            }
            // Client-initiated liveness PING with a one-interval PONG deadline (F7).
            _ = ping.tick() => {
                if awaiting_pong.swap(true, Ordering::SeqCst) {
                    break Err(NatsError::Io(std::io::Error::other("NATS PONG deadline missed (connection black-holed)")));
                }
                if let Err(e) = wr.write_all(b"PING\r\n").await { break Err(NatsError::Io(e)); }
            }
            // Outbound app commands (PUB / a late SUB).
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::Pub(bytes)) => {
                    if let Err(e) = wr.write_all(&bytes).await { break Err(NatsError::Io(e)); }
                }
                Some(Cmd::Sub(subject)) => {
                    if subscribed.insert(subject.clone()) {
                        next_sid += 1;
                        if let Err(e) = wr.write_all(format!("SUB {subject} {next_sid}\r\n").as_bytes()).await {
                            break Err(NatsError::Io(e));
                        }
                    }
                }
                None => break Ok(BackendDropped), // the backend was dropped
            }
        }
    };
    reader.abort();
    outcome
}

/// The socket reader task: parse control lines, dispatch MSG, answer a server PING with a PONG,
/// and clear the liveness flag on a PONG. On a read error it reports via `dead_tx` and ends.
async fn reader_loop<R: AsyncBufRead + Unpin>(
    mut rd: R,
    subs: Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>>,
    ctl_tx: mpsc::Sender<Vec<u8>>,
    awaiting_pong: Arc<AtomicBool>,
    dead_tx: oneshot::Sender<std::io::Error>,
) {
    loop {
        let line = match read_control_line(&mut rd).await {
            Ok(line) => line,
            Err(e) => {
                let _ = dead_tx.send(e);
                return;
            }
        };
        match classify_line(&line) {
            LineKind::Ping => {
                let _ = ctl_tx.try_send(b"PONG\r\n".to_vec());
            }
            LineKind::Pong => awaiting_pong.store(false, Ordering::SeqCst),
            LineKind::Msg => {
                if let Err(e) = handle_msg(&line, &mut rd, &subs).await {
                    let _ = dead_tx.send(e);
                    return;
                }
            }
            LineKind::Err => tracing::warn!(error = %line.trim(), "NATS -ERR"),
            LineKind::Other => {} // +OK / INFO updates: ignore
        }
    }
}

/// The classes of NATS control line the reader acts on (kept pure so the PING/PONG/MSG parse is
/// unit-tested without a live broker — F2 regression guard).
#[derive(Debug, PartialEq, Eq)]
enum LineKind {
    Ping,
    Pong,
    Msg,
    Err,
    Other,
}

fn classify_line(line: &str) -> LineKind {
    if line.starts_with("MSG ") {
        LineKind::Msg
    } else if line.starts_with("PING") {
        LineKind::Ping
    } else if line.starts_with("PONG") {
        LineKind::Pong
    } else if line.starts_with("-ERR") {
        LineKind::Err
    } else {
        LineKind::Other
    }
}

/// Whether the server `INFO` advertises a capability this plaintext client cannot satisfy (F8):
/// TLS or authentication. Returns a human reason for the fatal error.
fn info_requires_unsupported(info: &str) -> Option<&'static str> {
    // NATS INFO is compact JSON; a required capability appears as `"tls_required":true` /
    // `"auth_required":true`. The plaintext reference client can meet neither.
    if info.contains("\"tls_required\":true") {
        return Some("broker advertises tls_required, but the reference NATS client is plaintext");
    }
    if info.contains("\"auth_required\":true") {
        return Some(
            "broker advertises auth_required, but the reference NATS client sends an unauthenticated CONNECT",
        );
    }
    None
}

/// Read one CRLF-terminated NATS control line, bounded to [`MAX_CONTROL_LINE`] (F1): an
/// unterminated line errors at the cap instead of growing without limit. Only ever called from
/// the single reader task, so it is never cancelled mid-line.
async fn read_control_line<R: AsyncBufRead + Unpin>(rd: &mut R) -> std::io::Result<String> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = rd.fill_buf().await?;
        if available.is_empty() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                buf.extend_from_slice(&available[..=pos]);
                rd.consume(pos + 1);
                break;
            }
            None => {
                let n = available.len();
                buf.extend_from_slice(available);
                rd.consume(n);
                if buf.len() > MAX_CONTROL_LINE {
                    return Err(std::io::Error::other("oversized NATS control line"));
                }
            }
        }
    }
    // Trim the trailing CRLF; reject a non-UTF-8 control line (a broken/hostile broker).
    while matches!(buf.last(), Some(b'\r') | Some(b'\n')) {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|_| std::io::Error::other("non-UTF-8 NATS control line"))
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

    #[test]
    fn control_lines_are_classified() {
        // The PING/PONG/MSG parse gated without a live broker (F2 regression guard).
        assert_eq!(classify_line("PING"), LineKind::Ping);
        assert_eq!(classify_line("PING\r"), LineKind::Ping);
        assert_eq!(classify_line("PONG"), LineKind::Pong);
        assert_eq!(classify_line("MSG sl.dialback.gw-B 1 42"), LineKind::Msg);
        assert_eq!(classify_line("-ERR 'Unknown Protocol'"), LineKind::Err);
        assert_eq!(classify_line("+OK"), LineKind::Other);
        assert_eq!(classify_line("INFO {\"x\":1}"), LineKind::Other);
    }

    #[test]
    fn info_flags_tls_and_auth_requirements_as_fatal() {
        // F8: the plaintext client must fail loud, not loop, when the broker demands TLS/auth.
        assert!(
            info_requires_unsupported("INFO {\"server_id\":\"a\",\"tls_required\":true}").is_some()
        );
        assert!(info_requires_unsupported("INFO {\"auth_required\":true}").is_some());
        // A vanilla trusted-network broker is fine.
        assert!(
            info_requires_unsupported("INFO {\"server_id\":\"a\",\"max_payload\":1048576}")
                .is_none()
        );
    }

    /// An oversized, unterminated control line errors at the bound (F1) rather than growing.
    #[tokio::test]
    async fn an_unterminated_control_line_is_bounded() {
        let flood = vec![b'x'; MAX_CONTROL_LINE + 4096];
        let mut reader: &[u8] = &flood; // never a '\n'
        let err = read_control_line(&mut reader).await.unwrap_err();
        assert_eq!(err.to_string(), "oversized NATS control line");
    }

    /// A well-formed line reads and trims its CRLF.
    #[tokio::test]
    async fn a_control_line_reads_and_trims_crlf() {
        let mut reader: &[u8] = b"PING\r\nrest";
        assert_eq!(read_control_line(&mut reader).await.unwrap(), "PING");
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
            node_name: "web-01".into(),
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
        assert_eq!(got.node_name, "web-01");
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
