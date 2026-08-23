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

const CHANNEL_CAPACITY: usize = 256;

const RECONNECT_BACKOFF: Duration = Duration::from_secs(1);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const CMD_QUEUE_CAP: usize = 1024;

const PING_INTERVAL: Duration = Duration::from_secs(20);

const MAX_CONTROL_LINE: usize = 8192;

const CONNECT: &[u8] =
    b"CONNECT {\"verbose\":false,\"pedantic\":false,\"name\":\"sessionlayer-gateway\"}\r\n";

enum Cmd {
    Pub(Vec<u8>),
    Sub(String),
}

fn dialback_subject(prefix: &str, gateway_id: &str) -> String {
    format!("{prefix}.dialback.{gateway_id}")
}

pub struct NatsBackend {
    subject_prefix: String,
    cmd_tx: mpsc::Sender<Cmd>,
    subs: Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>>,
    connected: Arc<AtomicBool>,
}

impl NatsBackend {
    /// Returns immediately; first connect happens in background.
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
                return Err(CoordinationError::Transport(
                    "NATS not connected".to_string(),
                ));
            }
            let mut cmd = format!("PUB {subject} {}\r\n", payload.len()).into_bytes();
            cmd.extend_from_slice(&payload);
            cmd.extend_from_slice(b"\r\n");
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

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// ±50% jitter (matches the Agent's and the agent-control-channel's reconnect
/// jitter) so a broker/CP restart doesn't resync every Gateway's retry timer.
/// `sample` is `[-1, 1]`; split out from the RNG draw so the bound is unit-testable.
fn jittered_backoff(base: Duration, sample: f64) -> Duration {
    base.mul_f64(1.0 + 0.5 * sample.clamp(-1.0, 1.0))
}

fn random_sample() -> f64 {
    use rand_core::RngCore;
    (f64::from(rand_core::OsRng.next_u32()) / f64::from(u32::MAX)) * 2.0 - 1.0
}

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

struct BackendDropped;

async fn connection_manager(
    addr: String,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    subs: Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>>,
    connected: Arc<AtomicBool>,
) {
    loop {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                match run_connection(stream, &mut cmd_rx, &subs, &connected).await {
                    Ok(BackendDropped) => {
                        connected.store(false, Ordering::SeqCst);
                        return;
                    }
                    Err(NatsError::Fatal(reason)) => {
                        connected.store(false, Ordering::SeqCst);
                        tracing::error!(addr = %addr, reason = %reason, "NATS broker requires a capability this plaintext reference client cannot provide (run a TLS/auth sidecar or substitute a TLS-capable CoordinationBackend); stopping - HA signalling is DOWN and remote-owned sessions will fail closed");
                        return;
                    }
                    Err(NatsError::Io(e)) => {
                        tracing::info!(addr = %addr, error = %e, "NATS connection ended; reconnecting");
                    }
                }
                connected.store(false, Ordering::SeqCst);
            }
            Ok(Err(e)) => {
                tracing::info!(addr = %addr, error = %e, "NATS connect failed; retrying");
            }
            Err(_) => {
                tracing::info!(addr = %addr, timeout = ?CONNECT_TIMEOUT, "NATS connect timed out; retrying");
            }
        }
        tokio::time::sleep(jittered_backoff(RECONNECT_BACKOFF, random_sample())).await;
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

    let info = read_control_line(&mut rd).await?;
    if !info.starts_with("INFO") {
        return Err(NatsError::Io(std::io::Error::other(
            "expected NATS INFO greeting",
        )));
    }
    if let Some(reason) = info_requires_unsupported(&info) {
        return Err(NatsError::Fatal(reason.to_string()));
    }
    wr.write_all(CONNECT).await?;

    let mut subscribed: HashSet<String> = HashSet::new();
    let mut next_sid: u64 = 0;
    let subjects: Vec<String> = lock(subs).keys().cloned().collect();
    for subject in subjects {
        next_sid += 1;
        wr.write_all(format!("SUB {subject} {next_sid}\r\n").as_bytes())
            .await?;
        subscribed.insert(subject);
    }
    connected.store(true, Ordering::SeqCst);

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

    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let outcome = loop {
        tokio::select! {
            biased;
            err = &mut dead_rx => {
                break Err(NatsError::Io(err.unwrap_or_else(|_| std::io::Error::other("NATS reader task gone"))));
            }
            Some(pong) = ctl_rx.recv() => {
                if let Err(e) = wr.write_all(&pong).await { break Err(NatsError::Io(e)); }
            }
            _ = ping.tick() => {
                if awaiting_pong.swap(true, Ordering::SeqCst) {
                    break Err(NatsError::Io(std::io::Error::other("NATS PONG deadline missed (connection black-holed)")));
                }
                if let Err(e) = wr.write_all(b"PING\r\n").await { break Err(NatsError::Io(e)); }
            }
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
                None => break Ok(BackendDropped),
            }
        }
    };
    reader.abort();
    outcome
}

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
            LineKind::Other => {}
        }
    }
}

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

fn info_requires_unsupported(info: &str) -> Option<&'static str> {
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
    while matches!(buf.last(), Some(b'\r') | Some(b'\n')) {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|_| std::io::Error::other("non-UTF-8 NATS control line"))
}

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
    if len > 1024 * 1024 {
        return Err(std::io::Error::other("oversized NATS payload"));
    }
    let mut buf = vec![0u8; len];
    rd.read_exact(&mut buf).await?;
    let mut crlf = [0u8; 2];
    let _ = rd.read_exact(&mut crlf).await;

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
    fn jittered_backoff_stays_within_half_bounds() {
        let base = Duration::from_secs(1);
        assert_eq!(jittered_backoff(base, 0.0), base);
        assert_eq!(jittered_backoff(base, -1.0), Duration::from_millis(500));
        assert_eq!(jittered_backoff(base, 1.0), Duration::from_millis(1500));
        assert_eq!(jittered_backoff(base, -9.0), Duration::from_millis(500));
        assert_eq!(jittered_backoff(base, 9.0), Duration::from_millis(1500));
    }

    #[test]
    fn control_lines_are_classified() {
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
        assert!(
            info_requires_unsupported("INFO {\"server_id\":\"a\",\"tls_required\":true}").is_some()
        );
        assert!(info_requires_unsupported("INFO {\"auth_required\":true}").is_some());
        assert!(
            info_requires_unsupported("INFO {\"server_id\":\"a\",\"max_payload\":1048576}")
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_unterminated_control_line_is_bounded() {
        let flood = vec![b'x'; MAX_CONTROL_LINE + 4096];
        let mut reader: &[u8] = &flood;
        let err = read_control_line(&mut reader).await.unwrap_err();
        assert_eq!(err.to_string(), "oversized NATS control line");
    }

    #[tokio::test]
    async fn a_control_line_reads_and_trims_crlf() {
        let mut reader: &[u8] = b"PING\r\nrest";
        assert_eq!(read_control_line(&mut reader).await.unwrap(), "PING");
    }

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

    #[tokio::test]
    async fn msg_for_an_unknown_subject_is_dropped() {
        let subs: Arc<Mutex<HashMap<String, broadcast::Sender<DialBackSignal>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let payload = DialBackSignal::default().encode_to_vec();
        let line = format!("MSG sl.dialback.nobody 1 {}", payload.len());
        let mut body = payload.clone();
        body.extend_from_slice(b"\r\n");
        let mut reader: &[u8] = &body;
        handle_msg(&line, &mut reader, &subs).await.unwrap();
    }
}
