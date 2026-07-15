//! A minimal readiness surface (Session Fifteen; Design §10.3). An L4/L7 load balancer polls
//! `GET /readyz` and deregisters a Gateway that answers `503` — so on SIGTERM the LB stops
//! sending NEW connections before this Gateway tears its live sessions down (graceful drain).
//!
//! Deliberately dep-free (raw TCP + a fixed HTTP/1.1 response): a readiness probe reads only
//! the status line, so there is no need to pull a hyper server onto the Tier-0 data plane.
//! Any request returns the current readiness — the probe path is not parsed.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const READY: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nready\n";
const DRAINING: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\ndraining\n";

/// Bound on reading a probe's request before responding, so a stalled prober cannot hold the
/// slot.
const PROBE_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Bind the readiness listener and serve until `shutdown` flips true. `ready` reports the
/// current state (`true` ⇒ `200`, `false` ⇒ `503`). Returns an error only if the bind fails
/// (fail closed at startup); a per-connection error is logged and dropped.
pub async fn bind_and_serve(
    addr: &str,
    ready: watch::Receiver<bool>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "readiness surface listening on /readyz");
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        let ready = ready.clone();
                        tokio::spawn(async move {
                            let _ = respond(stream, ready).await;
                        });
                    }
                    Err(e) => tracing::debug!(error = %e, "readiness accept failed"),
                }
            }
        }
    }
}

/// Spawn [`bind_and_serve`] as a background task (a bind failure is logged, not fatal — the
/// readiness surface is best-effort observability, not on the auth/data path).
pub fn spawn(
    addr: String,
    ready: watch::Receiver<bool>,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = bind_and_serve(&addr, ready, shutdown).await {
            tracing::warn!(addr = %addr, error = %e, "readiness surface could not bind; continuing without it");
        }
    })
}

async fn respond(mut stream: TcpStream, ready: watch::Receiver<bool>) -> std::io::Result<()> {
    // Drain the request head (bounded) so the client's write completes before we respond;
    // the path/method are not inspected — any request returns the current readiness.
    let mut buf = [0u8; 1024];
    let _ = tokio::time::timeout(PROBE_READ_TIMEOUT, stream.read(&mut buf)).await;
    let body = if *ready.borrow() { READY } else { DRAINING };
    stream.write_all(body).await?;
    stream.flush().await
}
