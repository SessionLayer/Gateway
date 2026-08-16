use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const READY: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nready\n";
const DRAINING: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\ndraining\n";

const PROBE_READ_TIMEOUT: Duration = Duration::from_secs(2);

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
    let mut buf = [0u8; 1024];
    let _ = tokio::time::timeout(PROBE_READ_TIMEOUT, stream.read(&mut buf)).await;
    let body = if *ready.borrow() { READY } else { DRAINING };
    stream.write_all(body).await?;
    stream.flush().await
}
