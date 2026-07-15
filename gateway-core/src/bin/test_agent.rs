//! `test-agent` — a stand-in SessionLayer Agent for the Docker agent-path E2E.
//!
//! It runs **inside the node container as a non-root user**, dials OUT to the
//! Gateway's WSS transport with its mTLS identity, and splices each dial-back to that
//! container's own `127.0.0.1:22`. It is test scaffolding: the production Agent lives
//! in its own repository. Built only under the `test-agent` feature.

use clap::Parser;
use gateway_core::agent::testclient::AgentClient;

#[derive(Parser, Debug)]
#[command(
    name = "test-agent",
    about = "Test-only SessionLayer Agent (wire contract client)"
)]
struct Cli {
    /// `wss://host:port` of the Gateway's agent transport.
    #[arg(long)]
    endpoint: String,
    /// The Gateway's enrolled name — the server name its certificate must present.
    #[arg(long)]
    server_name: String,
    /// PEM file: the internal mTLS CA the Agent already holds.
    #[arg(long)]
    ca: std::path::PathBuf,
    /// PEM file: the Agent's identity certificate (its S12 credential).
    #[arg(long)]
    cert: std::path::PathBuf,
    /// PEM file: the identity's private key (PKCS#8).
    #[arg(long)]
    key: std::path::PathBuf,
    /// The node this Agent is bound to (its certificate's dNSName SAN).
    #[arg(long)]
    node_name: String,
    /// The node's local sshd. Validated to be a loopback address.
    #[arg(long, default_value = "127.0.0.1:22")]
    splice_addr: String,
    #[arg(long, default_value_t = 65536)]
    max_frame_bytes: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // FR-CONN-6 / §9.3: the Agent runs non-root, so it cannot read the node's host key
    // — which is what raises host-key spoofing to a node-root compromise. Fail closed.
    if is_root() {
        anyhow::bail!("refusing to run as root (FR-CONN-6): the agent must not be able to read the node host key");
    }
    // The splice target is local configuration and must be loopback: an agent that could
    // be pointed anywhere else would be a network pivot.
    let addr: std::net::SocketAddr = cli.splice_addr.parse()?;
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "splice target must be a loopback address, got {addr}"
    );

    let client = AgentClient {
        endpoint: cli.endpoint,
        server_name: cli.server_name,
        ca_der: pem_certs(&cli.ca)?,
        cert_der: pem_certs(&cli.cert)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no certificate in {}", cli.cert.display()))?,
        key_pkcs8_der: pem_key(&cli.key)?,
        node_name: cli.node_name,
        splice_addr: cli.splice_addr,
        max_frame_bytes: cli.max_frame_bytes,
    };

    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = tx.send(true);
    });
    client.run_forever(rx).await;
    Ok(())
}

/// The real UID, without `libc` (this workspace forbids `unsafe`): on Linux `/proc/self`
/// is owned by the process's own UID.
fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

fn pem_certs(path: &std::path::Path) -> anyhow::Result<Vec<Vec<u8>>> {
    let bytes = std::fs::read(path)?;
    Ok(pem::parse_many(&bytes)?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| p.into_contents())
        .collect())
}

fn pem_key(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    pem::parse_many(&bytes)?
        .into_iter()
        .find(|p| p.tag().ends_with("PRIVATE KEY"))
        .map(|p| p.into_contents())
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", path.display()))
}
