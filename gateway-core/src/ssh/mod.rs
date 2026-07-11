//! The outer SSH leg (Session Seven): the Gateway's SSH server.
//!
//! A TCP listener that, per connection, (1) determines the **real** client source
//! IP via PROXY protocol v2 (trusted only from LB CIDRs, fail-closed both ways —
//! [`proxy`]), (2) enforces the **global source-IP gate before any SSH banner**
//! (§7.1 row 1), and (3) runs the SSH transport + auth handshake via russh,
//! advertising `publickey` + `keyboard-interactive` and delegating every
//! auth/authorize decision to the CP ([`handler`]). On a successful
//! authenticate + authorize it hands the decision + session token to the
//! [`NodeConnector`](connector::NodeConnector) seam and closes cleanly (Session
//! Eight attaches the inner leg).
//!
//! Tier-0: the accept path bounds the PROXY read (handshake timeout), caps
//! concurrent connections, and never logs SSH secrets/keys/OTP/tokens/plaintext.

pub mod connector;
pub mod handler;
pub mod outcome;
pub mod proxy;
pub mod target;

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use zeroize::Zeroize;

use russh::keys::PrivateKey;
use russh::server::Config as RusshConfig;
use russh::{MethodKind, MethodSet, SshId};

use std::sync::atomic::Ordering;

use crate::config::SshServerConfig;
use crate::netmatch::{self, Cidr};
use crate::ssh::handler::{ConnState, HandlerDeps, SshHandler};
use crate::ssh::proxy::resolve_source_ip;

pub use crate::cpauth::{CpAuthClient, CpChannelFactory, CredentialSnapshot};
pub use crate::ssh::handler::HandlerDeps as OuterLegDeps;

/// A failure standing up the outer SSH leg (fail-closed at startup).
#[derive(Debug, thiserror::Error)]
pub enum SshServerError {
    /// The listen address / host-key file could not be used.
    #[error("outer-leg SSH server I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A configured LB or gate CIDR could not be parsed.
    #[error("invalid source-IP CIDR configuration: {0}")]
    Cidr(#[from] netmatch::CidrError),

    /// The host key could not be generated / loaded / persisted.
    #[error("outer-leg host key error: {0}")]
    HostKey(String),

    /// The SSH server configuration is internally inconsistent (fail closed).
    #[error("invalid outer-leg SSH configuration: {0}")]
    Config(String),
}

/// Immutable per-server state shared by every accepted connection.
struct ServerInner {
    russh_config: Arc<RusshConfig>,
    deps: HandlerDeps,
    /// Trusted LB CIDRs; empty disables PROXY protocol (peer IP is the source).
    lb_cidrs: Vec<Cidr>,
    /// Global source-IP gate; empty disables the gate (allow all).
    gate_cidrs: Vec<Cidr>,
    /// Tier-0 bound on the pre-banner PROXY read.
    handshake_timeout: Duration,
    /// Absolute pre-auth deadline: a connection that hasn't authenticated within
    /// this is dropped (not reset by packet activity, unlike inactivity_timeout).
    login_grace: Duration,
    /// Tier-0 bound on concurrently-handshaking connections.
    connection_slots: Arc<Semaphore>,
}

/// A bound, ready-to-run outer SSH leg. Obtain via [`bind`], then [`BoundServer::run`].
pub struct BoundServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    inner: Arc<ServerInner>,
}

impl BoundServer {
    /// The address the server is listening on (useful when bound to port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Run the accept loop until `shutdown` resolves. Each accepted connection is
    /// handled on its own task, bounded by the connection-slots semaphore.
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()>) {
        let inner = self.inner;
        tokio::pin!(shutdown);
        tracing::info!(addr = %self.local_addr, "outer SSH leg listening");
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    tracing::info!("outer SSH leg shutting down");
                    return;
                }
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            // Bound concurrent handshakes (Tier-0). Over the cap →
                            // drop at accept rather than exhaust resources.
                            let Ok(permit) = inner.connection_slots.clone().try_acquire_owned() else {
                                tracing::warn!(peer = %peer, "at connection capacity; dropping");
                                continue;
                            };
                            let inner = inner.clone();
                            tokio::spawn(async move {
                                let _permit = permit; // held for the connection lifetime
                                handle_connection(inner, stream, peer.ip()).await;
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "accept failed");
                        }
                    }
                }
            }
        }
    }
}

/// Handle one accepted connection: resolve the real source IP (PROXY), apply the
/// global gate **before any SSH banner**, then run the SSH handshake.
async fn handle_connection(inner: Arc<ServerInner>, mut stream: TcpStream, peer: IpAddr) {
    // Canonicalize the peer first: on a dual-stack listener a v4 client arrives as
    // `::ffff:a.b.c.d`; `to_canonical` maps it back to v4 so LB-trust and the gate
    // (and the CP `source_ip`) see the real family (F-dualstack).
    let peer = peer.to_canonical();

    // (1) Real source IP via PROXY v2 (fail-closed both ways), bounded so a
    // connect-then-stall peer cannot hold the slot.
    let real_ip = match tokio::time::timeout(
        inner.handshake_timeout,
        resolve_source_ip(&mut stream, peer, &inner.lb_cidrs),
    )
    .await
    {
        Ok(Ok(ip)) => ip.to_canonical(),
        Ok(Err(e)) => {
            tracing::info!(peer = %peer, error = %e, "PROXY/source rejected before banner");
            return;
        }
        Err(_) => {
            tracing::info!(peer = %peer, "PROXY header read timed out; dropping");
            return;
        }
    };

    // (2) Global CIDR gate (FR-AUTH-13): drop before any SSH bytes (§7.1 row 1).
    if !inner.gate_cidrs.is_empty() && !netmatch::any_contains(&inner.gate_cidrs, real_ip) {
        tracing::info!(source_ip = %real_ip, outcome = "blocked_source", "source IP outside global gate; dropping before banner");
        return;
    }

    // (3) SSH transport + auth handshake.
    let conn = Arc::new(ConnState::default());
    let handler = SshHandler::new(inner.deps.clone(), real_ip, conn.clone());
    match russh::server::run_stream(inner.russh_config.clone(), stream, handler).await {
        Ok(running) => {
            // Absolute pre-auth deadline: drop the connection if authentication
            // hasn't completed within login_grace (russh's inactivity_timeout
            // resets on every packet, so a slow-loris could camp a slot forever).
            let handle = running.handle();
            let grace = inner.login_grace;
            let wd_conn = conn.clone();
            let watchdog = tokio::spawn(async move {
                tokio::time::sleep(grace).await;
                if !wd_conn.authenticated.load(Ordering::SeqCst) {
                    let _ = handle
                        .disconnect(
                            russh::Disconnect::ByApplication,
                            "authentication timed out".to_string(),
                            String::new(),
                        )
                        .await;
                }
            });

            if let Err(e) = running.await {
                tracing::debug!(error = ?e, source_ip = %real_ip, "SSH session ended");
            }
            watchdog.abort();

            // One consolidated record if the connection ended unauthenticated.
            if !conn.authenticated.load(Ordering::SeqCst) {
                let methods = conn.methods_tried.lock().unwrap().clone();
                let outcome = if conn.cp_unavailable.load(Ordering::SeqCst) {
                    "cp_unavailable"
                } else {
                    "auth_failed"
                };
                tracing::info!(source_ip = %real_ip, outcome, methods = ?methods, "outer-leg connection ended without authentication");
            }
        }
        Err(e) => {
            tracing::debug!(error = ?e, source_ip = %real_ip, "SSH handshake failed");
        }
    }
}

/// Bind the outer SSH leg per `config`, wiring in the CP-delegating `deps`.
/// Fail-closed: bad CIDRs, an unusable host key, or a bind failure abort startup.
pub async fn bind(
    config: Arc<SshServerConfig>,
    deps: HandlerDeps,
) -> Result<BoundServer, SshServerError> {
    validate_config(&config)?;

    let lb_cidrs = netmatch::parse_cidrs(&config.proxy.lb_cidrs)?;
    let gate_cidrs = netmatch::parse_cidrs(&config.source_ip_allowlist)?;

    // Operator warnings for permissive-but-valid configurations.
    if config.source_ip_allowlist.is_empty() {
        tracing::warn!("outer SSH leg enabled with an EMPTY source-IP gate (allow-all); set ssh.source_ip_allowlist to restrict access (FR-AUTH-13)");
    }
    if config.proxy.lb_cidrs.is_empty() {
        tracing::warn!("PROXY protocol is OFF (ssh.proxy.lb_cidrs empty); behind an L4 LB the LB address would become the source IP for every client — set lb_cidrs (FR-AUTH-14)");
    }

    let host_key = load_or_generate_host_key(&config.host_key_path)?;
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::PublicKey);
    methods.push(MethodKind::KeyboardInteractive);

    let russh_config = RusshConfig {
        server_id: SshId::Standard("SSH-2.0-SessionLayer_Gateway".into()),
        methods,
        keys: vec![host_key],
        // Generous grace covering a browser OIDC device flow (FR-AUTH-4). russh's
        // inactivity_timeout is the connection-idle bound; the device-flow
        // heartbeat keeps traffic flowing below it.
        inactivity_timeout: Some(Duration::from_secs(config.login_grace_secs)),
        // Constant-time auth rejection (russh enforces this floor).
        auth_rejection_time: Duration::from_secs(1),
        ..Default::default()
    };

    let listener = TcpListener::bind(&config.listen_addr).await?;
    let local_addr = listener.local_addr()?;

    let inner = Arc::new(ServerInner {
        russh_config: Arc::new(russh_config),
        deps,
        lb_cidrs,
        gate_cidrs,
        handshake_timeout: Duration::from_secs(config.handshake_timeout_secs),
        login_grace: Duration::from_secs(config.login_grace_secs),
        connection_slots: Arc::new(Semaphore::new(config.max_connections)),
    });

    Ok(BoundServer {
        listener,
        local_addr,
        inner,
    })
}

/// Validate the SSH configuration, failing closed on inconsistent timing that
/// would busy-loop or let the device flow outlast the pre-auth deadline.
fn validate_config(config: &SshServerConfig) -> Result<(), SshServerError> {
    let df = &config.device_flow;
    if df.heartbeat_interval_secs == 0 {
        return Err(SshServerError::Config(
            "device_flow.heartbeat_interval_secs must be > 0 (0 would busy-poll)".to_string(),
        ));
    }
    if df.poll_timeout_secs >= config.login_grace_secs {
        return Err(SshServerError::Config(format!(
            "device_flow.poll_timeout_secs ({}) must be < login_grace_secs ({})",
            df.poll_timeout_secs, config.login_grace_secs
        )));
    }
    if df.heartbeat_interval_secs >= config.login_grace_secs {
        return Err(SshServerError::Config(format!(
            "device_flow.heartbeat_interval_secs ({}) must be < login_grace_secs ({})",
            df.heartbeat_interval_secs, config.login_grace_secs
        )));
    }
    Ok(())
}

/// Load the persisted ed25519 host key, or generate one (persisting it when a
/// path is configured; ephemeral when not — fine for tests).
fn load_or_generate_host_key(path: &Path) -> Result<PrivateKey, SshServerError> {
    if path.as_os_str().is_empty() {
        return generate_host_key();
    }
    if path.exists() {
        let pem = std::fs::read_to_string(path)?;
        return PrivateKey::from_openssh(&pem)
            .map_err(|e| SshServerError::HostKey(format!("parsing host key {path:?}: {e}")));
    }
    let key = generate_host_key()?;
    let pem = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(|e| SshServerError::HostKey(format!("encoding host key: {e}")))?;
    write_owner_only(path, pem.as_bytes())?;
    Ok(key)
}

/// Generate a fresh ed25519 host key from a scrubbed random seed. (russh's
/// `ssh-key` `rand_core` feature is off, so we seed the keypair directly.)
fn generate_host_key() -> Result<PrivateKey, SshServerError> {
    use rand_core::RngCore;
    use russh::keys::ssh_key::private::Ed25519Keypair;

    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.zeroize();
    Ok(PrivateKey::from(keypair))
}

/// Write `bytes` to `path` with `0600` on unix (the host key is private material).
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), SshServerError> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_host_keys_are_ed25519_and_distinct() {
        let a = generate_host_key().unwrap();
        let b = generate_host_key().unwrap();
        assert_eq!(a.algorithm(), russh::keys::Algorithm::Ed25519);
        assert_ne!(
            a.public_key().to_bytes().unwrap(),
            b.public_key().to_bytes().unwrap()
        );
    }

    #[test]
    fn config_validation_fails_closed_on_bad_timing() {
        use crate::config::{DeviceFlowConfig, SshServerConfig};
        let ok = SshServerConfig::default();
        assert!(validate_config(&ok).is_ok());

        let mut zero_hb = SshServerConfig::default();
        zero_hb.device_flow.heartbeat_interval_secs = 0;
        assert!(matches!(
            validate_config(&zero_hb),
            Err(SshServerError::Config(_))
        ));

        let bad = SshServerConfig {
            login_grace_secs: 30,
            device_flow: DeviceFlowConfig {
                heartbeat_interval_secs: 10,
                poll_timeout_secs: 60, // >= login_grace
            },
            ..Default::default()
        };
        assert!(matches!(
            validate_config(&bad),
            Err(SshServerError::Config(_))
        ));
    }

    #[test]
    fn host_key_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host_ed25519");
        let first = load_or_generate_host_key(&path).unwrap();
        assert!(path.exists());
        let reloaded = load_or_generate_host_key(&path).unwrap();
        assert_eq!(
            first.public_key().to_bytes().unwrap(),
            reloaded.public_key().to_bytes().unwrap(),
            "a persisted host key must reload identically"
        );
    }

    #[cfg(unix)]
    #[test]
    fn persisted_host_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host_ed25519");
        let _ = load_or_generate_host_key(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
