pub mod bridge;
pub mod connector;
pub mod forward;
pub mod handler;
pub mod hostverify;
pub mod innerleg;
pub mod lockfeed;
pub mod locks;
pub mod outcome;
pub mod proxy;
pub mod proxyjump;
pub mod recorder;
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

#[derive(Debug, thiserror::Error)]
pub enum SshServerError {
    #[error("outer-leg SSH server I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid source-IP CIDR configuration: {0}")]
    Cidr(#[from] netmatch::CidrError),
    #[error("outer-leg host key error: {0}")]
    HostKey(String),
    #[error("invalid outer-leg SSH configuration: {0}")]
    Config(String),
}

struct ServerInner {
    russh_config: Arc<RusshConfig>,
    deps: HandlerDeps,
    lb_cidrs: Vec<Cidr>,
    gate_cidrs: Vec<Cidr>,
    handshake_timeout: Duration,
    login_grace: Duration,
    connection_slots: Arc<Semaphore>,
}

pub struct BoundServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    inner: Arc<ServerInner>,
}

impl BoundServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

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
                            let Ok(permit) = inner.connection_slots.clone().try_acquire_owned() else {
                                tracing::warn!(peer = %peer, "at connection capacity; dropping");
                                continue;
                            };
                            let inner = inner.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
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

async fn handle_connection(inner: Arc<ServerInner>, mut stream: TcpStream, peer: IpAddr) {
    let peer = peer.to_canonical();

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

    if !inner.gate_cidrs.is_empty() && !netmatch::any_contains(&inner.gate_cidrs, real_ip) {
        tracing::info!(source_ip = %real_ip, outcome = "blocked_source", "source IP outside global gate; dropping before banner");
        return;
    }

    use tracing::Instrument;
    let conn = Arc::new(ConnState::default());
    let handler = SshHandler::new(inner.deps.clone(), real_ip, conn.clone());
    let session_span = handler.trace_span();
    run_ssh_connection(inner, stream, handler, conn, real_ip)
        .instrument(session_span)
        .await;
}

async fn run_ssh_connection(
    inner: Arc<ServerInner>,
    stream: TcpStream,
    handler: SshHandler,
    conn: Arc<ConnState>,
    real_ip: IpAddr,
) {
    match russh::server::run_stream(inner.russh_config.clone(), stream, handler).await {
        Ok(running) => {
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

pub async fn bind(
    config: Arc<SshServerConfig>,
    deps: HandlerDeps,
) -> Result<BoundServer, SshServerError> {
    validate_config(&config)?;

    let lb_cidrs = netmatch::parse_cidrs(&config.proxy.lb_cidrs)?;
    let gate_cidrs = netmatch::parse_cidrs(&config.source_ip_allowlist)?;

    if config.source_ip_allowlist.is_empty() {
        tracing::warn!("outer SSH leg enabled with an EMPTY source-IP gate (allow-all); set ssh.source_ip_allowlist to restrict access");
    }
    if config.proxy.lb_cidrs.is_empty() {
        tracing::warn!("PROXY protocol is OFF (ssh.proxy.lb_cidrs empty); behind an L4 LB the LB address would become the source IP for every client - set lb_cidrs");
    }

    let host_key = load_or_generate_host_key(&config.host_key_path)?;
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::PublicKey);
    methods.push(MethodKind::KeyboardInteractive);

    let russh_config = RusshConfig {
        server_id: SshId::Standard("SSH-2.0-SessionLayer_Gateway".into()),
        methods,
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_secs(config.inner.max_session_idle_secs)),
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

fn validate_config(config: &SshServerConfig) -> Result<(), SshServerError> {
    if config.break_glass.mid_session_expiry == crate::config::MidSessionExpiryMode::RunToTtl {
        return Err(SshServerError::Config(
            "break_glass.mid_session_expiry must be grace_then_kill or hard_kill (never run_to_ttl): a break-glass session must be time-boxed".to_string(),
        ));
    }
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
    if config.inner.max_session_idle_secs < config.login_grace_secs {
        return Err(SshServerError::Config(format!(
            "inner.max_session_idle_secs ({}) must be >= login_grace_secs ({})",
            config.inner.max_session_idle_secs, config.login_grace_secs
        )));
    }
    let inner = &config.inner;
    if inner.connect_timeout_secs == 0 || inner.handshake_timeout_secs == 0 {
        return Err(SshServerError::Config(
            "inner.connect_timeout_secs and inner.handshake_timeout_secs must be > 0".to_string(),
        ));
    }
    if inner.max_packet_bytes == 0 || inner.window_bytes < inner.max_packet_bytes {
        return Err(SshServerError::Config(format!(
            "inner.window_bytes ({}) must be >= inner.max_packet_bytes ({} > 0)",
            inner.window_bytes, inner.max_packet_bytes
        )));
    }
    if inner.max_channels_per_connection == 0 {
        return Err(SshServerError::Config(
            "inner.max_channels_per_connection must be >= 1".to_string(),
        ));
    }
    validate_agent_config(&config.agent, inner)?;
    Ok(())
}

fn validate_agent_config(
    agent: &crate::config::AgentTransportConfig,
    inner: &crate::config::InnerLegServerConfig,
) -> Result<(), SshServerError> {
    use crate::agent::{HEARTBEAT_INTERVAL_SECS_RANGE, MAX_FRAME_BYTES_RANGE};

    if agent.listen_addr.is_empty() {
        return Ok(());
    }

    if !MAX_FRAME_BYTES_RANGE.contains(&agent.max_frame_bytes) {
        return Err(SshServerError::Config(format!(
            "ssh.agent.max_frame_bytes ({}) is outside the wire-contract §3 range {}-{}; an Agent would refuse this HELLO_ACK",
            agent.max_frame_bytes,
            MAX_FRAME_BYTES_RANGE.start(),
            MAX_FRAME_BYTES_RANGE.end()
        )));
    }
    if agent.max_frame_bytes <= inner.max_packet_bytes as usize {
        return Err(SshServerError::Config(format!(
            "ssh.agent.max_frame_bytes ({}) must be > inner.max_packet_bytes ({})",
            agent.max_frame_bytes, inner.max_packet_bytes
        )));
    }
    if !HEARTBEAT_INTERVAL_SECS_RANGE.contains(&agent.heartbeat_interval_secs) {
        return Err(SshServerError::Config(format!(
            "ssh.agent.heartbeat_interval_secs ({}) is outside the wire-contract §3 range {}-{}; an Agent would refuse this HELLO_ACK",
            agent.heartbeat_interval_secs,
            HEARTBEAT_INTERVAL_SECS_RANGE.start(),
            HEARTBEAT_INTERVAL_SECS_RANGE.end()
        )));
    }
    if agent.dial_back_timeout_secs as i64 >= agent.dial_back_token_ttl_secs {
        return Err(SshServerError::Config(format!(
            "ssh.agent.dial_back_timeout_secs ({}) must be < dial_back_token_ttl_secs ({})",
            agent.dial_back_timeout_secs, agent.dial_back_token_ttl_secs
        )));
    }
    if agent.dial_back_timeout_secs == 0 || agent.handshake_timeout_secs == 0 {
        return Err(SshServerError::Config(
            "ssh.agent.dial_back_timeout_secs and handshake_timeout_secs must be > 0".to_string(),
        ));
    }
    if agent.max_agents == 0 {
        return Err(SshServerError::Config(
            "ssh.agent.max_agents must be >= 1".to_string(),
        ));
    }
    if agent.max_connections < agent.max_agents {
        return Err(SshServerError::Config(format!(
            "ssh.agent.max_connections ({}) must be >= max_agents ({})",
            agent.max_connections, agent.max_agents
        )));
    }
    Ok(())
}

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

fn generate_host_key() -> Result<PrivateKey, SshServerError> {
    use rand_core::RngCore;
    use russh::keys::ssh_key::private::Ed25519Keypair;

    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.zeroize();
    Ok(PrivateKey::from(keypair))
}

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
                poll_timeout_secs: 60,
            },
            ..Default::default()
        };
        assert!(matches!(
            validate_config(&bad),
            Err(SshServerError::Config(_))
        ));
    }

    #[test]
    fn break_glass_run_to_ttl_is_rejected() {
        use crate::config::{BreakGlassConfig, MidSessionExpiryMode};
        let run_to_ttl = SshServerConfig {
            break_glass: BreakGlassConfig {
                enabled: true,
                mid_session_expiry: MidSessionExpiryMode::RunToTtl,
            },
            ..Default::default()
        };
        assert!(matches!(
            validate_config(&run_to_ttl),
            Err(SshServerError::Config(_))
        ));
        for mode in [
            MidSessionExpiryMode::GraceThenKill,
            MidSessionExpiryMode::HardKill,
        ] {
            let ok = SshServerConfig {
                break_glass: BreakGlassConfig {
                    enabled: true,
                    mid_session_expiry: mode,
                },
                ..Default::default()
            };
            assert!(validate_config(&ok).is_ok(), "{mode:?} must be accepted");
        }
    }

    #[test]
    fn agent_transport_bounds_fail_closed() {
        use crate::config::AgentTransportConfig;

        assert!(validate_config(&SshServerConfig::default()).is_ok());

        let enabled = |agent: AgentTransportConfig| SshServerConfig {
            agent,
            ..Default::default()
        };
        let on = AgentTransportConfig {
            listen_addr: "0.0.0.0:9444".into(),
            ..Default::default()
        };
        assert!(validate_config(&enabled(on.clone())).is_ok());

        assert!(matches!(
            validate_config(&enabled(AgentTransportConfig {
                max_frame_bytes: 32 * 1024,
                ..on.clone()
            })),
            Err(SshServerError::Config(_))
        ));

        // Bounds on the two values HELLO_ACK proposes. The Agent enforces the SAME
        // range, so a Gateway outside it would boot healthy and then be refused by
        // every Agent in the fleet - reject it at startup, loudly.
        for outside in [
            AgentTransportConfig {
                max_frame_bytes: 2 * 1024 * 1024,
                ..on.clone()
            },
            AgentTransportConfig {
                max_frame_bytes: 2048,
                ..on.clone()
            },
            AgentTransportConfig {
                heartbeat_interval_secs: 600,
                ..on.clone()
            },
            AgentTransportConfig {
                heartbeat_interval_secs: 0,
                ..on.clone()
            },
        ] {
            assert!(
                matches!(
                    validate_config(&enabled(outside.clone())),
                    Err(SshServerError::Config(_))
                ),
                "outside the contract §3 range, must be refused at startup: {outside:?}"
            );
        }

        for edge in [
            AgentTransportConfig {
                max_frame_bytes: 1024 * 1024,
                ..on.clone()
            },
            AgentTransportConfig {
                heartbeat_interval_secs: 1,
                ..on.clone()
            },
            AgentTransportConfig {
                heartbeat_interval_secs: 300,
                ..on.clone()
            },
        ] {
            assert!(
                validate_config(&enabled(edge.clone())).is_ok(),
                "the contract range is inclusive: {edge:?}"
            );
        }
        assert!(matches!(
            validate_config(&enabled(AgentTransportConfig {
                dial_back_timeout_secs: 30,
                dial_back_token_ttl_secs: 30,
                ..on.clone()
            })),
            Err(SshServerError::Config(_))
        ));
        for zeroed in [
            AgentTransportConfig {
                dial_back_timeout_secs: 0,
                ..on.clone()
            },
            AgentTransportConfig {
                handshake_timeout_secs: 0,
                ..on.clone()
            },
            AgentTransportConfig {
                heartbeat_interval_secs: 0,
                ..on.clone()
            },
            AgentTransportConfig {
                max_agents: 0,
                ..on.clone()
            },
            AgentTransportConfig {
                max_connections: 512,
                max_agents: 1024,
                ..on.clone()
            },
        ] {
            assert!(
                matches!(
                    validate_config(&enabled(zeroed.clone())),
                    Err(SshServerError::Config(_))
                ),
                "must reject {zeroed:?}"
            );
        }
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
