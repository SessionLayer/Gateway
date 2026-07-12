//! SessionLayer Gateway daemon.
//!
//! Tier-0 caution: this binary is the plaintext SSH MITM (Design §15, NFR-5) —
//! the largest blast radius in the platform. It establishes the renewable CP
//! mTLS identity (Session Four) and, when configured, starts the **outer SSH
//! leg** (Session Seven): the SSH server that gates on source IP and negotiates
//! auth, delegating every decision to the CP. The **inner** leg (node
//! connection, host verification, byte bridge) is Session Eight; the outer leg
//! stops at the `NodeConnector` seam. The SSH server starts only when
//! `ssh.listen_addr` is set **and** the Gateway holds a CP identity (fail closed).

use clap::{Parser, Subcommand, ValueEnum};
use gateway_core::{
    asyncio::{self, IoBackend},
    config::GatewayConfig,
    cpauth, handshake, health, identity, mtls, ssh, tls,
};
use std::sync::Arc;
use std::time::Duration;

/// `--version` output: SemVer plus the supported CP <-> Gateway protocol range.
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (SessionLayer Gateway; CP<->GW protocol 1.0-1.1)"
);

#[derive(Parser, Debug)]
#[command(
    name = "gateway",
    version = VERSION,
    about = "SessionLayer Gateway daemon (Session One scaffold)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the health/version report as JSON and exit.
    Health,
    /// Resolve and print the async-I/O backend for a requested reactor, then
    /// exit. Demonstrates the seam and its deny-safe fallback: requesting
    /// `uring` on a build/platform without io_uring degrades to `epoll`.
    IoBackend {
        /// Reactor to request (default: the config default, `epoll`).
        #[arg(long, value_enum, default_value_t = BackendArg::Epoll)]
        request: BackendArg,
    },
}

/// CLI mirror of [`IoBackend`] so the binary owns the `clap` dependency.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum BackendArg {
    Epoll,
    Uring,
}

impl From<BackendArg> for IoBackend {
    fn from(arg: BackendArg) -> Self {
        match arg {
            BackendArg::Epoll => IoBackend::Epoll,
            BackendArg::Uring => IoBackend::Uring,
        }
    }
}

fn main() -> anyhow::Result<()> {
    init_tracing();

    match Cli::parse().command {
        Some(Command::Health) => {
            println!("{}", serde_json::to_string_pretty(&health::report())?);
            Ok(())
        }
        Some(Command::IoBackend { request }) => {
            let requested = IoBackend::from(request);
            let resolved = asyncio::select_io(requested).backend();
            println!("requested {requested:?} -> resolved {resolved:?}");
            Ok(())
        }
        None => run(),
    }
}

/// Run the daemon: a multi-threaded tokio runtime that establishes the Gateway's
/// mTLS identity (when a bootstrap credential is configured), starts the outer
/// SSH leg (when configured), then idles until a shutdown signal.
///
/// **Fail-closed:** with a bootstrap credential configured, an enrollment /
/// load failure aborts startup (the process exits non-zero) rather than running
/// without an authenticated CP identity; the SSH server is not started without
/// a CP identity to delegate to.
fn run() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let cfg = GatewayConfig::default();
        let io = asyncio::select_io(cfg.io_backend);
        let report = health::report();

        tracing::info!(
            component = %report.component,
            semver = %report.semver,
            protocol_range = %report.protocol_range,
            io_backend = ?io.backend(),
            cp_mtls_endpoint = %cfg.cp_mtls_endpoint,
            "SessionLayer Gateway starting"
        );

        // Establish (or load) the renewable mTLS identity if bootstrap is
        // configured; the renew-ahead loop then runs for the process lifetime.
        let renew = bootstrap_identity(&cfg).await?;
        if renew.is_none() {
            tracing::info!(
                "no bootstrap credential configured; running without a CP mTLS identity (scaffold mode)"
            );
        }

        // Shutdown is broadcast to the accept loop AND the drain step (SIGTERM +
        // Ctrl-C). A `watch` retains the value so neither observer loses the signal.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            wait_for_shutdown().await;
            let _ = shutdown_tx.send(true);
        });

        // Outer SSH leg (Session Seven): started only when configured AND the
        // Gateway holds a CP mTLS identity to delegate auth to (fail closed).
        let finalize_tracker =
            start_outer_leg(&cfg, renew.as_ref(), shutdown_rx.clone()).await?;

        tracing::info!("awaiting shutdown signal (SIGTERM / Ctrl-C)");
        let mut sd = shutdown_rx;
        let _ = sd.wait_for(|v| *v).await;
        tracing::info!("shutdown signal received; Gateway stopping");

        // Graceful shutdown: the accept loop has stopped; give live sessions'
        // recordings a bounded grace to finalize + upload before we exit, so they
        // are not lost (#3). In-flight connection preservation is S14 (F-drain).
        if let Some(tracker) = finalize_tracker {
            let grace = Duration::from_secs(cfg.ssh.recorder.upload_timeout_secs.saturating_add(10));
            tracing::info!(grace_secs = grace.as_secs(), "draining in-flight recording finalizes");
            tracker.drain(grace).await;
        }
        Ok::<(), anyhow::Error>(())
    })
}

/// Resolve when the process should shut down: SIGTERM (container/systemd stop) or
/// Ctrl-C (SIGINT). On non-unix only Ctrl-C is available.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Establish the Gateway's mTLS identity per config and spawn the renew-ahead
/// loop. Returns `None` when no bootstrap credential is configured (scaffold
/// mode). Fail-closed: any error is propagated so startup aborts.
async fn bootstrap_identity(cfg: &GatewayConfig) -> anyhow::Result<Option<identity::RenewHandle>> {
    let Some(bootstrap) = cfg.bootstrap.clone() else {
        return Ok(None);
    };

    // A crypto provider must be installed before any rustls config is built.
    tls::install_ring_provider();

    let server_name = if bootstrap.server_name.is_empty() {
        host_from_endpoint(&cfg.cp_mtls_endpoint).ok_or_else(|| {
            anyhow::anyhow!("cannot derive server name from {}", cfg.cp_mtls_endpoint)
        })?
    } else {
        bootstrap.server_name.clone()
    };

    let params = mtls::ChannelParams {
        endpoint: cfg.cp_mtls_endpoint.clone(),
        server_name,
        connect_timeout: Duration::from_secs(cfg.identity.connect_timeout_secs),
        rpc_timeout: Duration::from_secs(cfg.identity.rpc_timeout_secs),
    };

    let store = identity::IdentityStore::open(&cfg.data_dir)?;
    let existing = store.load()?;

    // Trust anchor for verifying the CP's server certificate: the issued CA chain
    // once enrolled, else the operator-pinned bootstrap CA.
    let anchors: Vec<Vec<u8>> = match &existing {
        Some(c) => c.ca_chain_der.clone(),
        None => {
            let ca_pem = std::fs::read(&bootstrap.ca_cert_path).map_err(|e| {
                anyhow::anyhow!(
                    "reading bootstrap CA {}: {e}",
                    bootstrap.ca_cert_path.display()
                )
            })?;
            mtls::pem_certs_to_der(&ca_pem)?
        }
    };

    // Negotiate a common protocol version at connect over the secured channel
    // (FR-HA-9 / VERSIONING §7). Fail closed on a mismatch/disjoint range before
    // enrolling or renewing anything.
    let boot_channel = mtls::connect_bootstrap(&params, &anchors).await?;
    let negotiated = handshake::negotiate_over_channel(boot_channel)
        .await
        .map_err(|e| anyhow::anyhow!("CP<->GW version negotiation failed: {e}"))?;
    tracing::info!(
        protocol = %negotiated.version_string(),
        server = %negotiated.server_name,
        "negotiated CP<->GW protocol version at connect"
    );

    // Load an existing credential, or enroll for the first time. Renew on startup
    // if we loaded one that is already close to expiry (§8.1).
    //
    // The enroll/renew `IdentityError` is wrapped at this boundary with
    // `anyhow!("… {e}")`, which formats only the (code-only) `Display` and carries
    // NO `tonic::Status` source. Otherwise `#[from] tonic::Status` keeps the
    // Status as the error `source()`, and `fn main`'s `Termination` Debug-print of
    // a returned `Err` would walk the chain and emit the CP-controlled Status
    // message (ANSI / newline injection) to startup stderr.
    let credential = match existing {
        Some(existing) => {
            let remaining = identity::remaining_fraction(
                std::time::SystemTime::now(),
                existing.not_before,
                existing.not_after,
            );
            if remaining <= cfg.identity.startup_renew_below_fraction {
                tracing::info!(
                    remaining,
                    "loaded identity is near expiry; renewing on startup"
                );
                identity::renew(&store, &params, &existing).await
            } else {
                tracing::info!(
                    gateway_id = %existing.gateway_id,
                    generation = existing.generation,
                    "loaded persisted mTLS identity"
                );
                Ok(existing)
            }
        }
        None => {
            tracing::info!(gateway_name = %bootstrap.gateway_name, "enrolling with the Control Plane");
            identity::enroll(
                &store,
                &params,
                &anchors,
                bootstrap.enrollment_token.as_str(),
                &bootstrap.gateway_name,
            )
            .await
        }
    }
    .map_err(|e| anyhow::anyhow!("gateway enrollment/renewal failed: {e}"))?;

    tracing::info!(
        gateway_id = %credential.gateway_id,
        generation = credential.generation,
        "mTLS identity active"
    );

    let renew_ahead = identity::RenewAhead::new(
        store,
        identity::RenewAheadConfig {
            renew_ahead_fraction: cfg.identity.renew_ahead_fraction,
            renew_jitter_fraction: cfg.identity.renew_jitter_fraction,
            retry_backoff: Duration::from_secs(30),
            channel: params,
        },
        credential,
    );
    let handle = renew_ahead.handle();

    // The loop runs until Ctrl-C; give it its own shutdown future.
    tokio::spawn(async move {
        let shutdown = Box::pin(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        renew_ahead.run(shutdown).await;
    });

    Ok(Some(handle))
}

/// Start the outer SSH leg if `ssh.listen_addr` is configured. Requires a CP
/// mTLS identity to delegate auth to — without one the server is **not** started
/// (fail closed: never an SSH front door that can't reach the decision authority).
/// The CP auth client tracks the renewing credential so a rotated identity is
/// picked up without a restart.
async fn start_outer_leg(
    cfg: &GatewayConfig,
    renew: Option<&identity::RenewHandle>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<Option<ssh::recorder::FinalizeTracker>> {
    if cfg.ssh.listen_addr.is_empty() {
        return Ok(None);
    }
    let Some(renew) = renew else {
        tracing::warn!(
            "ssh.listen_addr is set but the Gateway has no CP mTLS identity; refusing to start the outer leg (fail closed)"
        );
        return Ok(None);
    };

    let server_name = host_from_endpoint(&cfg.cp_mtls_endpoint).ok_or_else(|| {
        anyhow::anyhow!("cannot derive CP server name from {}", cfg.cp_mtls_endpoint)
    })?;
    let params = mtls::ChannelParams {
        endpoint: cfg.cp_mtls_endpoint.clone(),
        server_name,
        connect_timeout: Duration::from_secs(cfg.ssh.cp_connect_timeout_secs),
        rpc_timeout: Duration::from_secs(cfg.ssh.cp_rpc_timeout_secs),
    };

    // Republish the renewing credential as channel snapshots so the CP auth
    // client always dials with the current identity.
    let (snap_tx, snap_rx) = tokio::sync::watch::channel(snapshot(&renew.current()));
    let mut cred_rx = renew.subscribe();
    tokio::spawn(async move {
        while cred_rx.changed().await.is_ok() {
            let cred = cred_rx.borrow_and_update().clone();
            let _ = snap_tx.send(snapshot(&cred));
        }
    });

    let factory = Arc::new(cpauth::CpChannelFactory::from_watch(params, snap_rx));
    let cpauth = Arc::new(cpauth::CpAuthClient::new(
        factory,
        Duration::from_secs(cfg.ssh.cp_rpc_timeout_secs),
    ));
    let ssh_cfg = Arc::new(cfg.ssh.clone());
    // Session Nine: the real session recorder (asciicast v2 + SFTP/SCP decode +
    // customer-key encryption + hash-chained WORM upload). Reuses the one CP
    // client; reads the optional upload-CA up front (fail closed on misconfig).
    let recorder_factory = Arc::new(ssh::recorder::RecorderFactoryImpl::new(
        cpauth.clone(),
        cfg.ssh.recorder.clone(),
    )?);
    let finalize_tracker = ssh::recorder::FinalizeTracker::default();
    let deps = ssh::handler::HandlerDeps {
        cpauth,
        connector: Arc::new(ssh::connector::AgentlessDial::new(Duration::from_secs(
            ssh_cfg.inner.connect_timeout_secs,
        ))),
        resolver: Arc::new(ssh::target::IdentityResolver),
        recorder_factory,
        finalize_tracker: finalize_tracker.clone(),
        config: ssh_cfg.clone(),
    };

    let server = ssh::bind(ssh_cfg, deps).await?;
    tracing::info!(addr = %server.local_addr(), "outer SSH leg started");
    let mut shutdown = shutdown;
    tokio::spawn(async move {
        server
            .run(async move {
                let _ = shutdown.wait_for(|v| *v).await;
            })
            .await;
    });
    Ok(Some(finalize_tracker))
}

/// Snapshot a credential for the CP channel factory (leaf/key + trust anchors).
fn snapshot(cred: &identity::Credential) -> cpauth::CredentialSnapshot {
    cpauth::CredentialSnapshot {
        identity: cred.identity.clone(),
        ca_chain_der: cred.ca_chain_der.clone(),
    }
}

/// Extract the host from a `scheme://host:port` endpoint (no external URL dep),
/// correctly handling a bracketed IPv6 literal (`[::1]` / `[::1]:9443`).
fn host_from_endpoint(endpoint: &str) -> Option<String> {
    let after_scheme = endpoint.split("://").nth(1).unwrap_or(endpoint);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: the host is between the brackets; a `:port` may follow.
        rest.split(']').next().unwrap_or(rest)
    } else {
        // host or host:port — the host has no colons, so strip a trailing :port.
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    (!host.is_empty()).then(|| host.to_string())
}

/// Structured logging via `tracing`. Honours `RUST_LOG`, defaulting to `info`.
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_is_extracted_from_endpoint() {
        assert_eq!(
            host_from_endpoint("https://cp.internal:9443").as_deref(),
            Some("cp.internal")
        );
        assert_eq!(
            host_from_endpoint("https://127.0.0.1:9443").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            host_from_endpoint("https://cp.internal").as_deref(),
            Some("cp.internal")
        );
        // Bracketed IPv6 literal, with and without a port.
        assert_eq!(
            host_from_endpoint("https://[::1]:9443").as_deref(),
            Some("::1")
        );
        assert_eq!(host_from_endpoint("https://[::1]").as_deref(), Some("::1"));
        assert_eq!(
            host_from_endpoint("https://[2001:db8::5]:9443").as_deref(),
            Some("2001:db8::5")
        );
        assert_eq!(host_from_endpoint("").as_deref(), None);
    }

    #[test]
    fn default_config_bootstraps_no_identity() {
        // The default (un-enrolled) config must not attempt enrollment.
        let cfg = GatewayConfig::default();
        assert!(cfg.bootstrap.is_none());
    }
}
