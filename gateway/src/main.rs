//! SessionLayer Gateway daemon (Session One scaffold).
//!
//! Tier-0 caution: this binary becomes the plaintext SSH MITM (Design §15,
//! NFR-5) — the largest blast radius in the platform. Session One ships only a
//! skeleton: structured logging, a health/version surface, and async-I/O
//! backend selection. There is NO SSH I/O, NO network listener, and NO
//! plaintext handling yet. Product behavior is added in later sessions behind
//! the seams established here.

use clap::{Parser, Subcommand, ValueEnum};
use gateway_core::{
    asyncio::{self, IoBackend},
    config::GatewayConfig,
    handshake, health, identity, mtls, tls,
};
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
/// mTLS identity (when a bootstrap credential is configured) and then idles until
/// a shutdown signal. There are still no data-plane listeners (the SSH legs are
/// later sessions), so beyond the identity lifecycle this is inert.
///
/// **Fail-closed:** with a bootstrap credential configured, an enrollment /
/// load failure aborts startup (the process exits non-zero) rather than running
/// without an authenticated CP identity.
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

        tracing::info!("no data-plane listeners yet; awaiting shutdown signal (Ctrl-C)");
        tokio::signal::ctrl_c().await?;
        tracing::info!("shutdown signal received; Gateway stopping");
        Ok::<(), anyhow::Error>(())
    })
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
