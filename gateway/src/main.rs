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
    health,
};

/// `--version` output: SemVer plus the supported CP <-> Gateway protocol range.
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (SessionLayer Gateway; CP<->GW protocol 1.0-1.0)"
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

/// Run the daemon skeleton: a multi-threaded tokio runtime that logs readiness
/// and then idles until a shutdown signal. There are no listeners yet, so this
/// is deliberately inert beyond logging.
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
            cp_endpoint = %cfg.cp_endpoint,
            "SessionLayer Gateway starting (Session One scaffold; no SSH I/O)"
        );
        tracing::info!(
            "no data-plane listeners in this scaffold; awaiting shutdown signal (Ctrl-C)"
        );

        tokio::signal::ctrl_c().await?;
        tracing::info!("shutdown signal received; Gateway stopping");
        Ok::<(), anyhow::Error>(())
    })
}

/// Structured logging via `tracing`. Honours `RUST_LOG`, defaulting to `info`.
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();
}
