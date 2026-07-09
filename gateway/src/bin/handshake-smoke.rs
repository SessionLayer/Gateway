//! `handshake-smoke` — connect to the CP gRPC `Handshake` service, negotiate the
//! protocol version, print `negotiated <version>`, and exit 0 (nonzero on
//! failure).
//!
//! This is the Gateway half of the cross-repo version-negotiation smoke
//! (`scripts/e2e-smoke.sh`). It is intentionally exercised by that e2e (against
//! a running CP), NOT by `cargo nextest run` — unit tests use an in-process mock
//! (`gateway_core::handshake` tests) and never require a running CP.
//!
//! Dev-only plaintext transport; mTLS arrives in Session Four.

use clap::Parser;
use gateway_core::handshake;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "handshake-smoke",
    about = "CP <-> Gateway version-negotiation smoke (dev-only, plaintext)"
)]
struct Args {
    /// CP gRPC endpoint, e.g. http://127.0.0.1:9090
    #[arg(long, default_value = "http://127.0.0.1:9090")]
    endpoint: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    let args = Args::parse();

    match handshake::negotiate(&args.endpoint).await {
        Ok(negotiated) => {
            // The e2e smoke greps for "negotiated <version>"; keep that literal.
            println!(
                "negotiated {} with {} (semver {})",
                negotiated.version_string(),
                negotiated.server_name,
                negotiated.server_semver
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("handshake-smoke: negotiation failed: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Structured logging via `tracing`. Honours `RUST_LOG`, defaulting to `warn` so
/// the smoke's stdout stays clean for the e2e grep. `try_init` avoids panicking
/// if a subscriber is already set.
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}
