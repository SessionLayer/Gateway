//! CP <-> Gateway version-negotiation smoke (dev-only, plaintext).

use clap::Parser;
use gateway_core::handshake;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "handshake-smoke",
    about = "CP <-> Gateway version-negotiation smoke (dev-only, plaintext)"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:9090")]
    endpoint: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    let args = Args::parse();

    match handshake::negotiate(&args.endpoint).await {
        Ok(negotiated) => {
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

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}
