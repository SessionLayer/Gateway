use clap::{Parser, Subcommand, ValueEnum};
use gateway::hardening;
use gateway_core::{
    agent,
    asyncio::{self, IoBackend},
    config::{CoordinationConfig, GatewayConfig, HaConfig},
    cpauth, ha, handshake, health, identity, mtls, ssh, tls,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (SessionLayer Gateway; CP<->GW protocol 1.0-1.1)"
);

#[derive(Parser, Debug)]
#[command(
    name = "gateway",
    version = VERSION,
    about = "SessionLayer Gateway daemon: policy-enforced SSH proxy with session recording"
)]
struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Health,
    IoBackend {
        #[arg(long, value_enum, default_value_t = BackendArg::Epoll)]
        request: BackendArg,
    },
}

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
    let cli = Cli::parse();
    match cli.command {
        // The daemon path installs its subscriber (with the optional OTel layer)
        // inside the runtime via `telemetry::init`; the print-and-exit subcommands
        // just need plain fmt logging.
        Some(Command::Health) => {
            init_tracing();
            println!("{}", serde_json::to_string_pretty(&health::report())?);
            Ok(())
        }
        Some(Command::IoBackend { request }) => {
            init_tracing();
            let requested = IoBackend::from(request);
            let resolved = asyncio::select_io(requested).backend();
            println!("requested {requested:?} -> resolved {resolved:?}");
            Ok(())
        }
        None => run(cli.config),
    }
}

fn run(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    let cfg = GatewayConfig::load(config_path.as_deref())?;

    hardening::disable_coredumps(&cfg.hardening)?;

    let io_uring_active = matches!(
        asyncio::select_io(cfg.io_backend).backend(),
        IoBackend::Uring
    );

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if cfg.hardening.landlock.enabled {
        let ll = cfg.hardening.landlock.clone();
        builder.on_thread_start(move || hardening::confine_thread_for_landlock(&ll));
    }
    let runtime = builder.build()?;

    runtime.block_on(async {
        let _telemetry = gateway_core::telemetry::init();

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

        let renew = bootstrap_identity(&cfg).await?;
        if renew.is_none() {
            tracing::info!(
                "no bootstrap credential configured; running without a CP mTLS identity (scaffold mode)"
            );
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            wait_for_shutdown().await;
            let _ = shutdown_tx.send(true);
        });
        let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);

        let mut serves: Vec<Box<dyn FnOnce() + Send>> = Vec::new();

        let outer = start_outer_leg(&cfg, renew.as_ref(), drain_rx.clone(), &mut serves).await?;

        let (ready_tx, ready_rx) = tokio::sync::watch::channel(true);
        let (readyz_stop_tx, readyz_stop_rx) = tokio::sync::watch::channel(false);
        if !cfg.ha.drain.readyz_addr.is_empty() {
            let addr = cfg.ha.drain.readyz_addr.clone();
            serves.push(Box::new(move || {
                ha::readiness::spawn(addr, ready_rx, readyz_stop_rx);
            }));
        }

        hardening::apply(&cfg.hardening, io_uring_active)?;

        for serve in serves {
            serve();
        }

        tracing::info!("awaiting shutdown signal (SIGTERM / Ctrl-C)");
        let mut sd = shutdown_rx;
        let _ = sd.wait_for(|v| *v).await;
        tracing::info!("shutdown signal received; Gateway stopping");

        let _ = ready_tx.send(false);
        let pre_grace = Duration::from_secs(cfg.ha.drain.pre_drain_grace_secs);
        if !pre_grace.is_zero() {
            tracing::info!(grace_secs = pre_grace.as_secs(), "pre-drain grace: unready but still accepting so the LB can deregister");
            tokio::time::sleep(pre_grace).await;
        }
        let _ = drain_tx.send(true);
        if let Some(outer) = outer {
            let deadline = Duration::from_secs(cfg.ha.drain.deadline_secs);
            drain_live_sessions(&outer.live_sessions, outer.served_relays.as_ref(), deadline).await;
            let remaining = outer.live_sessions.terminate_all();
            if remaining > 0 {
                tracing::warn!(remaining, "tearing down sessions still live at the drain deadline via the recorder-finalize path");
                drain_live_sessions(&outer.live_sessions, None, TEARDOWN_SETTLE_BOUND).await;
            }
            let grace = Duration::from_secs(cfg.ssh.recorder.upload_timeout_secs.saturating_add(10));
            tracing::info!(grace_secs = grace.as_secs(), "draining in-flight recording finalizes");
            outer.finalize_tracker.drain(grace).await;
        }
        let _ = readyz_stop_tx.send(true);
        Ok::<(), anyhow::Error>(())
    })
}

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

async fn bootstrap_identity(cfg: &GatewayConfig) -> anyhow::Result<Option<identity::RenewHandle>> {
    let Some(bootstrap) = cfg.bootstrap.clone() else {
        return Ok(None);
    };

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

    let boot_channel = mtls::connect_bootstrap(&params, &anchors).await?;
    let negotiated = handshake::negotiate_over_channel(boot_channel)
        .await
        .map_err(|e| anyhow::anyhow!("CP<->GW version negotiation failed: {e}"))?;
    tracing::info!(
        protocol = %negotiated.version_string(),
        server = %negotiated.server_name,
        "negotiated CP<->GW protocol version at connect"
    );

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

    tokio::spawn(async move {
        let shutdown = Box::pin(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        renew_ahead.run(shutdown).await;
    });

    Ok(Some(handle))
}

struct OuterLeg {
    finalize_tracker: ssh::recorder::FinalizeTracker,
    live_sessions: Arc<ssh::locks::LiveSessionRegistry>,
    served_relays: Option<Arc<ha::peer_client::ServedRelays>>,
}

const TEARDOWN_SETTLE_BOUND: Duration = Duration::from_secs(5);

async fn drain_live_sessions(
    live: &ssh::locks::LiveSessionRegistry,
    served_relays: Option<&Arc<ha::peer_client::ServedRelays>>,
    deadline: Duration,
) {
    let start = std::time::Instant::now();
    loop {
        let sessions = live.len();
        let relays = served_relays.map(|r| r.active()).unwrap_or(0);
        if sessions == 0 && relays == 0 {
            return;
        }
        if start.elapsed() >= deadline {
            tracing::warn!(
                remaining_sessions = sessions,
                remaining_relays = relays,
                "drain deadline reached with sessions/relays still open; finalizing and exiting"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn start_outer_leg(
    cfg: &GatewayConfig,
    renew: Option<&identity::RenewHandle>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    serves: &mut Vec<Box<dyn FnOnce() + Send>>,
) -> anyhow::Result<Option<OuterLeg>> {
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

    let (snap_tx, snap_rx) = tokio::sync::watch::channel(snapshot(&renew.current()));
    let mut cred_rx = renew.subscribe();
    tokio::spawn(async move {
        while cred_rx.changed().await.is_ok() {
            let cred = cred_rx.borrow_and_update().clone();
            let _ = snap_tx.send(snapshot(&cred));
        }
    });

    let factory = Arc::new(cpauth::CpChannelFactory::from_watch(
        params,
        snap_rx.clone(),
    ));
    let cpauth = Arc::new(cpauth::CpAuthClient::new(
        factory.clone(),
        Duration::from_secs(cfg.ssh.cp_rpc_timeout_secs),
    ));
    let ssh_cfg = Arc::new(cfg.ssh.clone());

    let lock_set = Arc::new(ssh::locks::LockSet::new(
        ssh_cfg.reeval.lock_feed_unhealthy_after_secs,
        ssh_cfg.reeval.lock_expiry_skew_secs,
    ));
    let live_sessions = Arc::new(ssh::locks::LiveSessionRegistry::default());
    ssh::lockfeed::LockFeedClientTask::new(
        factory,
        lock_set.clone(),
        live_sessions.clone(),
        Duration::from_secs(ssh_cfg.reeval.lock_feed_connect_timeout_secs),
    )
    .spawn(shutdown.clone());
    gateway_core::telemetry::register_gateway_gauges(live_sessions.clone(), lock_set.clone());
    let mut recorder_cfg = cfg.ssh.recorder.clone();
    if recorder_cfg.spool_dir.is_none() {
        let spool = cfg.data_dir.join("recording-spool");
        std::fs::create_dir_all(&spool).map_err(|e| {
            anyhow::anyhow!("creating recording spool dir {}: {e}", spool.display())
        })?;
        recorder_cfg.spool_dir = Some(spool);
    }
    let recorder_factory = Arc::new(ssh::recorder::RecorderFactoryImpl::new(
        cpauth.clone(),
        recorder_cfg,
    )?);
    let finalize_tracker = ssh::recorder::FinalizeTracker::default();

    let (agent_connector, served_relays) = match start_agent_transport(
        cfg,
        &renew.current(),
        cpauth.clone(),
        lock_set.clone(),
        snap_rx,
        shutdown.clone(),
        serves,
    )
    .await?
    {
        Some((connector, served_relays)) => (Some(connector), Some(served_relays)),
        None => (None, None),
    };

    let connector = Arc::new(ssh::connector::DispatchConnector::new(
        Arc::new(ssh::connector::AgentlessDial::new(Duration::from_secs(
            ssh_cfg.inner.connect_timeout_secs,
        ))),
        agent_connector,
    ));
    let proxy_jump = if ssh_cfg.proxy_jump.enabled {
        match ssh::proxyjump::ProxyJumpState::new() {
            Ok(state) => {
                tracing::info!("ProxyJump host-cert MITM enabled");
                Some(Arc::new(state))
            }
            Err(e) => {
                tracing::error!(error = %e, "ProxyJump enabled but outer host key generation failed; ProxyJump DISABLED (direct-tcpip is handled as an ordinary local port-forward, still gated on port_forward_local)");
                None
            }
        }
    } else {
        None
    };
    let deps = ssh::handler::HandlerDeps {
        cpauth,
        connector,
        resolver: Arc::new(ssh::target::IdentityResolver),
        recorder_factory,
        finalize_tracker: finalize_tracker.clone(),
        lock_set,
        live_sessions: live_sessions.clone(),
        config: ssh_cfg.clone(),
        proxy_jump,
    };

    let server = ssh::bind(ssh_cfg, deps).await?;
    tracing::info!(addr = %server.local_addr(), "outer SSH leg bound (serving after hardening)");
    let mut shutdown = shutdown;
    serves.push(Box::new(move || {
        tokio::spawn(async move {
            server
                .run(async move {
                    let _ = shutdown.wait_for(|v| *v).await;
                })
                .await;
        });
    }));
    Ok(Some(OuterLeg {
        finalize_tracker,
        live_sessions,
        served_relays,
    }))
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
async fn start_agent_transport(
    cfg: &GatewayConfig,
    cred: &identity::Credential,
    cpauth: Arc<cpauth::CpAuthClient>,
    lock_set: Arc<ssh::locks::LockSet>,
    cred_watch: tokio::sync::watch::Receiver<cpauth::CredentialSnapshot>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    serves: &mut Vec<Box<dyn FnOnce() + Send>>,
) -> anyhow::Result<
    Option<(
        Arc<dyn ssh::connector::NodeConnector>,
        Arc<ha::peer_client::ServedRelays>,
    )>,
> {
    let acfg = &cfg.ssh.agent;
    if acfg.listen_addr.is_empty() {
        return Ok(None);
    }

    let registry = Arc::new(agent::registry::AgentRegistry::new(acfg.max_agents));
    let pending = Arc::new(agent::token::PendingDialBacks::default());
    let signer = Arc::new(agent::token::DialBackSigner::generate());

    let coordination = build_coordination(&cfg.ha)?;
    let relay_signer = Arc::new(ha::relay_token::RelaySigner::generate());
    let pending_relays = Arc::new(ha::relay_token::PendingRelays::default());
    let owner_cache = Arc::new(ha::presence::OwnerCache::new(Duration::from_secs(
        cfg.ha.routing.cache_ttl_secs,
    )));
    let served_relays = Arc::new(ha::peer_client::ServedRelays::default());
    let self_name = cred.gateway_name.clone();

    let transport = agent::server::bind(
        agent::server::AgentTransportDeps {
            cpauth: cpauth.clone(),
            gateway_id: cred.gateway_id.clone(),
            gateway_name: self_name.clone(),
            registry: registry.clone(),
            pending: pending.clone(),
            signer: signer.clone(),
            lock_set: lock_set.clone(),
            peer_relay: Some(agent::server::PeerRelayServerDeps {
                relay_signer: relay_signer.clone(),
                pending_relays: pending_relays.clone(),
            }),
            config: acfg.clone(),
        },
        shutdown.clone(),
    )
    .await?;
    let local_addr = transport.local_addr();
    let advertise = agent::server::advertise_url(acfg, local_addr);
    if local_addr.ip().is_unspecified() && acfg.advertise_url.is_empty() {
        anyhow::bail!(
            "ssh.agent.listen_addr binds a wildcard address ({local_addr}); set ssh.agent.advertise_url to the wss:// URL agents should dial back to"
        );
    }
    let peer_relay_addr = derive_peer_relay_addr(&cfg.ha, &advertise)?;
    tracing::info!(addr = %local_addr, advertise = %advertise, peer_relay_addr = %peer_relay_addr, mode = ?cfg.ha.mode, "outbound-agent transport + HA peer relay started");

    let mut sd = shutdown.clone();
    serves.push(Box::new(move || {
        tokio::spawn(async move {
            transport
                .run(async move {
                    let _ = sd.wait_for(|v| *v).await;
                })
                .await;
        });
    }));

    let agent_dial: Arc<dyn ssh::connector::NodeConnector> = Arc::new(agent::dial::AgentDial::new(
        registry.clone(),
        pending,
        signer,
        lock_set,
        cred.gateway_id.clone(),
        advertise,
        acfg.dial_back_token_ttl_secs,
        Duration::from_secs(acfg.dial_back_timeout_secs),
    ));

    let store = Arc::new(ha::presence::CpPresenceStore::new(cpauth));
    ha::presence::HeartbeatLoop::new(
        store,
        registry.clone(),
        owner_cache.clone(),
        peer_relay_addr.clone(),
        Duration::from_secs(cfg.ha.presence.heartbeat_interval_secs),
    )
    .spawn(shutdown.clone());

    ha::peer_client::spawn(
        ha::peer_client::PeerClientDeps {
            coordination: coordination.clone(),
            self_gateway_id: self_name.clone(),
            local_connector: agent_dial.clone(),
            registry,
            owner_cache: owner_cache.clone(),
            served_relays: served_relays.clone(),
            credential: cred_watch,
            max_frame_bytes: acfg.max_frame_bytes,
            handshake_timeout: Duration::from_secs(acfg.handshake_timeout_secs),
        },
        shutdown,
    );

    let remote: Arc<dyn ssh::connector::NodeConnector> =
        Arc::new(ha::connector::RemoteGatewayConnector::new(
            coordination,
            relay_signer,
            pending_relays,
            self_name.clone(),
            peer_relay_addr,
            Duration::from_secs(cfg.ha.routing.relay_timeout_secs),
            Duration::from_secs(cfg.ha.routing.relay_timeout_secs + 20),
        ));
    let router: Arc<dyn ssh::connector::NodeConnector> = Arc::new(ha::connector::AgentRouter::new(
        self_name,
        agent_dial,
        remote,
        owner_cache,
    ));
    Ok(Some((router, served_relays)))
}

fn build_coordination(
    ha: &HaConfig,
) -> anyhow::Result<Arc<dyn ha::coordination::CoordinationBackend>> {
    match &ha.coordination {
        CoordinationConfig::InProcess => Ok(Arc::new(ha::coordination::InProcessBackend::new())),
        CoordinationConfig::Nats {
            url,
            subject_prefix,
        } => {
            tracing::info!(url = %url, subject_prefix = %subject_prefix, "using the NATS coordination backend (core pub/sub; run NATS on a trusted network or NATS-over-TLS)");
            let backend = ha::nats::NatsBackend::connect(url, subject_prefix)
                .map_err(|e| anyhow::anyhow!("NATS coordination backend: {e}"))?;
            Ok(Arc::new(backend))
        }
    }
}

fn derive_peer_relay_addr(ha: &HaConfig, agent_advertise_url: &str) -> anyhow::Result<String> {
    if !ha.peer_relay_advertise_addr.is_empty() {
        return Ok(ha.peer_relay_advertise_addr.clone());
    }
    let addr = agent_advertise_url
        .strip_prefix("wss://")
        .unwrap_or(agent_advertise_url)
        .split('/')
        .next()
        .unwrap_or(agent_advertise_url);
    if addr.is_empty() {
        anyhow::bail!(
            "cannot derive ha.peer_relay_advertise_addr from the agent advertise URL {agent_advertise_url:?}; set ha.peer_relay_advertise_addr"
        );
    }
    Ok(addr.to_string())
}

fn snapshot(cred: &identity::Credential) -> cpauth::CredentialSnapshot {
    cpauth::CredentialSnapshot {
        identity: cred.identity.clone(),
        ca_chain_der: cred.ca_chain_der.clone(),
    }
}

fn host_from_endpoint(endpoint: &str) -> Option<String> {
    let after_scheme = endpoint.split("://").nth(1).unwrap_or(endpoint);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    (!host.is_empty()).then(|| host.to_string())
}

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
        let cfg = GatewayConfig::default();
        assert!(cfg.bootstrap.is_none());
    }

    /// Waiting for `live_sessions.len() == 0` after `terminate_all()` is only safe if this
    /// wait genuinely observes the count draining - so returning PROMPTLY matters as much
    /// as blocking. (A faithful live-session variant needs a real russh `Handle` in
    /// `SessionControl`, which only the Docker E2E provides.)
    #[tokio::test]
    async fn drain_blocks_until_in_flight_reaches_zero_then_returns_promptly() {
        let live = ssh::locks::LiveSessionRegistry::default();
        let relays = Arc::new(ha::peer_client::ServedRelays::default());

        let t0 = std::time::Instant::now();
        drain_live_sessions(&live, Some(&relays), Duration::from_secs(30)).await;
        assert!(t0.elapsed() < Duration::from_secs(1));

        let slot = relays.begin("web-01").expect("slot");
        assert_eq!(relays.active(), 1);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            drop(slot);
        });
        let t1 = std::time::Instant::now();
        drain_live_sessions(&live, Some(&relays), Duration::from_secs(30)).await;
        let waited = t1.elapsed();
        assert!(
            waited >= Duration::from_millis(350),
            "it waited for the relay to finish"
        );
        assert!(
            waited < Duration::from_secs(5),
            "and returned once drained, not at the 30s deadline"
        );
    }
}
