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
    agent,
    asyncio::{self, IoBackend},
    config::{CoordinationConfig, GatewayConfig, HaConfig},
    cpauth, ha, handshake, health, identity, mtls, ssh, tls,
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

        // Two signals (Session Fifteen, M3 / FR-HA-7 ordering):
        //   * `shutdown` — the OS signal (SIGTERM / Ctrl-C); only `run` observes it, to SEQUENCE
        //     the drain.
        //   * `drain` — begin-drain: stop accepting, release presence, stop serving new relays,
        //     close agent control channels. The servers + background loops watch THIS, and it
        //     fires only AFTER the pre-drain grace, so the LB deregisters us while we still accept.
        // A `watch` retains the value so no observer loses the edge.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            wait_for_shutdown().await;
            let _ = shutdown_tx.send(true);
        });
        let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);

        // Outer SSH leg (Session Seven): started only when configured AND the
        // Gateway holds a CP mTLS identity to delegate auth to (fail closed).
        let outer = start_outer_leg(&cfg, renew.as_ref(), drain_rx.clone()).await?;

        // Readiness surface (Session Fifteen): `ready` until we start draining. A
        // separate `readyz_stop` keeps the /readyz listener alive THROUGH the drain (so
        // the LB keeps seeing 503 while sessions finish), stopping only at the very end.
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(true);
        let (readyz_stop_tx, readyz_stop_rx) = tokio::sync::watch::channel(false);
        if !cfg.ha.drain.readyz_addr.is_empty() {
            ha::readiness::spawn(cfg.ha.drain.readyz_addr.clone(), ready_rx, readyz_stop_rx);
        }

        tracing::info!("awaiting shutdown signal (SIGTERM / Ctrl-C)");
        let mut sd = shutdown_rx;
        let _ = sd.wait_for(|v| *v).await;
        tracing::info!("shutdown signal received; Gateway stopping");

        // Graceful drain (Session Fifteen, §10.3 — closes S9 F-drain; M3 ordering).
        // (1) Flip `/readyz` to 503 but KEEP ACCEPTING for the pre-drain grace, so the LB
        //     observes unready and deregisters us FIRST (no window where it still routes a new
        //     connection to a Gateway that has stopped listening).
        let _ = ready_tx.send(false);
        let pre_grace = Duration::from_secs(cfg.ha.drain.pre_drain_grace_secs);
        if !pre_grace.is_zero() {
            tracing::info!(grace_secs = pre_grace.as_secs(), "pre-drain grace: unready but still accepting so the LB can deregister");
            tokio::time::sleep(pre_grace).await;
        }
        // (2) BEGIN drain: stop accepting, the heartbeat loop releases presence so a standby
        //     claims, and agent control channels close so agents fail over.
        let _ = drain_tx.send(true);
        // (3) FINISH live sessions AND owner-role relays to a bounded deadline (not dropped
        //     instantly — the F-drain fix + M2). (4) Any still-live session at the deadline is
        //     torn down via the recorder-finalize path (L4). (5) drain in-flight finalizes.
        if let Some(outer) = outer {
            let deadline = Duration::from_secs(cfg.ha.drain.deadline_secs);
            drain_live_sessions(&outer.live_sessions, outer.served_relays.as_ref(), deadline).await;
            let remaining = outer.live_sessions.terminate_all();
            if remaining > 0 {
                tracing::warn!(remaining, "tearing down sessions still live at the drain deadline via the recorder-finalize path (L4)");
            }
            let grace = Duration::from_secs(cfg.ssh.recorder.upload_timeout_secs.saturating_add(10));
            tracing::info!(grace_secs = grace.as_secs(), "draining in-flight recording finalizes");
            outer.finalize_tracker.drain(grace).await;
        }
        let _ = readyz_stop_tx.send(true);
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
/// The running outer leg's drain handles (Session Fifteen): the recording finalize tracker
/// and the live-session registry the graceful drain waits on.
struct OuterLeg {
    finalize_tracker: ssh::recorder::FinalizeTracker,
    live_sessions: Arc<ssh::locks::LiveSessionRegistry>,
    /// Relays this Gateway serves AS AN OWNER for peer ingresses (M2). They have no
    /// LiveSessionRegistry of their own, so the drain waits on this counter too — otherwise a
    /// pure owner/relay Gateway would cut its live relayed sessions the instant it exits.
    served_relays: Option<Arc<ha::peer_client::ServedRelays>>,
}

/// Wait for both this Gateway's own live sessions AND the relays it serves as an owner to
/// finish, bounded by `deadline` (the S9 F-drain fix + M2: sessions are finished-to-deadline,
/// not dropped instantly, on either role).
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

    let factory = Arc::new(cpauth::CpChannelFactory::from_watch(
        params,
        snap_rx.clone(),
    ));
    let cpauth = Arc::new(cpauth::CpAuthClient::new(
        factory.clone(),
        Duration::from_secs(cfg.ssh.cp_rpc_timeout_secs),
    ));
    let ssh_cfg = Arc::new(cfg.ssh.clone());

    // Session Ten: the actively-pushed lock deny-set + live-session registry, and
    // the background lock-feed stream client (resync on reconnect; the set is never
    // cleared on disconnect, so a pushed lock keeps denying under datastore loss).
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
    // Session Nine: the real session recorder (asciicast v2 + SFTP/SCP decode +
    // customer-key encryption + hash-chained WORM upload). Reuses the one CP
    // client; reads the optional upload-CA up front (fail closed on misconfig).
    let recorder_factory = Arc::new(ssh::recorder::RecorderFactoryImpl::new(
        cpauth.clone(),
        cfg.ssh.recorder.clone(),
    )?);
    let finalize_tracker = ssh::recorder::FinalizeTracker::default();

    // Session Fourteen: the outbound-agent transport (Design §9.2). Started only when
    // configured; a node whose inventory declares OUTBOUND_AGENT is otherwise simply
    // offline (fail closed — never a silent fallback to an agentless dial).
    let (agent_connector, served_relays) = match start_agent_transport(
        cfg,
        &renew.current(),
        cpauth.clone(),
        lock_set.clone(),
        snap_rx,
        shutdown.clone(),
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
    let deps = ssh::handler::HandlerDeps {
        cpauth,
        connector,
        resolver: Arc::new(ssh::target::IdentityResolver),
        recorder_factory,
        finalize_tracker: finalize_tracker.clone(),
        lock_set,
        live_sessions: live_sessions.clone(),
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
    Ok(Some(OuterLeg {
        finalize_tracker,
        live_sessions,
        served_relays,
    }))
}

/// Start the outbound-agent WSS transport if `ssh.agent.listen_addr` is configured,
/// returning the agent `NodeConnector` to dispatch OUTBOUND_AGENT nodes to.
///
/// Fail-closed: if the transport is configured but cannot stand up (the CP will not
/// issue the agent-facing serverAuth leaf, the port is taken), startup **aborts** —
/// running the SSH front door while every agent node is silently unreachable would be
/// a worse failure than not starting.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
async fn start_agent_transport(
    cfg: &GatewayConfig,
    cred: &identity::Credential,
    cpauth: Arc<cpauth::CpAuthClient>,
    lock_set: Arc<ssh::locks::LockSet>,
    cred_watch: tokio::sync::watch::Receiver<cpauth::CredentialSnapshot>,
    shutdown: tokio::sync::watch::Receiver<bool>,
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
    // Per-process, in-memory, never persisted: a token from a previous boot or another
    // Gateway cannot be redeemed here (contract §6).
    let signer = Arc::new(agent::token::DialBackSigner::generate());

    // HA (Session Fifteen): the coordination bus + relay-token machinery, always wired
    // (single mode is mode-symmetric — the remote path is dormant because the owner is always
    // self). The relay signer + pending ledger are shared between the ingress-side
    // RemoteGatewayConnector and the peer-relay server that redeems its tokens.
    let coordination = build_coordination(&cfg.ha)?;
    let relay_signer = Arc::new(ha::relay_token::RelaySigner::generate());
    let pending_relays = Arc::new(ha::relay_token::PendingRelays::default());
    let owner_cache = Arc::new(ha::presence::OwnerCache::new(Duration::from_secs(
        cfg.ha.routing.cache_ttl_secs,
    )));
    // In-flight served-relay registry: bounds concurrent relays per node (F4) and lets the
    // graceful drain wait for live relays this Gateway is serving as an owner (M2).
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
    // The dial-back address rides in the signal (contract §5), so it must be an address an
    // Agent can actually dial. A wildcard bind with no explicit `advertise_url` would send
    // every Agent to `0.0.0.0` and leave the whole agent fleet silently unreachable — fail
    // closed at startup instead of discovering it one dead session at a time.
    if local_addr.ip().is_unspecified() && acfg.advertise_url.is_empty() {
        anyhow::bail!(
            "ssh.agent.listen_addr binds a wildcard address ({local_addr}); set ssh.agent.advertise_url to the wss:// URL agents should dial back to"
        );
    }
    // The host:port a peer owner dials back to for the direct relay (the SAME TLS server as
    // the agent transport). Configured explicitly, else derived from the agent advertise URL.
    let peer_relay_addr = derive_peer_relay_addr(&cfg.ha, &advertise)?;
    tracing::info!(addr = %local_addr, advertise = %advertise, peer_relay_addr = %peer_relay_addr, mode = ?cfg.ha.mode, "outbound-agent transport + HA peer relay started");

    let mut sd = shutdown.clone();
    tokio::spawn(async move {
        transport
            .run(async move {
                let _ = sd.wait_for(|v| *v).await;
            })
            .await;
    });

    // The LOCAL agent connector (S14): shared by the router (local route) and the peer client
    // (the owner-side node dial-back that produces the byte stream to relay).
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

    // Claim presence for every node this Gateway holds a channel for (runs in both modes).
    let store = Arc::new(ha::presence::CpPresenceStore::new(cpauth));
    ha::presence::HeartbeatLoop::new(
        store,
        registry.clone(),
        owner_cache.clone(),
        peer_relay_addr.clone(),
        Duration::from_secs(cfg.ha.presence.heartbeat_interval_secs),
    )
    .spawn(shutdown.clone());

    // The owner-side signal handler: serve a peer ingress a relay to a node we own.
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

    // The ingress-side remote connector + the router that decides local-vs-remote by owner.
    // The relay token must outlive the relay-establish window, so its TTL exceeds
    // relay_timeout by a comfortable margin.
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

/// Build the coordination signal bus from the HA config (Session Fifteen). In-process by
/// default (zero deps); the NATS backend lands behind the `nats` feature.
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

/// Resolve the peer-relay advertise address (`host:port`) a peer owner dials back to. Uses
/// `ha.peer_relay_advertise_addr` when set, else derives it from the agent advertise URL —
/// the peer relay shares that TLS server.
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
