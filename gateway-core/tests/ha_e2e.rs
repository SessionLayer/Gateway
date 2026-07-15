//! Session Fifteen — **a real SSH session relayed across two Gateways**.
//!
//! `ssh deploy%node@gw-A` where the node's Agent is connected to **gw-B**. gw-A (ingress)
//! authorizes, learns from presence that gw-B owns the node, signals gw-B over the
//! coordination bus, and gw-B dials a direct relay back and splices the node. gw-A runs the
//! UNCHANGED inner leg + recorder; the client is never redirected; the session bytes never
//! traverse the coordination bus. Two real `ssh::bind` gateways + the real agent transport +
//! a real Debian node, in one process.
#![cfg(feature = "test-agent")]

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use gateway_core::agent::dial::AgentDial;
use gateway_core::agent::registry::AgentRegistry;
use gateway_core::agent::server::{self, PeerRelayServerDeps};
use gateway_core::agent::token::{DialBackSigner, PendingDialBacks};
use gateway_core::config::{
    AgentTransportConfig, DeviceFlowConfig, InnerLegServerConfig, SshServerConfig,
};
use gateway_core::cpauth::CredentialSnapshot;
use gateway_core::ha::connector::{AgentRouter, RemoteGatewayConnector};
use gateway_core::ha::coordination::{CoordinationBackend, InProcessBackend, PublishFuture};
use gateway_core::ha::peer_client::{self, PeerClientDeps, ServedRelays};
use gateway_core::ha::presence::{CpPresenceStore, HeartbeatLoop, OwnerCache};
use gateway_core::ha::relay_token::{PendingRelays, RelaySigner};
use gateway_core::pb::Capability;
use gateway_core::pbgw::DialBackSignal;
use gateway_core::ssh;
use gateway_core::ssh::connector::{AgentlessDial, DispatchConnector, NodeConnector};
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use support::docker::{self, build_image};
use support::{MockCp, RecorderChoice};
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient:s14";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode:s14";
const AGENT_NODE_IMAGE: &str = "sessionlayer-gw-agentnode:s14";

// A REAL human node name (NOT UUID-shaped): the HA path resolves ownership by node NAME, and a
// UUID-shaped name would mask the name->node.id resolution the CP performs (T3 item 1).
const NODE: &str = "web-01";
const AGENT_ID: &str = "agent-ha";
const GW_A: &str = "gw-a-ha"; // ingress
const GW_B: &str = "gw-b-ha"; // owner (holds the agent)

async fn build_images() -> anyhow::Result<()> {
    build_image("ssh-client", CLIENT_IMAGE).await?;
    build_image("sshd", NODE_IMAGE).await?;
    docker::build_image_with_args(
        "agent-node",
        AGENT_NODE_IMAGE,
        &[("NODE_IMAGE", NODE_IMAGE)],
    )
    .await
}

struct KeyMat {
    private_openssh: String,
    public_line: String,
    public_wire: Vec<u8>,
    fingerprint: String,
}

fn gen_key(alg: Algorithm) -> KeyMat {
    let key = PrivateKey::random(&mut OsRng, alg).unwrap();
    KeyMat {
        private_openssh: key.to_openssh(LineEnding::LF).unwrap().to_string(),
        public_line: key.public_key().to_openssh().unwrap(),
        public_wire: key.public_key().to_bytes().unwrap(),
        fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
    }
}

fn test_agent_binary() -> Vec<u8> {
    std::fs::read(env!("CARGO_BIN_EXE_test-agent")).expect("cargo builds the test agent")
}

/// A coordination backend wrapping `InProcessBackend` that records every published signal, so
/// the test can prove the session plaintext never rode the bus.
struct RecordingBus {
    inner: InProcessBackend,
    published: Mutex<Vec<Vec<u8>>>,
}

impl RecordingBus {
    fn new() -> Self {
        Self {
            inner: InProcessBackend::new(),
            published: Mutex::new(Vec::new()),
        }
    }
    fn assert_no_bytes(&self, needle: &[u8]) {
        let published = self.published.lock().unwrap();
        assert!(!published.is_empty(), "the dial-back signal was published");
        for p in published.iter() {
            assert!(
                !p.windows(needle.len()).any(|w| w == needle),
                "session output must NEVER traverse the coordination bus"
            );
        }
    }
}

impl CoordinationBackend for RecordingBus {
    fn publish_dial_back<'a>(
        &'a self,
        owner: &'a str,
        signal: &'a DialBackSignal,
    ) -> PublishFuture<'a> {
        use prost::Message;
        self.published.lock().unwrap().push(signal.encode_to_vec());
        self.inner.publish_dial_back(owner, signal)
    }
    fn subscribe(&self, my_id: &str) -> futures_util::stream::BoxStream<'static, DialBackSignal> {
        self.inner.subscribe(my_id)
    }
}

fn ssh_cfg(agent_port: u16) -> SshServerConfig {
    SshServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        login_grace_secs: 60,
        device_flow: DeviceFlowConfig {
            heartbeat_interval_secs: 1,
            poll_timeout_secs: 20,
        },
        inner: InnerLegServerConfig {
            connect_timeout_secs: 4,
            handshake_timeout_secs: 8,
            max_session_idle_secs: 120,
            ..Default::default()
        },
        agent: AgentTransportConfig {
            listen_addr: format!("0.0.0.0:{agent_port}"),
            heartbeat_interval_secs: 5,
            dial_back_timeout_secs: 10,
            dial_back_token_ttl_secs: 30,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// gw-B (owner): the agent transport the node's Agent connects to, the presence heartbeat
/// loop that claims ownership, and the peer-client that serves relays. No outer SSH leg.
struct Owner {
    agent_port: u16,
    registry: Arc<AgentRegistry>,
    _sd: tokio::sync::watch::Sender<bool>,
}

async fn start_owner(
    cp: &MockCp,
    coordination: Arc<dyn CoordinationBackend>,
) -> anyhow::Result<Owner> {
    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    let agent_port = listener.local_addr()?.port();
    drop(listener);
    let config = Arc::new(ssh_cfg(agent_port));

    let (deps, cred) = support::outer_leg_deps_named(
        cp,
        config.clone(),
        Arc::new(AgentlessDial::new(Duration::from_secs(4))),
        RecorderChoice::Null,
        GW_B,
    )
    .await;

    let registry = Arc::new(AgentRegistry::new(16));
    let pending = Arc::new(PendingDialBacks::default());
    let signer = Arc::new(DialBackSigner::generate());
    let relay_signer = Arc::new(RelaySigner::generate());
    let pending_relays = Arc::new(PendingRelays::default());

    let transport = server::bind(
        server::AgentTransportDeps {
            cpauth: deps.cpauth.clone(),
            gateway_id: cred.gateway_id.clone(),
            gateway_name: GW_B.to_string(),
            registry: registry.clone(),
            pending: pending.clone(),
            signer: signer.clone(),
            lock_set: deps.lock_set.clone(),
            peer_relay: Some(PeerRelayServerDeps {
                relay_signer,
                pending_relays,
            }),
            config: config.agent.clone(),
        },
        sd_rx.clone(),
    )
    .await?;
    let agent_port = transport.local_addr().port();
    let mut sd = sd_rx.clone();
    tokio::spawn(transport.run(async move {
        let _ = sd.wait_for(|v| *v).await;
    }));

    let peer_relay_addr = format!("{}:{agent_port}", docker::container_reachable_host_ip());
    let advertise = format!(
        "wss://{}:{agent_port}",
        docker::container_reachable_host_ip()
    );

    let agent_dial: Arc<dyn NodeConnector> = Arc::new(AgentDial::new(
        registry.clone(),
        pending,
        signer,
        deps.lock_set.clone(),
        cred.gateway_id.clone(),
        advertise,
        config.agent.dial_back_token_ttl_secs,
        Duration::from_secs(config.agent.dial_back_timeout_secs),
    ));

    // Claim presence for the node (short interval so ownership is established quickly). The
    // heartbeat loop and the peer client share ONE OwnerCache so the R1 is_self_owner recheck
    // sees the claimed ownership.
    let owner_cache = Arc::new(OwnerCache::new(Duration::from_secs(30)));
    let store = Arc::new(CpPresenceStore::new(deps.cpauth.clone()));
    HeartbeatLoop::new(
        store,
        registry.clone(),
        owner_cache.clone(),
        peer_relay_addr,
        Duration::from_secs(1),
    )
    .spawn(sd_rx.clone());

    // Serve relays for peers.
    let (cred_tx, cred_rx) = tokio::sync::watch::channel(CredentialSnapshot {
        identity: cred.identity.clone(),
        ca_chain_der: cred.ca_chain_der.clone(),
    });
    std::mem::forget(cred_tx);
    peer_client::spawn(
        PeerClientDeps {
            coordination,
            self_gateway_id: GW_B.to_string(),
            local_connector: agent_dial,
            registry: registry.clone(),
            owner_cache,
            served_relays: Arc::new(ServedRelays::default()),
            credential: cred_rx,
            max_frame_bytes: config.agent.max_frame_bytes,
            handshake_timeout: Duration::from_secs(config.agent.handshake_timeout_secs),
        },
        sd_rx,
    );

    Ok(Owner {
        agent_port,
        registry,
        _sd: sd_tx,
    })
}

/// gw-A (ingress): the outer SSH leg the client connects to, plus the agent transport with
/// the peer-relay server + the AgentRouter that routes the remote-owned node to gw-B.
struct Ingress {
    ssh_port: u16,
    _sd: tokio::sync::watch::Sender<bool>,
}

async fn start_ingress(
    cp: &MockCp,
    coordination: Arc<dyn CoordinationBackend>,
) -> anyhow::Result<Ingress> {
    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    let agent_port = listener.local_addr()?.port();
    drop(listener);
    let config = Arc::new(ssh_cfg(agent_port));

    let (deps, cred) = support::outer_leg_deps_named(
        cp,
        config.clone(),
        Arc::new(AgentlessDial::new(Duration::from_secs(4))),
        RecorderChoice::Null,
        GW_A,
    )
    .await;

    let relay_signer = Arc::new(RelaySigner::generate());
    let pending_relays = Arc::new(PendingRelays::default());

    let transport = server::bind(
        server::AgentTransportDeps {
            cpauth: deps.cpauth.clone(),
            gateway_id: cred.gateway_id.clone(),
            gateway_name: GW_A.to_string(),
            registry: Arc::new(AgentRegistry::new(16)),
            pending: Arc::new(PendingDialBacks::default()),
            signer: Arc::new(DialBackSigner::generate()),
            lock_set: deps.lock_set.clone(),
            peer_relay: Some(PeerRelayServerDeps {
                relay_signer: relay_signer.clone(),
                pending_relays: pending_relays.clone(),
            }),
            config: config.agent.clone(),
        },
        sd_rx.clone(),
    )
    .await?;
    let agent_port = transport.local_addr().port();
    let peer_relay_addr = format!("{}:{agent_port}", docker::container_reachable_host_ip());
    let mut sd = sd_rx.clone();
    tokio::spawn(transport.run(async move {
        let _ = sd.wait_for(|v| *v).await;
    }));

    // The AgentRouter: gw-A holds no agent, so the remote-owned node routes over the relay.
    let remote: Arc<dyn NodeConnector> = Arc::new(RemoteGatewayConnector::new(
        coordination,
        relay_signer,
        pending_relays,
        GW_A.to_string(),
        peer_relay_addr,
        Duration::from_secs(10),
        Duration::from_secs(30),
    ));
    let local: Arc<dyn NodeConnector> = Arc::new(AgentlessDial::new(Duration::from_secs(4)));
    let router = Arc::new(AgentRouter::new(
        GW_A.to_string(),
        local,
        remote,
        Arc::new(OwnerCache::new(Duration::from_secs(30))),
    ));
    let connector = Arc::new(DispatchConnector::new(
        Arc::new(AgentlessDial::new(Duration::from_secs(4))),
        Some(router as Arc<dyn NodeConnector>),
    ));
    let deps = ssh::handler::HandlerDeps { connector, ..deps };

    let server = ssh::bind(config, deps).await?;
    let ssh_port = server.local_addr().port();
    let mut sd = sd_rx;
    tokio::spawn(server.run(async move {
        let _ = sd.wait_for(|v| *v).await;
    }));

    Ok(Ingress {
        ssh_port,
        _sd: sd_tx,
    })
}

async fn start_agent_node(
    cp: &MockCp,
    host_key: &KeyMat,
    owner_agent_port: u16,
) -> anyhow::Result<ContainerAsync<GenericImage>> {
    let identity = cp.issue_agent_identity(AGENT_ID, NODE);
    let node = GenericImage::new(
        AGENT_NODE_IMAGE.split(':').next().unwrap(),
        AGENT_NODE_IMAGE.split(':').nth(1).unwrap(),
    )
    .with_wait_for(WaitFor::message_on_stderr("Server listening on"))
    .with_startup_timeout(Duration::from_secs(120))
    .with_env_var("TRUSTED_USER_CA", cp.session_ca_public_line())
    .with_env_var(
        "AGENT_ENDPOINT",
        format!(
            "wss://{}:{owner_agent_port}",
            docker::container_reachable_host_ip()
        ),
    )
    // The node's Agent connects to the OWNER (gw-B), whose serverAuth cert carries gw-B's name.
    .with_env_var("AGENT_SERVER_NAME", GW_B)
    .with_env_var("AGENT_NODE_NAME", NODE)
    .with_env_var("AGENT_LOG", "info")
    .with_copy_to(
        CopyTargetOptions::new("/etc/ssh/ssh_host_ed25519_key").with_mode(0o600),
        host_key.private_openssh.clone().into_bytes(),
    )
    .with_copy_to(
        CopyTargetOptions::new("/etc/ssh/ssh_host_ed25519_key.pub").with_mode(0o644),
        host_key.public_line.clone().into_bytes(),
    )
    .with_copy_to(
        CopyTargetOptions::new("/agent/test-agent").with_mode(0o755),
        test_agent_binary(),
    )
    .with_copy_to(
        CopyTargetOptions::new("/agent/ca.pem").with_mode(0o644),
        cp.ca_pem(),
    )
    .with_copy_to(
        CopyTargetOptions::new("/agent/agent.pem").with_mode(0o644),
        gateway_core::mtls::cert_der_to_pem(&identity.cert_der),
    )
    .with_copy_to(
        CopyTargetOptions::new("/agent/agent.key").with_mode(0o600),
        identity.key_pem.into_bytes(),
    )
    .start()
    .await?;
    Ok(node)
}

async fn client_container(pin_key: &KeyMat) -> ContainerAsync<GenericImage> {
    GenericImage::new(
        CLIENT_IMAGE.split(':').next().unwrap(),
        CLIENT_IMAGE.split(':').nth(1).unwrap(),
    )
    .with_network("host")
    .with_startup_timeout(Duration::from_secs(60))
    .with_copy_to(
        CopyTargetOptions::new("/root/pin_key").with_mode(0o600),
        pin_key.private_openssh.clone().into_bytes(),
    )
    .start()
    .await
    .expect("start ssh-client container")
}

async fn ssh_exec(
    container: &ContainerAsync<GenericImage>,
    args: Vec<String>,
) -> (Option<i64>, String, String) {
    use testcontainers::core::ExecCommand;
    let mut res = container.exec(ExecCommand::new(args)).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

fn ssh_cmd(port: u16, target: &str, command: &str) -> Vec<String> {
    vec![
        "ssh".into(),
        "-p".into(),
        port.to_string(),
        "-i".into(),
        "/root/pin_key".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "ConnectTimeout=30".into(),
        format!("{target}@127.0.0.1"),
        command.into(),
    ]
}

#[tokio::test]
async fn ssh_is_relayed_across_two_gateways_and_the_bus_carries_no_session_bytes(
) -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let bus = Arc::new(RecordingBus::new());
    let coordination: Arc<dyn CoordinationBackend> = bus.clone();

    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", NODE, "deploy");
    cp.set_capabilities(NODE, &[Capability::Shell, Capability::Exec]);
    cp.set_agent_node_connection(
        NODE,
        NODE,
        cp.pinned_verification(host_key.public_wire.clone()),
    );

    // gw-B owns the node's agent; gw-A is the ingress the client connects to.
    let owner = start_owner(&cp, coordination.clone()).await?;
    let ingress = start_ingress(&cp, coordination.clone()).await?;
    let node = start_agent_node(&cp, &host_key, owner.agent_port).await?;

    // Wait for the agent to register on gw-B AND for gw-B to claim presence (so gw-A's
    // Authorize returns owning_gateway_id = gw-B and routes over the relay).
    for _ in 0..240 {
        if owner.registry.lookup(NODE).is_ok() && cp.presence_owner(NODE).as_deref() == Some(GW_B) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        owner.registry.lookup(NODE).is_ok(),
        "the node's agent registered on gw-B"
    );
    assert_eq!(
        cp.presence_owner(NODE).as_deref(),
        Some(GW_B),
        "gw-B claimed presence"
    );

    let client = client_container(&pin).await;

    // THE HEADLINE: the client connects to gw-A, the session is relayed to gw-B, and the
    // command runs on the node whose agent is on gw-B.
    let marker = "HA_RELAY_OK_9f3c";
    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(
            ingress.ssh_port,
            &format!("deploy%{NODE}"),
            &format!("echo {marker}; hostname"),
        ),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "the relayed session must succeed; stderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "node output returns over the cross-gateway relay; stdout={stdout:?}"
    );

    // The session output NEVER traversed the coordination bus (only the DialBackSignal did).
    bus.assert_no_bytes(marker.as_bytes());

    let _ = node;
    Ok(())
}
