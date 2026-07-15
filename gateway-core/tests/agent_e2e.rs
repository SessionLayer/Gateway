//! Session Fourteen, Parts B/D/E/F — **the first end-to-end SSH through the AGENT path**.
//!
//! `ssh login%node@gw 'echo AGENT_PATH_OK; hostname'` runs on a REAL Debian 13 node whose
//! `sshd` the Gateway never dials: the node's **non-root Agent** dials OUT to the
//! Gateway's WSS transport, the Gateway signals it, and the Agent dials back and splices
//! the connection to its own `127.0.0.1:22`. Everything above that seam — the inner-leg
//! certificate, no-TOFU host verification, the byte bridge, the recorder — is the S8/S9
//! code, unchanged.
//!
//! Networking: the SSH client container is `--network host` (so `127.0.0.1` is the host
//! loopback the Gateway binds to); the node container is on the bridge and dials OUT to the
//! Gateway on the host's routable address. The node needs **no inbound reachability of its
//! own** — the Gateway never connects to it, and its CP record carries no dial address.
#![cfg(feature = "test-agent")]

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway_core::agent::registry::AgentRegistry;
use gateway_core::agent::server;
use gateway_core::agent::token::{DialBackSigner, PendingDialBacks};
use gateway_core::config::{
    AgentTransportConfig, DeviceFlowConfig, InnerLegServerConfig, RecorderConfig, SshServerConfig,
};
use gateway_core::pb::{Capability, KeySealAlgorithm, RecordingStatus};
use gateway_core::ssh;
use gateway_core::ssh::connector::{AgentlessDial, DispatchConnector, NodeConnector};
use p256::pkcs8::EncodePublicKey;
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use support::docker::{self, build_image};
use support::{MockCp, RecorderChoice};
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient:s14";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode:s14";
const AGENT_NODE_IMAGE: &str = "sessionlayer-gw-agentnode:s14";

/// The agent-model node: `node_id` is what the resolver produces, `node_name` is the
/// enrollment name that joins the session to the Agent (its certificate's dNSName SAN).
const AGENT_NODE: &str = "node-agent";
const AGENT_ID: &str = "agent-1";
/// The agentless node in the same fleet (FR-CONN-3: a fleet mixes both models).
const DIRECT_NODE: &str = "node-direct";

const GW_NAME: &str = "gw-agent-e2e";

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

/// The `test-agent` binary cargo just built for us — the client half of the frozen wire
/// contract. It is injected into the node container and runs there as a non-root user.
fn test_agent_binary() -> Vec<u8> {
    std::fs::read(env!("CARGO_BIN_EXE_test-agent")).expect("cargo builds the test agent")
}

/// A node in the OUTBOUND-AGENT model: real sshd **plus** a non-root Agent that dials out
/// to `gateway_url` and splices to this container's own `127.0.0.1:22`. No port of this
/// container is ever dialled by the Gateway.
async fn start_agent_node(
    cp: &MockCp,
    host_key: &KeyMat,
    gateway_port: u16,
    node_name: &str,
    agent_id: &str,
) -> anyhow::Result<ContainerAsync<GenericImage>> {
    let identity = cp.issue_agent_identity(agent_id, node_name);
    let node = GenericImage::new(
        AGENT_NODE_IMAGE.split(':').next().unwrap(),
        AGENT_NODE_IMAGE.split(':').nth(1).unwrap(),
    )
    .with_wait_for(WaitFor::message_on_stderr("Server listening on"))
    .with_startup_timeout(Duration::from_secs(120))
    // The Agent dials OUT to the Gateway on the host; nothing ever dials in.
    .with_env_var("TRUSTED_USER_CA", cp.session_ca_public_line())
    .with_env_var(
        "AGENT_ENDPOINT",
        format!(
            "wss://{}:{gateway_port}",
            docker::container_reachable_host_ip()
        ),
    )
    .with_env_var("AGENT_SERVER_NAME", GW_NAME)
    .with_env_var("AGENT_NODE_NAME", node_name)
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

/// The ordinary agentless node (the S8 model), for the mixed-fleet run.
async fn start_direct_node(
    cp: &MockCp,
    host_key: &KeyMat,
) -> anyhow::Result<(ContainerAsync<GenericImage>, u16)> {
    let node = GenericImage::new(
        NODE_IMAGE.split(':').next().unwrap(),
        NODE_IMAGE.split(':').nth(1).unwrap(),
    )
    .with_wait_for(WaitFor::message_on_stderr("Server listening on"))
    .with_startup_timeout(Duration::from_secs(120))
    .with_env_var("TRUSTED_USER_CA", cp.session_ca_public_line())
    .with_copy_to(
        CopyTargetOptions::new("/etc/ssh/ssh_host_ed25519_key").with_mode(0o600),
        host_key.private_openssh.clone().into_bytes(),
    )
    .with_copy_to(
        CopyTargetOptions::new("/etc/ssh/ssh_host_ed25519_key.pub").with_mode(0o644),
        host_key.public_line.clone().into_bytes(),
    )
    .start()
    .await?;
    let port = node.get_host_port_ipv4(22).await?;
    Ok((node, port))
}

/// The whole Gateway: the agent WSS transport (bound first, so the node knows its port),
/// the per-node dispatching connector, and the outer SSH leg.
struct Gateway {
    ssh_port: u16,
    agent_port: u16,
    registry: Arc<AgentRegistry>,
    _shutdown: tokio::sync::watch::Sender<bool>,
}

async fn start_gateway(cp: &MockCp, recorder: RecorderChoice) -> anyhow::Result<Gateway> {
    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);

    // Bind the agent transport on 0.0.0.0 so the node container can reach it through the
    // Docker host-gateway, and learn the port before the nodes start.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    let agent_port = listener.local_addr()?.port();
    drop(listener);

    let config = Arc::new(gw_config(agent_port, recorder_config(&recorder)));
    let (deps, cred) = support::outer_leg_deps_named(
        cp,
        config.clone(),
        Arc::new(AgentlessDial::new(Duration::from_secs(4))),
        recorder,
        GW_NAME,
    )
    .await;

    let registry = Arc::new(AgentRegistry::new(16));
    let pending = Arc::new(PendingDialBacks::default());
    let signer = Arc::new(DialBackSigner::generate());

    let transport = server::bind(
        server::AgentTransportDeps {
            cpauth: deps.cpauth.clone(),
            gateway_id: cred.gateway_id.clone(),
            gateway_name: GW_NAME.to_string(),
            registry: registry.clone(),
            pending: pending.clone(),
            signer: signer.clone(),
            lock_set: deps.lock_set.clone(),
            peer_relay: None,
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

    // Part E: per-node selection. The SAME Gateway serves an agentless node by dialling it
    // and an agent node by signalling its Agent — the choice is the CP's, per node.
    let agent_dial = Arc::new(gateway_core::agent::dial::AgentDial::new(
        registry.clone(),
        pending,
        signer,
        deps.lock_set.clone(),
        cred.gateway_id.clone(),
        format!(
            "wss://{}:{agent_port}",
            docker::container_reachable_host_ip()
        ),
        config.agent.dial_back_token_ttl_secs,
        Duration::from_secs(config.agent.dial_back_timeout_secs),
    ));
    let deps = ssh::handler::HandlerDeps {
        connector: Arc::new(DispatchConnector::new(
            Arc::new(AgentlessDial::new(Duration::from_secs(4))),
            Some(agent_dial as Arc<dyn NodeConnector>),
        )),
        ..deps
    };

    let server = ssh::bind(config, deps).await?;
    let ssh_port = server.local_addr().port();
    let mut sd = sd_rx;
    tokio::spawn(server.run(async move {
        let _ = sd.wait_for(|v| *v).await;
    }));

    Ok(Gateway {
        ssh_port,
        agent_port,
        registry,
        _shutdown: sd_tx,
    })
}

fn recorder_config(choice: &RecorderChoice) -> RecorderConfig {
    match choice {
        // The E2E uploads to a plain-http MinIO (prod defaults to require_https).
        RecorderChoice::Real => RecorderConfig {
            require_https: false,
            ..Default::default()
        },
        RecorderChoice::Null => RecorderConfig::default(),
    }
}

fn gw_config(agent_port: u16, recorder: RecorderConfig) -> SshServerConfig {
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
            handshake_timeout_secs: 10,
            ..Default::default()
        },
        recorder,
        ..Default::default()
    }
}

/// Wait for the node's Agent to dial out and register. On failure, surface the Agent's own
/// log from inside the container — otherwise the only symptom is a silent timeout.
async fn await_agent(gw: &Gateway, node: &ContainerAsync<GenericImage>, node_name: &str) {
    for _ in 0..240 {
        if gw.registry.lookup(node_name).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let (_c, log, _e) = ssh_exec(
        node,
        vec!["sh".into(), "-c".into(), "cat /agent/agent.log".into()],
    )
    .await;
    panic!("the node's agent never registered its control channel; agent log:\n{log}");
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
    let mut res = container.exec(ExecCommand::new(args)).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

fn ssh_cmd(port: u16, extra: &[&str], target: &str, command: &str) -> Vec<String> {
    let mut a = vec![
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
    ];
    a.extend(extra.iter().map(|s| s.to_string()));
    a.push(format!("{target}@127.0.0.1"));
    if !command.is_empty() {
        a.push(command.into());
    }
    a
}

/// The node's own `sshd` log — the tamper-independent second trail (FR-AUD-4, §12.2).
async fn node_sshd_log(node: &ContainerAsync<GenericImage>) -> String {
    String::from_utf8_lossy(&node.stderr_to_vec().await.unwrap()).into_owned()
}

// ── The headline: a real SSH session over the agent path, in a mixed fleet ──────

#[tokio::test]
async fn ssh_runs_on_a_real_node_through_the_agent_path_in_a_mixed_fleet() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let agent_host_key = gen_key(Algorithm::Ed25519);
    let direct_host_key = gen_key(Algorithm::Ed25519);

    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", AGENT_NODE, "deploy");
    cp.allow("alice", DIRECT_NODE, "deploy");
    for node in [AGENT_NODE, DIRECT_NODE] {
        cp.set_capabilities(node, &[Capability::Shell, Capability::Exec]);
    }

    let gw = start_gateway(&cp, RecorderChoice::Null).await?;

    // The agent node: the CP declares OUTBOUND_AGENT and gives NO dial address. The
    // Gateway structurally cannot dial it — it can only signal its Agent.
    let agent_node =
        start_agent_node(&cp, &agent_host_key, gw.agent_port, AGENT_NODE, AGENT_ID).await?;
    cp.set_agent_node_connection(
        AGENT_NODE,
        AGENT_NODE,
        cp.pinned_verification(agent_host_key.public_wire.clone()),
    );

    // The agentless node, in the same fleet, on the same Gateway (FR-CONN-3).
    let (direct_node, direct_port) = start_direct_node(&cp, &direct_host_key).await?;
    cp.set_node_connection(
        DIRECT_NODE,
        &format!("127.0.0.1:{direct_port}"),
        cp.pinned_verification(direct_host_key.public_wire.clone()),
    );

    await_agent(&gw, &agent_node, AGENT_NODE).await;
    let client = client_container(&pin).await;

    // (1) THE AGENT PATH: the command runs on the node and its output comes back.
    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(
            gw.ssh_port,
            &[],
            &format!("deploy%{AGENT_NODE}"),
            "echo AGENT_PATH_OK; hostname",
        ),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "the agent-path session must succeed; stderr={stderr}"
    );
    assert!(
        stdout.contains("AGENT_PATH_OK"),
        "node output must return over the splice; stdout={stdout:?}"
    );

    // (2) An interactive PTY works over the splice too.
    let (code, stdout, _e) = ssh_exec(
        &client,
        ssh_cmd(
            gw.ssh_port,
            &["-tt"],
            &format!("deploy%{AGENT_NODE}"),
            "echo PTY_$(id -un)",
        ),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "an interactive PTY must work over the splice"
    );
    assert!(
        stdout.contains("PTY_deploy"),
        "the PTY session runs as the inner-cert principal; stdout={stdout:?}"
    );

    // (3) MIXED FLEET: the agentless node still works, on the same Gateway, in the same
    // run — the connector is chosen per node.
    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(
            gw.ssh_port,
            &[],
            &format!("deploy%{DIRECT_NODE}"),
            "echo AGENTLESS_OK",
        ),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "the agentless node must still work; stderr={stderr}"
    );
    assert!(stdout.contains("AGENTLESS_OK"));

    // (4) FR-AUD-4 — the node-local second trail. The Gateway's inner certificate carries
    // key_id = session_id + principal, and the node's own sshd (LogLevel VERBOSE) logs it
    // on every accepted certificate. The two trails cross-correlate on the session id with
    // NO trust in the Agent, which is what makes the second trail independent.
    let key_ids = cp.signed_key_ids();
    assert!(!key_ids.is_empty(), "the CP signed inner certificates");
    let log = node_sshd_log(&agent_node).await;
    let correlated = key_ids.iter().any(|k| log.contains(k.as_str()));
    assert!(
        correlated,
        "the node's sshd log must record the inner cert key-id ({key_ids:?})"
    );
    assert!(
        log.contains("Accepted publickey for deploy"),
        "the node's own log records the session; log tail:\n{}",
        log.chars().rev().take(2000).collect::<String>()
    );

    // (5) The Agent runs NON-ROOT (FR-CONN-6): it cannot read the node's host key, so
    // spoofing this node's identity needs node-root compromise.
    let (code, whoami, _e) = ssh_exec(
        &agent_node,
        vec![
            "sh".into(),
            "-c".into(),
            "ps -o user= -C test-agent | head -1".into(),
        ],
    )
    .await;
    assert_eq!(code, Some(0));
    assert_eq!(
        whoami.trim(),
        "deploy",
        "the Agent must not run as root (FR-CONN-6)"
    );

    drop(direct_node);
    drop(agent_node);
    Ok(())
}

// ── Part F: no-TOFU host verification holds over the splice ────────────────────

#[tokio::test]
async fn an_untrusted_node_host_key_aborts_over_the_agent_path() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let real_host_key = gen_key(Algorithm::Ed25519);
    let impostor = gen_key(Algorithm::Ed25519);

    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", AGENT_NODE, "deploy");

    let gw = start_gateway(&cp, RecorderChoice::Null).await?;
    let agent_node =
        start_agent_node(&cp, &real_host_key, gw.agent_port, AGENT_NODE, AGENT_ID).await?;

    // The CP pins a DIFFERENT host key than the node presents. The splice is carriage —
    // it changes nothing about who the Gateway will trust at the other end.
    cp.set_agent_node_connection(
        AGENT_NODE,
        AGENT_NODE,
        cp.pinned_verification(impostor.public_wire.clone()),
    );

    await_agent(&gw, &agent_node, AGENT_NODE).await;
    let client = client_container(&pin).await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(
            gw.ssh_port,
            &[],
            &format!("deploy%{AGENT_NODE}"),
            "echo SHOULD_NOT_RUN",
        ),
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "an untrusted host key must abort even over the agent path (never TOFU)"
    );
    assert!(
        !stdout.contains("SHOULD_NOT_RUN"),
        "the command must never reach the node"
    );
    assert!(
        stderr.contains("offline or unavailable"),
        "the user sees the generic §7.1 outcome; stderr={stderr:?}"
    );

    drop(agent_node);
    Ok(())
}

// ── A node whose Agent is not connected is simply offline ──────────────────────

#[tokio::test]
async fn a_node_whose_agent_is_disconnected_is_offline() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);

    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", AGENT_NODE, "deploy");

    let gw = start_gateway(&cp, RecorderChoice::Null).await?;
    // The node is declared agent-connected, but no Agent ever registers (the container is
    // never started). Post-authorization, the user gets the node-offline outcome.
    cp.set_agent_node_connection(
        AGENT_NODE,
        AGENT_NODE,
        cp.pinned_verification(host_key.public_wire.clone()),
    );

    let client = client_container(&pin).await;
    let (code, _stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw.ssh_port, &[], &format!("deploy%{AGENT_NODE}"), "true"),
    )
    .await;
    assert_ne!(code, Some(0), "a node with no Agent must fail closed");
    assert!(
        stderr.contains("offline or unavailable"),
        "§7.1 / FR-SESS-5 node-offline; stderr={stderr:?}"
    );
    Ok(())
}

// ── The S9 recorder is unchanged: recording still works over the agent path ────

#[tokio::test]
async fn a_session_over_the_agent_path_is_still_recorded() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);

    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", AGENT_NODE, "deploy");
    cp.set_capabilities(AGENT_NODE, &[Capability::Shell, Capability::Exec]);

    // The customer holds the key: the platform seals to the public half and cannot read
    // the recording back (S9). We keep the private half only to prove that.
    let customer = p256::SecretKey::random(&mut OsRng);
    let customer_pub = customer
        .public_key()
        .to_public_key_der()?
        .as_bytes()
        .to_vec();
    cp.set_customer_key(
        "cust-1",
        customer_pub,
        KeySealAlgorithm::EciesP256HkdfSha256Aes256gcm,
    );

    let (_minio, s3) = docker::start_minio().await?;
    cp.set_s3_target(s3.clone());

    let gw = start_gateway(&cp, RecorderChoice::Real).await?;
    let agent_node = start_agent_node(&cp, &host_key, gw.agent_port, AGENT_NODE, AGENT_ID).await?;
    cp.set_agent_node_connection(
        AGENT_NODE,
        AGENT_NODE,
        cp.pinned_verification(host_key.public_wire.clone()),
    );

    await_agent(&gw, &agent_node, AGENT_NODE).await;
    let client = client_container(&pin).await;

    let marker = "RECORDED_OVER_AGENT";
    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(
            gw.ssh_port,
            &["-tt"],
            &format!("deploy%{AGENT_NODE}"),
            &format!("echo {marker}"),
        ),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "the recorded agent session must run; {stderr}"
    );
    assert!(stdout.contains(marker));

    // The recorder tap is above the connector seam, so it sees the same bytes it always
    // did: the recording is registered, uploaded to the WORM store, and finalized.
    let mut finalized = Vec::new();
    for _ in 0..120 {
        finalized = cp.finalized_recordings();
        if !finalized.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(finalized.len(), 1, "the agent-path session was recorded");
    let record = &finalized[0];
    assert_eq!(record.status, RecordingStatus::Finalized as i32);
    assert!(record.byte_len > 0);
    assert!(
        record.hash_chain_head.starts_with("sha256:"),
        "the hash chain is committed"
    );

    let object_key = cp
        .recorded_object_keys()
        .pop()
        .expect("an object key was issued");
    let (status, body) = docker::get_object(&s3, &object_key).await?;
    assert_eq!(status, 200, "the sealed recording is in the WORM store");
    assert!(body.starts_with(b"SLREC1"), "the sealed-object envelope");
    assert!(
        !String::from_utf8_lossy(&body).contains(marker),
        "the object is sealed: the session plaintext is NOT readable in it"
    );

    drop(agent_node);
    Ok(())
}
