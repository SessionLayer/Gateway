//! NFR-1 end-to-end: **the FLEET survives losing one instance mid-session.** Two
//! real `ssh::bind` gateways share one mock CP and one real Debian node. GW-1 is the
//! survivor; GW-2 is a healthy peer that also OWNS a node via presence. Never host ssh.
//!
//! Honest physical caveat (verbatim, per the reliability framing): an in-flight
//! session whose bytes physically transit the killed instance terminates fail-closed
//! — a proxy cannot resurrect in-flight bytes through a dead box, and this platform
//! has no cross-gateway session resumption. So NFR-1 ("losing one instance MUST NOT
//! drop existing sessions") is proven at the FLEET level, which is what it means:
//!   (A) a live session ANCHORED ON THE SURVIVING instance keeps passing I/O AFTER
//!       the peer is killed (write-a-command / read-the-echo, post-kill), unaffected;
//!   (B) the killed instance's node OWNERSHIP is RELEASED (presence) so a surviving
//!       gateway takes it over — failover, not a stuck lock;
//!   (C) NEW sessions still establish while any instance is healthy.

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway_core::agent::registry::AgentRegistry;
use gateway_core::config::{DeviceFlowConfig, InnerLegServerConfig, SshServerConfig};
use gateway_core::cpauth::{CpAuthClient, CpChannelFactory};
use gateway_core::ha::presence::{CpPresenceStore, HeartbeatLoop, OwnerCache, PresenceStore};
use gateway_core::identity;
use gateway_core::ssh;
use gateway_core::ssh::connector::AgentlessDial;
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use support::docker::build_image;
use support::{MockCp, RecorderChoice};
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient:s24nfr1";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode:s24nfr1";
const NODE_A: &str = "node-nfr1"; // the agentless node GW-1 serves the live session on
const NODE_B: &str = "owned-nfr1"; // the node GW-2 owns via presence (virtual)
const TARGET: &str = "deploy%node-nfr1@127.0.0.1";
const GW2_NAME: &str = "gw-b-nfr1";
const SOCK: &str = "/root/nfr1.sock";

struct KeyMat {
    private_openssh: String,
    public_line: String,
    public_wire: Vec<u8>,
    fingerprint: String,
}

fn gen_key() -> KeyMat {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    KeyMat {
        private_openssh: key.to_openssh(LineEnding::LF).unwrap().to_string(),
        public_line: key.public_key().to_openssh().unwrap(),
        public_wire: key.public_key().to_bytes().unwrap(),
        fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
    }
}

async fn build_images() -> anyhow::Result<()> {
    build_image("ssh-client", CLIENT_IMAGE).await?;
    build_image("sshd", NODE_IMAGE).await
}

fn gw_config() -> SshServerConfig {
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
        ..Default::default()
    }
}

struct Gw {
    port: u16,
    task: tokio::task::JoinHandle<()>,
    cpauth: Arc<CpAuthClient>,
}

async fn start_gateway(cp: &MockCp, name: &str) -> Gw {
    let config = Arc::new(gw_config());
    let connector = Arc::new(AgentlessDial::new(Duration::from_secs(4)));
    let (deps, _cred) =
        support::outer_leg_deps_named(cp, config.clone(), connector, RecorderChoice::Null, name)
            .await;
    let cpauth = deps.cpauth.clone();
    let server = ssh::bind(config, deps).await.unwrap();
    let port = server.local_addr().port();
    let task = tokio::spawn(async move {
        server.run(std::future::pending::<()>()).await;
    });
    Gw { port, task, cpauth }
}

async fn enroll(cp: &MockCp, name: &str) -> identity::Credential {
    let dir = tempfile::tempdir().unwrap();
    let store = identity::IdentityStore::open(dir.path()).unwrap();
    std::mem::forget(dir);
    let params = cp.channel_params(Duration::from_secs(5), Duration::from_secs(10));
    identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &cp.mint_enrollment_token(),
        name,
    )
    .await
    .unwrap()
}

fn cpauth_for(cp: &MockCp, cred: &identity::Credential) -> Arc<CpAuthClient> {
    let params = cp.channel_params(Duration::from_secs(5), Duration::from_secs(10));
    let factory = Arc::new(CpChannelFactory::fixed(
        params,
        cred.identity.clone(),
        cred.ca_chain_der.clone(),
    ));
    Arc::new(CpAuthClient::new(factory, Duration::from_secs(10)))
}

async fn exec(
    client: &ContainerAsync<GenericImage>,
    args: &[&str],
) -> (Option<i64>, String, String) {
    exec_owned(client, args.iter().map(|s| s.to_string()).collect()).await
}

async fn exec_owned(
    client: &ContainerAsync<GenericImage>,
    args: Vec<String>,
) -> (Option<i64>, String, String) {
    let mut res = client.exec(ExecCommand::new(args)).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

/// A publickey ssh invocation to `port` running `command` on the agentless node.
fn ssh_pk(port: u16, command: &str) -> Vec<String> {
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
        TARGET.into(),
        command.into(),
    ]
}

#[tokio::test]
async fn losing_one_instance_the_fleet_survives_io_ownership_failover_and_new_sessions(
) -> anyhow::Result<()> {
    build_images().await?;
    // Short presence staleness so the ownership failover is observable quickly.
    let cp = MockCp::builder()
        .presence_staleness(Duration::from_secs(2))
        .start()
        .await;
    let pin = gen_key();
    let host_key = gen_key();
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", NODE_A, "deploy");

    // Real agentless node reachable by BOTH gateways (the live-session anchor).
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
    let node_port = node.get_host_port_ipv4(22).await?;
    let (_l, cert_wire) = cp.sign_host_cert(&host_key.public_wire, &[NODE_A], 3600);
    let trust = cp.host_ca_verification(cert_wire, &[NODE_A]);
    cp.set_node_connection(NODE_A, &format!("127.0.0.1:{node_port}"), trust);

    // GW-1 (survivor) + GW-2 (a healthy peer, killed mid-session).
    let gw1 = start_gateway(&cp, "gw-a-nfr1").await;
    let gw2 = start_gateway(&cp, GW2_NAME).await;

    // GW-2 OWNS node-B via a presence heartbeat loop (a real HA participant).
    let gw2_registry = Arc::new(AgentRegistry::new(16));
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    std::mem::forget(rx);
    std::mem::forget(gw2_registry.register(NODE_B, "agent-b", tx).unwrap());
    let (_gw2_hb_stop, gw2_hb_rx) = tokio::sync::watch::channel(false);
    let gw2_hb = HeartbeatLoop::new(
        Arc::new(CpPresenceStore::new(gw2.cpauth.clone())),
        gw2_registry,
        Arc::new(OwnerCache::new(Duration::from_secs(30))),
        "127.0.0.1:9444".to_string(),
        Duration::from_millis(300),
    )
    .spawn(gw2_hb_rx);
    // Wait for GW-2 to claim ownership of node-B.
    for _ in 0..80 {
        if cp.presence_owner(NODE_B).as_deref() == Some(GW2_NAME) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        cp.presence_owner(NODE_B).as_deref(),
        Some(GW2_NAME),
        "GW-2 owns node-B"
    );

    let client = GenericImage::new(
        CLIENT_IMAGE.split(':').next().unwrap(),
        CLIENT_IMAGE.split(':').nth(1).unwrap(),
    )
    .with_network("host")
    .with_startup_timeout(Duration::from_secs(60))
    .with_copy_to(
        CopyTargetOptions::new("/root/pin_key").with_mode(0o600),
        pin.private_openssh.clone().into_bytes(),
    )
    .start()
    .await?;

    // GW-2 is a genuine, healthy serving instance (prove it before killing it).
    let (code, stdout, stderr) = exec_owned(&client, ssh_pk(gw2.port, "echo GW2_HEALTHY")).await;
    assert_eq!(
        code,
        Some(0),
        "GW-2 is a healthy serving instance; stderr={stderr}"
    );
    assert!(stdout.contains("GW2_HEALTHY"));

    // A LIVE session anchored on GW-1: a ControlMaster (one auth, persistent, actively
    // passing I/O). Command #1 flows BEFORE the kill.
    let opts: Vec<String> = vec![
        "-p".into(),
        gw1.port.to_string(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
    ];
    let mut master: Vec<&str> = vec!["ssh", "-M", "-N", "-f", "-S", SOCK];
    master.extend(opts.iter().map(String::as_str));
    master.extend([
        "-i",
        "/root/pin_key",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "BatchMode=yes",
        "-o",
        "ControlMaster=yes",
        TARGET,
    ]);
    let (code, _o, stderr) = exec(&client, &master).await;
    assert_eq!(
        code,
        Some(0),
        "GW-1 ControlMaster establishes; stderr={stderr}"
    );
    let (code, stdout, stderr) = exec(
        &client,
        &["ssh", "-S", SOCK, TARGET, "echo", "IO_BEFORE_KILL"],
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "I/O flows on GW-1's live session before the kill; stderr={stderr}"
    );
    assert!(stdout.contains("IO_BEFORE_KILL"));

    // HARD-KILL GW-2 (crash): abort its SSH accept loop AND its presence heartbeat.
    gw2.task.abort();
    gw2_hb.abort();

    // (A) GW-1's live session KEEPS PASSING I/O after the peer died — a NEW command
    // over the SAME master runs on the node (write→echo, post-kill). Unaffected.
    let (code, stdout, stderr) = exec(
        &client,
        &["ssh", "-S", SOCK, TARGET, "echo", "IO_AFTER_KILL"],
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "GW-1's live session must keep passing I/O after GW-2's death; stderr={stderr}"
    );
    assert!(
        stdout.contains("IO_AFTER_KILL"),
        "post-kill I/O on the surviving instance; stdout={stdout:?}"
    );
    let (code, _o, _e) = exec(&client, &["ssh", "-S", SOCK, "-O", "check", TARGET]).await;
    assert_eq!(code, Some(0), "GW-1's master lives on past the peer kill");

    // (B) GW-2's node OWNERSHIP is RELEASED so a surviving gateway TAKES OVER — a
    // standby heartbeat reclaims node-B once GW-2 goes stale (failover, not a stuck row).
    let standby = enroll(&cp, "gw-standby-nfr1").await;
    let standby_store = CpPresenceStore::new(cpauth_for(&cp, &standby));
    let mut failed_over = false;
    for _ in 0..80 {
        let _ = standby_store.heartbeat(NODE_B, "127.0.0.1:9445").await;
        if cp.presence_owner(NODE_B).as_deref() == Some("gw-standby-nfr1") {
            failed_over = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(
        failed_over,
        "a surviving gateway must take over the killed instance's node (ownership released)"
    );

    // (C) NEW sessions still establish through GW-1 while it is healthy.
    let (code, stdout, stderr) = exec_owned(&client, ssh_pk(gw1.port, "echo NEW_AFTER_KILL")).await;
    assert_eq!(
        code,
        Some(0),
        "a new session must still establish after the instance loss; stderr={stderr}"
    );
    assert!(
        stdout.contains("NEW_AFTER_KILL"),
        "new sessions are not blocked while an instance is healthy; stdout={stdout:?}"
    );

    drop(client);
    drop(node);
    Ok(())
}
