mod support;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gateway_core::config::{
    DeviceFlowConfig, InnerLegServerConfig, MidSessionExpiryMode, ReevalConfig, SshServerConfig,
};
use gateway_core::pb::{NotifySessionEndRequest, SessionEndReason};
use gateway_core::ssh;
use gateway_core::ssh::connector::AgentlessDial;
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use support::docker::build_image;
use support::{MockCp, RecorderChoice};
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient:test";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode:test";
const NODE_ID: &str = "node-idle";

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

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn build_images() -> anyhow::Result<()> {
    build_image("ssh-client", CLIENT_IMAGE).await?;
    build_image("sshd", NODE_IMAGE).await
}

async fn start_node(
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

async fn client_container(pin: &KeyMat) -> ContainerAsync<GenericImage> {
    GenericImage::new(
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
    .await
    .expect("start ssh-client container")
}

fn gw_config(max_idle_secs: u64, login_grace_secs: u64) -> SshServerConfig {
    SshServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        login_grace_secs,
        device_flow: DeviceFlowConfig {
            heartbeat_interval_secs: 1,
            poll_timeout_secs: login_grace_secs.saturating_sub(1).min(20),
        },
        inner: InnerLegServerConfig {
            connect_timeout_secs: 4,
            handshake_timeout_secs: 8,
            max_session_idle_secs: max_idle_secs,
            ..Default::default()
        },
        reeval: ReevalConfig {
            grant_expiry_skew_secs: 1,
            mid_session_expiry: MidSessionExpiryMode::RunToTtl,
            mid_session_grace_secs: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn start_gateway(
    cp: &MockCp,
    config: Arc<SshServerConfig>,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    let connector = Arc::new(AgentlessDial::new(Duration::from_secs(
        config.inner.connect_timeout_secs,
    )));
    let deps =
        support::outer_leg_deps_with(cp, config.clone(), connector, RecorderChoice::Null).await;
    let server = ssh::bind(config, deps).await.unwrap();
    let port = server.local_addr().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));
    (port, tx)
}

async fn ssh_run(
    client: &ContainerAsync<GenericImage>,
    port: u16,
    command: &str,
) -> (Option<i64>, String, String) {
    let args = vec![
        "ssh".to_string(),
        "-p".to_string(),
        port.to_string(),
        "-i".to_string(),
        "/root/pin_key".to_string(),
        "-o".to_string(),
        "IdentitiesOnly=yes".to_string(),
        "-o".to_string(),
        "PreferredAuthentications=publickey".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(),
        "ConnectTimeout=30".to_string(),
        format!("deploy%{NODE_ID}@127.0.0.1"),
        command.to_string(),
    ];
    let mut res = client.exec(ExecCommand::new(args)).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

async fn wait_for_end(cp: &MockCp, session_id: &str) -> NotifySessionEndRequest {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(n) = cp
            .session_end_notifications()
            .into_iter()
            .find(|n| n.session_id == session_id)
        {
            return n;
        }
        assert!(
            Instant::now() < deadline,
            "no NotifySessionEnd for session {session_id} within the deadline"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn per_identity_idle_timeout_tightens_and_never_loosens() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key();
    let host_key = gen_key();
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", NODE_ID, "deploy");
    let (node, node_port) = start_node(&cp, &host_key).await?;
    let (_l, cert_wire) = cp.sign_host_cert(&host_key.public_wire, &[NODE_ID], 3600);
    let trust = cp.host_ca_verification(cert_wire, &[NODE_ID]);
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);
    cp.set_grant_expiry(now_epoch() + 3600);
    let client = client_container(&pin).await;

    let (gw, sd) = start_gateway(&cp, Arc::new(gw_config(120, 60))).await;
    cp.set_idle_timeout(6);
    let started = Instant::now();
    let (code, stdout, _stderr) =
        ssh_run(&client, gw, "sh -c 'echo UP; sleep 40; echo DONE_TIGHT'").await;
    let elapsed = started.elapsed();
    assert_ne!(code, Some(0), "the idle session must be torn down");
    assert!(
        stdout.contains("UP"),
        "a LIVE teardown: the channel bridged and ran before going idle; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("DONE_TIGHT"),
        "the tightened idle bound must cut the idle session short; stdout={stdout:?}"
    );
    assert!(
        elapsed < Duration::from_secs(25),
        "teardown at the TIGHTENED bound (~6s idle), nowhere near the 120s static bound or the 40s sleep; elapsed={elapsed:?}"
    );
    let sid = cp.last_authorize_request().unwrap().session_id;
    let n = wait_for_end(&cp, &sid).await;
    assert_eq!(
        n.reason,
        SessionEndReason::IdleTimeout as i32,
        "the idle teardown reports IDLE_TIMEOUT"
    );
    assert_eq!(cp.lease_released(&sid), Some(true));

    let (code, stdout, stderr) = ssh_run(
        &client,
        gw,
        "sh -c 'for i in 1 2 3 4 5 6 7; do echo T$i; sleep 2; done; echo DONE_ACTIVE'",
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "a session with steady output is not idle and must complete; stderr={stderr}"
    );
    assert!(
        stdout.contains("DONE_ACTIVE"),
        "the ~14s active session outlives the 6s idle bound; stdout={stdout:?}"
    );
    let sid_active = cp.last_authorize_request().unwrap().session_id;
    let n = wait_for_end(&cp, &sid_active).await;
    assert_eq!(n.reason, SessionEndReason::Closed as i32);
    drop(sd);

    let (gw, sd) = start_gateway(&cp, Arc::new(gw_config(15, 15))).await;
    cp.set_idle_timeout(600);
    let started = Instant::now();
    let (code, stdout, _stderr) =
        ssh_run(&client, gw, "sh -c 'echo UP; sleep 60; echo DONE_LOOSE'").await;
    let elapsed = started.elapsed();
    assert_ne!(
        code,
        Some(0),
        "a loosening context value must NOT extend the static bound"
    );
    assert!(
        !stdout.contains("DONE_LOOSE"),
        "the static 15s bound still tears the idle session down; stdout={stdout:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(13),
        "the session lives to the STATIC bound (not the tightened 6s of the earlier scenario); elapsed={elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(45),
        "the 600s context value must not extend the 15s static bound; elapsed={elapsed:?}"
    );
    let sid_loose = cp.last_authorize_request().unwrap().session_id;
    let n = wait_for_end(&cp, &sid_loose).await;
    assert_eq!(n.reason, SessionEndReason::IdleTimeout as i32);
    drop(sd);

    drop(client);
    drop(node);
    Ok(())
}
