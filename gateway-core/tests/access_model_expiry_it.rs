//! FR-ACC-8 end-to-end: the three mid-session identity-expiry modes enforced by the
//! Gateway against a **real Debian 13 OpenSSH node** — never host ssh.
//!
//! The CP signs `grant_expiry` into the decision context; the Gateway enforces, per
//! access model, what happens to a LIVE session when that grant passes:
//!
//! - `run_to_ttl` — in-flight channels run to natural close (only NEW channels are
//!   refused after expiry).
//! - `hard_kill` — the live session is torn down at `grant_expiry`.
//! - `grace_then_kill` — torn down a grace window after `grant_expiry`.
//!
//! And, regardless of mode, a **Lock always tears the session down immediately**.
//!
//! One node + one client + one mock CP are reused across the four scenarios; each
//! scenario runs its own in-process Gateway (Null recorder — no MinIO needed) with
//! the mode under test. A small `grant_expiry_skew_secs` keeps the runs short.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gateway_core::config::{
    DeviceFlowConfig, InnerLegServerConfig, MidSessionExpiryMode, ReevalConfig, SshServerConfig,
};
use gateway_core::ssh;
use gateway_core::ssh::connector::AgentlessDial;
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use support::docker::build_image;
use support::{MockCp, RecorderChoice};
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient:s24acc8";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode:s24acc8";
const NODE_ID: &str = "node-acc8";

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

/// Gateway config for a scenario: the mode under test + a 1s expiry skew so a grant
/// set a few seconds out still lets the session START (skew refuses NEW channels
/// only once `now + skew >= grant_expiry`).
fn gw_config(mode: MidSessionExpiryMode, grace_secs: u64) -> SshServerConfig {
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
        reeval: ReevalConfig {
            grant_expiry_skew_secs: 1,
            mid_session_expiry: mode,
            mid_session_grace_secs: grace_secs,
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
        "deploy%node-acc8@127.0.0.1".to_string(),
        command.to_string(),
    ];
    let mut res = client.exec(ExecCommand::new(args)).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

#[tokio::test]
async fn mid_session_expiry_modes_and_lock_override() -> anyhow::Result<()> {
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
    let client = client_container(&pin).await;

    // grant_expiry is set AFTER the gateway is up (enroll + lock-feed sync are slow
    // on the 2-core box), right before the session, so a small skew margin can't
    // race the setup latency and expire the grant before the first channel opens.
    const EXP: i64 = 10; // seconds ahead — comfortably past connect, before the command ends

    // ── run_to_ttl: a command that runs PAST grant_expiry completes normally. ──
    let (gw, sd) = start_gateway(&cp, Arc::new(gw_config(MidSessionExpiryMode::RunToTtl, 0))).await;
    cp.set_grant_expiry(now_epoch() + EXP);
    let (code, stdout, stderr) =
        ssh_run(&client, gw, "sh -c 'echo UP; sleep 14; echo DONE_RUNTOTTL'").await;
    assert_eq!(
        code,
        Some(0),
        "run_to_ttl: in-flight channel runs to natural close; stderr={stderr}"
    );
    assert!(
        stdout.contains("DONE_RUNTOTTL"),
        "run_to_ttl must not tear the live session down at grant_expiry; stdout={stdout:?}"
    );
    drop(sd);

    // ── hard_kill: the same over-running command is CUT SHORT at grant_expiry. ──
    let (gw, sd) = start_gateway(&cp, Arc::new(gw_config(MidSessionExpiryMode::HardKill, 0))).await;
    cp.set_grant_expiry(now_epoch() + EXP);
    let started = Instant::now();
    let (code, stdout, _stderr) =
        ssh_run(&client, gw, "sh -c 'echo UP; sleep 60; echo DONE_HARDKILL'").await;
    let hard_elapsed = started.elapsed();
    assert_ne!(
        code,
        Some(0),
        "hard_kill must tear the live session down, not exit clean"
    );
    assert!(
        stdout.contains("UP"),
        "hard_kill must be a LIVE teardown: the channel opened and the shell ran (UP) BEFORE teardown, not a connect-time open-refusal; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("DONE_HARDKILL"),
        "hard_kill must cut the session short at grant_expiry; stdout={stdout:?}"
    );
    assert!(
        hard_elapsed < Duration::from_secs(18),
        "hard_kill teardown is prompt at grant_expiry (~{EXP}s), well before the grace window and the 60s sleep; elapsed={hard_elapsed:?}"
    );
    drop(sd);

    // ── grace_then_kill: torn down, but only AFTER the grace window (survives well
    //    past grant_expiry — distinguishing it from hard_kill's immediate teardown). ──
    let (gw, sd) = start_gateway(
        &cp,
        Arc::new(gw_config(MidSessionExpiryMode::GraceThenKill, 10)),
    )
    .await;
    cp.set_grant_expiry(now_epoch() + EXP);
    let started = Instant::now();
    let (code, stdout, _stderr) =
        ssh_run(&client, gw, "sh -c 'echo UP; sleep 90; echo DONE_GRACE'").await;
    let grace_elapsed = started.elapsed();
    assert_ne!(
        code,
        Some(0),
        "grace_then_kill must tear the live session down"
    );
    assert!(
        !stdout.contains("DONE_GRACE"),
        "grace_then_kill must cut the session short; stdout={stdout:?}"
    );
    assert!(grace_elapsed >= Duration::from_secs(15), "grace_then_kill must survive the grace window (grant_expiry ~{EXP}s + 10s grace) past hard_kill's ~{EXP}s teardown; elapsed={grace_elapsed:?}");
    drop(sd);

    // ── Lock overrides EVERY mode: with run_to_ttl (which never tears a live session
    //    down on expiry), a pushed Lock still tears it down immediately. ──
    let (gw, sd) = start_gateway(&cp, Arc::new(gw_config(MidSessionExpiryMode::RunToTtl, 0))).await;
    cp.set_grant_expiry(now_epoch() + 3600); // far out — expiry is NOT the cause here.
    cp.push_lock_after_delay(
        gateway_core::pb::Lock {
            lock_id: "lock-acc8".into(),
            target: Some(gateway_core::pb::LockTarget {
                node_ids: vec![NODE_ID.to_string()],
                ..Default::default()
            }),
            reason: "incident".into(),
            ..Default::default()
        },
        Duration::from_secs(3),
    );
    let started = Instant::now();
    let (code, stdout, _stderr) =
        ssh_run(&client, gw, "sh -c 'echo UP; sleep 30; echo DONE_LOCK'").await;
    let lock_elapsed = started.elapsed();
    assert_ne!(
        code,
        Some(0),
        "a Lock must tear the session down even in run_to_ttl mode"
    );
    assert!(
        stdout.contains("UP"),
        "the Lock teardown must be a LIVE teardown: the channel opened and the shell ran (UP) before the lock, not an open-refusal; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("DONE_LOCK"),
        "a Lock overrides run_to_ttl and tears the live session down; stdout={stdout:?}"
    );
    assert!(
        lock_elapsed < Duration::from_secs(20),
        "a Lock teardown is immediate, not run-to-ttl; elapsed={lock_elapsed:?}"
    );
    cp.remove_lock("lock-acc8");
    drop(sd);

    drop(client);
    drop(node);
    Ok(())
}
