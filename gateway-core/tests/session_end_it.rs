//! FR-SESS-3 Part E end-to-end (Session 25): the reliable session-end signal +
//! the exact-lease lifecycle, against a real Debian 13 OpenSSH node and a stock
//! OpenSSH client in containers (never host ssh) with the in-process mock CP.
//!
//! Every teardown path must deliver EXACTLY ONE `NotifySessionEnd` with the
//! right reason — including the degraded paths where no recording exists (every
//! scenario here runs the Null recorder, so `FinalizeRecording` never fires and
//! only the new lifecycle signal can release the lease):
//!
//! - normal close → CLOSED, and the lease is released promptly (not at grant-TTL);
//! - authorize-then-abort (the node dial fails after ALLOW) → ERROR;
//! - HardKill mid-session expiry → EXPIRED;
//! - a pushed Lock → LOCKED.
//!
//! Exact-lease, no-under-count half: a RunToTtl session outliving `grant_expiry`
//! keeps re-stamping its lease via `ExtendSessionLease` (server-authoritative
//! window), and an extension failure never affects the session (accounting, not
//! authorization).

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

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient:s25sess3";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode:s25sess3";
const NODE_ID: &str = "node-sess3";
/// Authorized in inventory, but its dial address is a closed port — the
/// authorize-then-abort path (ALLOW taken a lease; the session never bridges).
const DEAD_NODE_ID: &str = "node-sess3-dead";

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

fn gw_config(mode: MidSessionExpiryMode) -> SshServerConfig {
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
    target: &str,
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
        target.to_string(),
        command.to_string(),
    ];
    let mut res = client.exec(ExecCommand::new(args)).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

/// The session-end signal is spawned off the Drop path; poll until it lands.
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
async fn session_end_signal_on_every_teardown_path_and_exact_leases() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key();
    let host_key = gen_key();
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", NODE_ID, "deploy");
    cp.allow("alice", DEAD_NODE_ID, "deploy");
    let (node, node_port) = start_node(&cp, &host_key).await?;
    let (_l, cert_wire) = cp.sign_host_cert(&host_key.public_wire, &[NODE_ID], 3600);
    let trust = cp.host_ca_verification(cert_wire, &[NODE_ID]);
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);
    // A port that was bound and released: the dead node's dial is refused AFTER
    // the ALLOW (and its lease) — the authorize-then-abort degraded path.
    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?.port()
    };
    cp.set_node_connection(
        DEAD_NODE_ID,
        &format!("127.0.0.1:{dead_port}"),
        cp.pinned_verification(host_key.public_wire.clone()),
    );
    let client = client_container(&pin).await;
    let live = format!("deploy%{NODE_ID}@127.0.0.1");

    // ── 1. Normal close, Null recorder (degraded: FinalizeRecording never fires):
    //       exactly the path that used to leak the lease until grant-TTL. ──
    let (gw, sd) = start_gateway(&cp, Arc::new(gw_config(MidSessionExpiryMode::RunToTtl))).await;
    let (code, stdout, stderr) = ssh_run(&client, gw, &live, "echo HELLO_CLOSE").await;
    assert_eq!(code, Some(0), "normal close must succeed; stderr={stderr}");
    assert!(stdout.contains("HELLO_CLOSE"));
    let sid_close = cp.last_authorize_request().unwrap().session_id;
    let n = wait_for_end(&cp, &sid_close).await;
    assert_eq!(
        n.reason,
        SessionEndReason::Closed as i32,
        "an orderly close reports CLOSED"
    );
    assert_eq!(
        cp.lease_released(&sid_close),
        Some(true),
        "the unrecorded session must free its slot promptly, not at grant-TTL"
    );

    // ── 2. Authorize-then-abort: ALLOW (lease taken) but the node dial fails —
    //       no channel ever bridges, yet the signal still fires. ──
    let (code, _stdout, stderr) = ssh_run(
        &client,
        gw,
        &format!("deploy%{DEAD_NODE_ID}@127.0.0.1"),
        "echo NEVER",
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "the dead node must fail the session; stderr={stderr}"
    );
    let sid_abort = cp.last_authorize_request().unwrap().session_id;
    assert_ne!(sid_abort, sid_close);
    let n = wait_for_end(&cp, &sid_abort).await;
    assert_eq!(
        n.reason,
        SessionEndReason::Error as i32,
        "an aborted (never-bridged) session reports ERROR"
    );
    assert_eq!(cp.lease_released(&sid_abort), Some(true));
    drop(sd);

    // ── 3. HardKill mid-session expiry → EXPIRED. ──
    let (gw, sd) = start_gateway(&cp, Arc::new(gw_config(MidSessionExpiryMode::HardKill))).await;
    cp.set_grant_expiry(now_epoch() + 6);
    let (code, stdout, _stderr) = ssh_run(
        &client,
        gw,
        &live,
        "sh -c 'echo UP; sleep 60; echo DONE_HK'",
    )
    .await;
    assert_ne!(code, Some(0), "hard_kill must tear the session down");
    assert!(stdout.contains("UP") && !stdout.contains("DONE_HK"));
    let sid_exp = cp.last_authorize_request().unwrap().session_id;
    let n = wait_for_end(&cp, &sid_exp).await;
    assert_eq!(
        n.reason,
        SessionEndReason::Expired as i32,
        "a grant-expiry teardown reports EXPIRED"
    );
    assert_eq!(cp.lease_released(&sid_exp), Some(true));
    drop(sd);

    // ── 4. A pushed Lock → LOCKED (Lock supremacy is untouched by Session 25). ──
    let (gw, sd) = start_gateway(&cp, Arc::new(gw_config(MidSessionExpiryMode::RunToTtl))).await;
    cp.set_grant_expiry(now_epoch() + 3600);
    cp.push_lock_after_delay(
        gateway_core::pb::Lock {
            lock_id: "lock-sess3".into(),
            target: Some(gateway_core::pb::LockTarget {
                node_ids: vec![NODE_ID.to_string()],
                ..Default::default()
            }),
            reason: "incident".into(),
            ..Default::default()
        },
        Duration::from_secs(3),
    );
    let (code, stdout, _stderr) = ssh_run(
        &client,
        gw,
        &live,
        "sh -c 'echo UP; sleep 30; echo DONE_LOCK'",
    )
    .await;
    assert_ne!(code, Some(0), "a Lock must tear the session down");
    assert!(stdout.contains("UP") && !stdout.contains("DONE_LOCK"));
    let sid_lock = cp.last_authorize_request().unwrap().session_id;
    let n = wait_for_end(&cp, &sid_lock).await;
    assert_eq!(
        n.reason,
        SessionEndReason::Locked as i32,
        "a lock-driven teardown reports LOCKED"
    );
    assert_eq!(cp.lease_released(&sid_lock), Some(true));
    cp.remove_lock("lock-sess3");
    drop(sd);

    // ── 5. RunToTtl outliving grant_expiry: the slot stays occupied (the lease is
    //       re-stamped ahead of expiry, cadence driven by the SERVER-returned
    //       window), then released at the real end. ──
    let (gw, sd) = start_gateway(&cp, Arc::new(gw_config(MidSessionExpiryMode::RunToTtl))).await;
    cp.set_extend_window(6);
    cp.set_grant_expiry(now_epoch() + 6);
    let before = cp.lease_extension_count();
    let (code, stdout, stderr) = ssh_run(
        &client,
        gw,
        &live,
        "sh -c 'echo UP; sleep 14; echo DONE_TTL'",
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "run_to_ttl runs past grant_expiry to natural close; stderr={stderr}"
    );
    assert!(stdout.contains("DONE_TTL"));
    let sid_ttl = cp.last_authorize_request().unwrap().session_id;
    assert!(
        cp.lease_extension_count() >= before + 2,
        "a session outliving grant_expiry must keep re-stamping its lease (got {} new extensions)",
        cp.lease_extension_count() - before
    );
    let n = wait_for_end(&cp, &sid_ttl).await;
    assert_eq!(n.reason, SessionEndReason::Closed as i32);
    assert_eq!(
        cp.lease_released(&sid_ttl),
        Some(true),
        "no under-count: the slot is held until the session actually ends, then released"
    );

    // ── 6. Extension failure is benign: accounting, never authorization. ──
    cp.set_extend_unavailable(true);
    cp.set_grant_expiry(now_epoch() + 5);
    let before = cp.lease_extension_count();
    let (code, stdout, stderr) = ssh_run(
        &client,
        gw,
        &live,
        "sh -c 'echo UP; sleep 12; echo DONE_EFAIL'",
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "a failed lease extension must NEVER tear the session down; stderr={stderr}"
    );
    assert!(stdout.contains("DONE_EFAIL"));
    assert!(
        cp.lease_extension_count() > before,
        "the keeper must keep retrying through transient failures"
    );
    cp.set_extend_unavailable(false);
    let sid_efail = cp.last_authorize_request().unwrap().session_id;
    let n = wait_for_end(&cp, &sid_efail).await;
    assert_eq!(n.reason, SessionEndReason::Closed as i32);
    drop(sd);

    // ── Exactly-once-ish: one signal per session, never a double-send from a
    //    normal close racing the Drop teardown. ──
    tokio::time::sleep(Duration::from_secs(2)).await;
    let all = cp.session_end_notifications();
    for sid in [
        &sid_close, &sid_abort, &sid_exp, &sid_lock, &sid_ttl, &sid_efail,
    ] {
        assert_eq!(
            all.iter().filter(|n| n.session_id == **sid).count(),
            1,
            "exactly one NotifySessionEnd per session (session {sid})"
        );
    }

    drop(client);
    drop(node);
    Ok(())
}
