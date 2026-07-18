//! FR-SESS-4 end-to-end: a real OpenSSH **ControlMaster** multiplexed connection
//! against a real Debian 13 node — one auth, several session channels — proving the
//! Gateway's per-channel gating and mid-connection lock teardown of a multiplexed
//! session. Never host ssh (the ssh/sftp client runs in a container).
//!
//! The master (`ssh -M -N`) authenticates ONCE; multiplexed clients then open
//! channels over it with NO re-auth. Capabilities are decided once at connect and
//! gated PER channel-open (FR-CHAN-2): an exec channel is admitted, an sftp channel
//! (capability withheld) is refused on the SAME connection. A Lock pushed while the
//! master is live tears the whole multiplexed session down.

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway_core::config::{DeviceFlowConfig, InnerLegServerConfig, SshServerConfig};
use gateway_core::pb::Capability;
use gateway_core::ssh;
use gateway_core::ssh::connector::AgentlessDial;
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use support::docker::build_image;
use support::{MockCp, RecorderChoice};
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient:s24cm";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode:s24cm";
const NODE_ID: &str = "node-cm";
const TARGET: &str = "deploy%node-cm@127.0.0.1";
const SOCK: &str = "/root/cm.sock";

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

async fn exec(
    client: &ContainerAsync<GenericImage>,
    args: &[&str],
) -> (Option<i64>, String, String) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let mut res = client.exec(ExecCommand::new(args)).await.expect("exec");
    let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await.unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await.unwrap()).into_owned();
    let code = res.exit_code().await.unwrap();
    (code, stdout, stderr)
}

/// The shared ssh options every multiplexed invocation needs (the master carries
/// auth; the children reuse the control socket).
fn base_opts(port: u16) -> Vec<String> {
    vec![
        "-p".into(),
        port.to_string(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
    ]
}

#[tokio::test]
async fn controlmaster_multiplex_per_channel_gate_and_lock_teardown() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key();
    let host_key = gen_key();
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", NODE_ID, "deploy");
    // Grant shell+exec but WITHHOLD sftp — the per-channel gate must admit exec and
    // refuse the sftp subsystem on the SAME multiplexed connection.
    cp.set_capabilities(NODE_ID, &[Capability::Shell, Capability::Exec]);
    // decision_ttl=0 so each channel-open re-authorizes (FR-CHAN-2): the positive
    // control below (grant Sftp mid-connection → same-master sftp succeeds) needs the
    // fresh capability picked up on the next channel-open.
    cp.set_decision_ttl(0);

    // Real node trusting the session CA.
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
    let (_l, cert_wire) = cp.sign_host_cert(&host_key.public_wire, &[NODE_ID], 3600);
    let trust = cp.host_ca_verification(cert_wire, &[NODE_ID]);
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);

    let config = Arc::new(SshServerConfig {
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
    });
    let connector = Arc::new(AgentlessDial::new(Duration::from_secs(4)));
    let deps =
        support::outer_leg_deps_with(&cp, config.clone(), connector, RecorderChoice::Null).await;
    let server = ssh::bind(config, deps).await?;
    let port = server.local_addr().port();
    let (sd_tx, sd_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(server.run(async move {
        let _ = sd_rx.await;
    }));

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

    // (1) Establish the ControlMaster: ONE authentication, backgrounded, no channel
    // yet (`-N`). Everything after multiplexes over this socket with no re-auth.
    let opts = base_opts(port);
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
        "the ControlMaster must authenticate once and background; stderr={stderr}"
    );

    // Master is alive.
    let (code, _o, _e) = exec(&client, &["ssh", "-S", SOCK, "-O", "check", TARGET]).await;
    assert_eq!(code, Some(0), "the multiplex master must be running");

    // (2) Channel A — exec is GRANTED: multiplexes over the master (no re-auth) and
    // runs on the node.
    let (code, stdout, stderr) = exec(
        &client,
        &["ssh", "-S", SOCK, TARGET, "echo", "CH_A_EXEC_OK"],
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "exec channel over the master must run; stderr={stderr}"
    );
    assert!(
        stdout.contains("CH_A_EXEC_OK"),
        "exec channel output; stdout={stdout:?}"
    );

    // (3) Channel B — sftp is WITHHELD: a second channel on the SAME authenticated
    // master, gated independently, must be refused at the per-channel capability
    // gate — a MULTIPLEXED subsystem/channel refusal, NOT a fresh connect/auth
    // failure (which would evidence the multiplex didn't happen at all).
    let sftp_cmd = [
        "sftp",
        "-b",
        "/dev/null",
        "-o",
        &format!("ControlPath={SOCK}"),
        TARGET,
    ];
    let (code, _o, sftp_err) = exec(&client, &sftp_cmd).await;
    assert_ne!(
        code,
        Some(0),
        "the sftp channel is not granted and must be refused per-channel"
    );
    assert!(
        !sftp_err.contains("Permission denied") && !sftp_err.to_lowercase().contains("connection refused"),
        "sftp must be refused at the MULTIPLEXED channel gate, not by a fresh connect/auth (no Permission denied / Connection refused); stderr={sftp_err:?}"
    );
    assert!(
        sftp_err.contains("subsystem request failed")
            || sftp_err.contains("Connection closed")
            || sftp_err.to_lowercase().contains("access denied"),
        "sftp stderr must evidence a multiplexed subsystem/channel refusal; stderr={sftp_err:?}"
    );

    // (3b) POSITIVE control on the SAME authenticated master: grant Sftp; the next
    // sftp channel re-authorizes (decision_ttl=0) and SUCCEEDS — a positive+negative
    // pair on ONE auth nails per-channel gating (not a per-connection artifact).
    cp.set_capabilities(
        NODE_ID,
        &[Capability::Shell, Capability::Exec, Capability::Sftp],
    );
    let (code, _o, sftp_ok_err) = exec(&client, &sftp_cmd).await;
    assert_eq!(
        code,
        Some(0),
        "once Sftp is granted, the SAME-master sftp channel must SUCCEED; stderr={sftp_ok_err:?}"
    );

    // (4) A Lock pushed while the multiplexed session is LIVE tears the whole thing
    // down: the master connection drops, so a subsequent multiplexed op fails.
    cp.add_lock(gateway_core::pb::Lock {
        lock_id: "lock-cm".into(),
        target: Some(gateway_core::pb::LockTarget {
            node_ids: vec![NODE_ID.to_string()],
            ..Default::default()
        }),
        reason: "incident".into(),
        ..Default::default()
    });
    // Give the pushed lock time to reach the feed and tear the connection down.
    let mut torn_down = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let (code, _o, _e) = exec(&client, &["ssh", "-S", SOCK, "-O", "check", TARGET]).await;
        if code != Some(0) {
            torn_down = true;
            break;
        }
    }
    assert!(
        torn_down,
        "a mid-connection Lock must tear the multiplexed master down"
    );

    // A fresh multiplexed exec after teardown must not run on the node.
    let (code, stdout, _e) = exec(
        &client,
        &["ssh", "-S", SOCK, TARGET, "echo", "SHOULD_NOT_RUN"],
    )
    .await;
    assert_ne!(code, Some(0), "no channel may run after the lock teardown");
    assert!(
        !stdout.contains("SHOULD_NOT_RUN"),
        "no output after teardown; stdout={stdout:?}"
    );

    let _ = sd_tx.send(());
    drop(client);
    drop(node);
    Ok(())
}
