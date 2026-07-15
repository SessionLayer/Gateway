//! Session Eight end-to-end: the **first real end-to-end SSH into a node**.
//!
//! A stock OpenSSH client (Debian 13 container, never host ssh) authenticates at
//! the Gateway's outer leg (pin → CP), the Gateway authorizes, mints the inner
//! cert via the mock CP's session CA, **verifies the node's host identity (no
//! TOFU)**, dials a real Debian 13 node container, and **bridges** the two legs —
//! so `echo` runs on the node and its output returns to the client.
//!
//! Networking (as S7): the client container uses `--network host`, so its
//! `127.0.0.1` is the host loopback the in-process Gateway binds to; the node
//! runs on the default bridge with a mapped sshd port the Gateway dials at
//! `127.0.0.1:<mapped>`.
//!
//! Host-identity matrix (Design §9.3, gates a–d): host-CA-signed cert verifies;
//! a pinned key verifies; an untrusted key aborts (no TOFU); a mismatched host
//! cert principal aborts.

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway_core::config::{InnerLegServerConfig, SshServerConfig};
use gateway_core::pb::Capability;
use gateway_core::ssh;
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use support::MockCp;
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};

const CLIENT_IMAGE: &str = "sessionlayer-gw-sshclient";
const CLIENT_TAG: &str = "s8";
const NODE_IMAGE: &str = "sessionlayer-gw-testnode";
const NODE_TAG: &str = "s8";
const NODE_ID: &str = "node-e2e";

fn ensure_docker_host() {
    if std::env::var_os("DOCKER_HOST").is_some() {
        return;
    }
    if let Ok(out) = std::process::Command::new("docker")
        .args([
            "context",
            "inspect",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ])
        .output()
    {
        let host = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && !host.is_empty() {
            std::env::set_var("DOCKER_HOST", host);
        }
    }
}

async fn build_image(subdir: &str, tag: &str) -> anyhow::Result<()> {
    ensure_docker_host();
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures")
        .join(subdir);
    anyhow::ensure!(dir.is_dir(), "fixture missing: {}", dir.display());
    let tag = tag.to_string();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("docker")
            .args(["build", "-t", &tag])
            .arg(&dir)
            .output()
    })
    .await??;
    anyhow::ensure!(
        out.status.success(),
        "docker build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

async fn build_images() -> anyhow::Result<()> {
    build_image("ssh-client", &format!("{CLIENT_IMAGE}:{CLIENT_TAG}")).await?;
    build_image("sshd", &format!("{NODE_IMAGE}:{NODE_TAG}")).await?;
    Ok(())
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

/// Start the Debian 13 node trusting the session CA and presenting the given
/// **injected** ed25519 host key (so the test controls what the Gateway sees at
/// KEX — russh prefers ed25519). Returns the container + its mapped sshd port.
async fn start_node(
    cp: &MockCp,
    host_key: &KeyMat,
) -> anyhow::Result<(ContainerAsync<GenericImage>, u16)> {
    let node = GenericImage::new(NODE_IMAGE, NODE_TAG)
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

async fn start_gateway(
    cp: &MockCp,
    config: Arc<SshServerConfig>,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    let deps = support::outer_leg_deps(cp, config.clone()).await;
    let server = ssh::bind(config, deps).await.unwrap();
    let port = server.local_addr().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));
    (port, tx)
}

fn gw_config() -> SshServerConfig {
    SshServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        login_grace_secs: 60,
        device_flow: gateway_core::config::DeviceFlowConfig {
            heartbeat_interval_secs: 1,
            poll_timeout_secs: 20,
        },
        inner: InnerLegServerConfig {
            // Snappy fail-closed bounds so the abort/offline cases are fast.
            connect_timeout_secs: 4,
            handshake_timeout_secs: 8,
            max_session_idle_secs: 120,
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn client_container(pin_key: &KeyMat) -> ContainerAsync<GenericImage> {
    GenericImage::new(CLIENT_IMAGE, CLIENT_TAG)
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

/// Register the outer-leg pin (alice→[deploy]) + the grant on the fixed node.
fn grant(cp: &MockCp, pin: &KeyMat) {
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", NODE_ID, "deploy");
}

// ── Headline: full end-to-end with host-CA verification ─────────────────────

#[tokio::test]
async fn end_to_end_command_shell_and_sftp_over_host_ca() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    cp.set_capabilities(
        NODE_ID,
        &[Capability::Shell, Capability::Exec, Capability::Sftp],
    );

    let (node, node_port) = start_node(&cp, &host_key).await?;
    // Host-CA path: sign the node's host key into a host cert (principal = node
    // id) and hand the Gateway the CA + expected principal + cert (Part C, gate a).
    let (_cert_line, cert_wire) = cp.sign_host_cert(&host_key.public_wire, &[NODE_ID], 3600);
    let trust = cp.host_ca_verification(cert_wire, &[NODE_ID]);
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config())).await;
    let client = client_container(&pin).await;

    // (1) The first real end-to-end: a command runs on the node, output returns.
    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &[], "deploy%node-e2e", "echo IT_WORKS; hostname"),
    )
    .await;
    assert_eq!(code, Some(0), "e2e command must succeed; stderr={stderr}");
    assert!(
        stdout.contains("IT_WORKS"),
        "node output must return; stdout={stdout:?}"
    );

    // (2) An interactive-style PTY session runs a command on the node.
    let (code, stdout, _e) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &["-tt"], "deploy%node-e2e", "echo PTY_$(id -un)"),
    )
    .await;
    assert_eq!(code, Some(0), "pty session must succeed");
    assert!(
        stdout.contains("PTY_deploy"),
        "pty runs as the cert principal; stdout={stdout:?}"
    );

    // (3) SFTP works when granted (the sftp subsystem is bridged).
    let (code, stdout, stderr) = ssh_exec(
        &client,
        vec![
            "sh".into(),
            "-c".into(),
            format!(
                "printf 'pwd\\nquit\\n' | sftp -i /root/pin_key -o IdentitiesOnly=yes \
                 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
                 -P {gw_port} -b - deploy%node-e2e@127.0.0.1"
            ),
        ],
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "sftp (granted) must succeed; stderr={stderr}"
    );
    assert!(
        stdout.contains("/home/deploy"),
        "sftp pwd shows the home dir; stdout={stdout:?}"
    );

    drop(node);
    Ok(())
}

// ── Host-verify matrix (gates b, c, d) ──────────────────────────────────────

#[tokio::test]
async fn pinned_host_key_verifies() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);

    let (node, node_port) = start_node(&cp, &host_key).await?;
    // Gate b: pin the node's exact host key.
    let trust = cp.pinned_verification(host_key.public_wire.clone());
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config())).await;
    let client = client_container(&pin).await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &[], "deploy%node-e2e", "echo PINNED_OK"),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "pinned host key must verify; stderr={stderr}"
    );
    assert!(stdout.contains("PINNED_OK"));
    drop(node);
    Ok(())
}

#[tokio::test]
async fn untrusted_host_key_aborts_no_tofu() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    let impostor = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);

    let (node, node_port) = start_node(&cp, &host_key).await?;
    // Gate c: pin a DIFFERENT key than the node presents → abort (never TOFU).
    let trust = cp.pinned_verification(impostor.public_wire.clone());
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config())).await;
    let client = client_container(&pin).await;

    let (code, _stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &[], "deploy%node-e2e", "echo SHOULD_NOT_RUN"),
    )
    .await;
    assert_ne!(code, Some(0), "an untrusted host key must abort (no TOFU)");
    assert!(
        stderr.contains("offline or unavailable"),
        "generic user error; stderr={stderr:?}"
    );
    assert!(!stderr.contains("SHOULD_NOT_RUN"));
    drop(node);
    Ok(())
}

#[tokio::test]
async fn mismatched_host_cert_principal_aborts() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);

    let (node, node_port) = start_node(&cp, &host_key).await?;
    // Gate d: a valid host-CA cert, but its principal is a DIFFERENT node → abort.
    let (_l, cert_wire) = cp.sign_host_cert(&host_key.public_wire, &["some-other-node"], 3600);
    let trust = cp.host_ca_verification(cert_wire, &[NODE_ID]);
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config())).await;
    let client = client_container(&pin).await;

    let (code, _stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &[], "deploy%node-e2e", "echo NOPE"),
    )
    .await;
    assert_ne!(code, Some(0), "a mismatched host-cert principal must abort");
    assert!(
        stderr.contains("offline or unavailable"),
        "generic user error; stderr={stderr:?}"
    );
    drop(node);
    Ok(())
}

// ── Capability gate (SFTP withheld) + node offline ──────────────────────────

#[tokio::test]
async fn sftp_is_refused_when_withheld() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);
    // Default capabilities = shell+exec (no SFTP).

    let (node, node_port) = start_node(&cp, &host_key).await?;
    let trust = cp.pinned_verification(host_key.public_wire.clone());
    cp.set_node_connection(NODE_ID, &format!("127.0.0.1:{node_port}"), trust);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config())).await;
    let client = client_container(&pin).await;

    // exec still works (granted)…
    let (code, _o, _e) = ssh_exec(&client, ssh_cmd(gw_port, &[], "deploy%node-e2e", "true")).await;
    assert_eq!(code, Some(0), "exec is granted");

    // …but the SFTP subsystem is refused (capability gate).
    let (code, _stdout, _stderr) = ssh_exec(
        &client,
        vec![
            "sh".into(),
            "-c".into(),
            format!(
                "printf 'pwd\\nquit\\n' | sftp -i /root/pin_key -o IdentitiesOnly=yes \
                 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
                 -P {gw_port} -b - deploy%node-e2e@127.0.0.1"
            ),
        ],
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "sftp must be refused when the capability is withheld"
    );
    drop(node);
    Ok(())
}

#[tokio::test]
async fn unreachable_node_is_node_offline() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    grant(&cp, &pin);

    // Point the connection at a dead port (no node), with a valid pin: the dial
    // fails closed → §7.1 "node offline" (auth+authz already succeeded).
    let trust = cp.pinned_verification(host_key.public_wire.clone());
    cp.set_node_connection(NODE_ID, "127.0.0.1:1", trust);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config())).await;
    let client = client_container(&pin).await;

    let (code, _stdout, stderr) =
        ssh_exec(&client, ssh_cmd(gw_port, &[], "deploy%node-e2e", "true")).await;
    assert_ne!(code, Some(0), "an unreachable node must fail closed");
    assert!(
        stderr.contains("offline or unavailable"),
        "node-offline outcome; stderr={stderr:?}"
    );
    Ok(())
}

// ── Session Sixteen addressing (Part A name-forward + Part B wildcard DNS) ────

/// The human-named node these addressing cases reach (a pin + grant + pinned host key).
const ADDR_NODE: &str = "web-01";

async fn wire_named_node(cp: &MockCp, pin: &KeyMat, host_key: &KeyMat, name: &str, node_port: u16) {
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", name, "deploy");
    let trust = cp.pinned_verification(host_key.public_wire.clone());
    cp.set_node_connection(name, &format!("127.0.0.1:{node_port}"), trust);
}

/// Part A (FR-ADDR-1): `ssh deploy%web-01@gw` reaches the node addressed by its human
/// NAME, and the Gateway forwards that NAME to `Authorize` (the CP resolves name→id
/// server-side; closes the read half of F-ha-connect-nodename-1).
#[tokio::test]
async fn addressing_by_human_name_forwards_the_node_name() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_named_node(&cp, &pin, &host_key, ADDR_NODE, node_port).await;

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config())).await;
    let client = client_container(&pin).await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &[], "deploy%web-01", "echo NAME_OK"),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "addressing by human name must reach the node; stderr={stderr}"
    );
    assert!(stdout.contains("NAME_OK"), "stdout={stdout:?}");

    let req = cp
        .last_authorize_request()
        .expect("an AuthorizeRequest reached the CP");
    assert_eq!(
        req.node_name, ADDR_NODE,
        "the parsed node NAME is forwarded for CP-side name→id resolution"
    );

    drop(node);
    Ok(())
}

/// Part B (FR-ADDR-1, wildcard DNS — SERVER side): a username whose node carries the
/// operator's DNS suffix (`deploy%web-01.ssh.corp`) reaches the same node as the bare
/// `deploy%web-01`, because the Gateway strips the configured `ssh.corp` suffix before
/// resolution, and the BARE name is what is forwarded to `Authorize`.
///
/// This drives the encoded username DIRECTLY (a real deployment produces it via a
/// client-side rewrite — see docs/addressing.md; note the stock-OpenSSH `User %r%%%h`
/// ssh_config token does NOT work, since `User` rejects %r/%h — so the client mechanism
/// is out of scope for this E2E, which proves the GATEWAY strip that Part B owns).
#[tokio::test]
async fn addressing_wildcard_dns_suffix_is_stripped() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_named_node(&cp, &pin, &host_key, ADDR_NODE, node_port).await;

    // Turn on wildcard DNS: strip `ssh.corp` to recover the bare node name `web-01`.
    let mut cfg = gw_config();
    cfg.node_dns_suffixes = vec!["ssh.corp".to_string()];
    let (gw_port, _sd) = start_gateway(&cp, Arc::new(cfg)).await;
    let client = client_container(&pin).await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &[], "deploy%web-01.ssh.corp", "echo WILDCARD_OK"),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "the suffixed node must reach the node after the strip; stderr={stderr}"
    );
    assert!(stdout.contains("WILDCARD_OK"), "stdout={stdout:?}");

    let req = cp
        .last_authorize_request()
        .expect("an AuthorizeRequest reached the CP");
    assert_eq!(
        req.node_name, ADDR_NODE,
        "the wildcard suffix is stripped before the name is forwarded"
    );

    drop(node);
    Ok(())
}
