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

/// Read half of F-ha-connect-nodename-1, name≠uuid: the client addresses the node by its
/// HUMAN NAME (`web-01`), the CP resolves it to a DISTINCT id, and the whole downstream keys
/// on that CP-resolved id (dial + inner-cert). Proves the Gateway forwards the NAME and does
/// NOT leak the raw parsed string past resolution — the regression guard for the Part A
/// downstream fix (NodeTarget/NodeDial.node_id -> context.node_id): without it,
/// SignContext.node_id is the parsed name "web-01" while the session token is bound to the
/// resolved id, so SignSessionCertificate rejects (ctx.node_id != token.node_id) and the
/// session fails closed. With the fix the end-to-end session succeeds.
#[tokio::test]
async fn addressing_by_name_resolves_to_a_distinct_cp_id() -> anyhow::Result<()> {
    const NODE_UUID: &str = "11111111-1111-4111-8111-111111111111";
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;

    // Client addresses by NAME; the CP inventory (allow, connection) is keyed by the distinct id.
    cp.map_node_name("web-01", NODE_UUID);
    cp.register_pin(&pin.fingerprint, "alice", &["deploy"]);
    cp.allow("alice", NODE_UUID, "deploy");
    let trust = cp.pinned_verification(host_key.public_wire.clone());
    cp.set_node_connection(NODE_UUID, &format!("127.0.0.1:{node_port}"), trust);

    let (gw_port, _sd) = start_gateway(&cp, Arc::new(gw_config())).await;
    let client = client_container(&pin).await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        ssh_cmd(gw_port, &[], "deploy%web-01", "echo DISTINCT_OK"),
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "name-addressed session must succeed when the CP resolves name->a distinct id; stderr={stderr}"
    );
    assert!(stdout.contains("DISTINCT_OK"), "stdout={stdout:?}");

    // The Gateway forwarded the NAME (not the id) for CP-side resolution.
    let req = cp
        .last_authorize_request()
        .expect("an AuthorizeRequest reached the CP");
    assert_eq!(req.node_name, "web-01", "the human NAME is forwarded");

    drop(node);
    Ok(())
}

// ── ProxyJump host-cert MITM (Session Sixteen, Part C; §9.3/§11, FR-ADDR-1) ──────
//
// `ssh -J gw deploy@web-01` opens a direct-tcpip forward to the node through the
// (authenticated) jump connection; the Gateway TERMINATES that inner hop, presenting
// a host-CA-signed host cert for `web-01`. A stock client with one `@cert-authority`
// line verifies it with NO TOFU, then the full session seam runs on the node.

/// Write `content` to `path` inside the client container (small config/known_hosts
/// files). `content` must contain no single quotes (ssh_config / base64 keys don't).
async fn write_client_file(container: &ContainerAsync<GenericImage>, path: &str, content: &str) {
    let (code, _o, e) = ssh_exec(
        container,
        vec![
            "sh".into(),
            "-c".into(),
            format!("printf '%s' '{content}' > {path}"),
        ],
    )
    .await;
    assert_eq!(code, Some(0), "write {path} failed: {e}");
}

/// The `@cert-authority * <host-CA>` known_hosts line the client installs once so it
/// trusts the Gateway's outer host cert for the node namespace (the consensual MITM).
fn cert_authority_line(cp: &MockCp) -> String {
    let ca = ssh_key::PublicKey::from_bytes(&cp.host_ca_public_wire())
        .unwrap()
        .to_openssh()
        .unwrap();
    format!("@cert-authority * {ca}")
}

/// A client ssh_config: the `jump` host is the Gateway (its own host key is not the
/// no-TOFU boundary → no host-key check); the `web-01` host is reached via ProxyJump
/// and verified STRICTLY against `known_hosts` (the `@cert-authority` line). This
/// separation is what proves the *node* is cert-verified with no TOFU.
fn proxyjump_ssh_config(gw_port: u16, known_hosts: &str) -> String {
    format!(
        "Host jump\n\
         \tHostName 127.0.0.1\n\
         \tPort {gw_port}\n\
         \tUser deploy\n\
         \tIdentityFile /root/pin_key\n\
         \tIdentitiesOnly yes\n\
         \tPreferredAuthentications publickey\n\
         \tStrictHostKeyChecking no\n\
         \tUserKnownHostsFile /dev/null\n\
         \tBatchMode yes\n\
         \n\
         Host web-01\n\
         \tProxyJump jump\n\
         \tUser deploy\n\
         \tIdentityFile /root/pin_key\n\
         \tIdentitiesOnly yes\n\
         \tPreferredAuthentications publickey\n\
         \tUserKnownHostsFile {known_hosts}\n\
         \tStrictHostKeyChecking yes\n\
         \tBatchMode yes\n\
         \tConnectTimeout 30\n"
    )
}

async fn start_proxyjump_gateway(cp: &MockCp) -> (u16, tokio::sync::oneshot::Sender<()>) {
    let mut cfg = gw_config();
    cfg.proxy_jump = gateway_core::config::ProxyJumpConfig { enabled: true };
    start_gateway(cp, Arc::new(cfg)).await
}

#[tokio::test]
async fn proxyjump_host_cert_mitm_runs_on_node() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_named_node(&cp, &pin, &host_key, ADDR_NODE, node_port).await;

    let (gw_port, _sd) = start_proxyjump_gateway(&cp).await;
    let client = client_container(&pin).await;
    write_client_file(&client, "/root/known_hosts_ca", &cert_authority_line(&cp)).await;
    write_client_file(
        &client,
        "/root/ssh_config",
        &proxyjump_ssh_config(gw_port, "/root/known_hosts_ca"),
    )
    .await;

    // ssh -J gw deploy@web-01 — the host cert is verified via `@cert-authority`.
    let (code, stdout, stderr) = ssh_exec(
        &client,
        vec![
            "ssh".into(),
            "-F".into(),
            "/root/ssh_config".into(),
            "web-01".into(),
            "echo PROXYJUMP_OK; id -un".into(),
        ],
    )
    .await;
    assert_eq!(
        code,
        Some(0),
        "ProxyJump host-cert MITM must run on the node; stderr={stderr}"
    );
    assert!(stdout.contains("PROXYJUMP_OK"), "stdout={stdout:?}");
    assert!(
        stdout.contains("deploy"),
        "ran as the granted login; stdout={stdout:?}"
    );

    // The node was addressed by human NAME through the inner hop's direct-tcpip target.
    let req = cp
        .last_authorize_request()
        .expect("an AuthorizeRequest reached the CP");
    assert_eq!(
        req.node_name, ADDR_NODE,
        "the direct-tcpip node name is authorized"
    );

    drop(node);
    Ok(())
}

#[tokio::test]
async fn proxyjump_without_cert_authority_is_refused_no_tofu() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_named_node(&cp, &pin, &host_key, ADDR_NODE, node_port).await;

    let (gw_port, _sd) = start_proxyjump_gateway(&cp).await;
    let client = client_container(&pin).await;
    // Empty known_hosts (NO @cert-authority) + strict checking: the presented host
    // cert cannot be verified and must be REJECTED — never trust-on-first-use.
    write_client_file(&client, "/root/known_hosts_empty", "").await;
    write_client_file(
        &client,
        "/root/ssh_config",
        &proxyjump_ssh_config(gw_port, "/root/known_hosts_empty"),
    )
    .await;

    let (code, stdout, stderr) = ssh_exec(
        &client,
        vec![
            "ssh".into(),
            "-F".into(),
            "/root/ssh_config".into(),
            "web-01".into(),
            "echo SHOULD_NOT_RUN".into(),
        ],
    )
    .await;
    assert_ne!(
        code,
        Some(0),
        "an unverifiable host cert must be refused (no TOFU)"
    );
    assert!(
        !stdout.contains("SHOULD_NOT_RUN"),
        "the session must NOT run without @cert-authority; stdout={stdout:?}"
    );
    assert!(
        stderr
            .to_lowercase()
            .contains("host key verification failed"),
        "the client rejected the host (no TOFU); stderr={stderr}"
    );

    drop(node);
    Ok(())
}

#[tokio::test]
async fn proxyjump_refuses_agent_forwarding() -> anyhow::Result<()> {
    build_images().await?;
    let cp = MockCp::start().await;
    let pin = gen_key(Algorithm::Ed25519);
    let host_key = gen_key(Algorithm::Ed25519);
    let (node, node_port) = start_node(&cp, &host_key).await?;
    wire_named_node(&cp, &pin, &host_key, ADDR_NODE, node_port).await;

    let (gw_port, _sd) = start_proxyjump_gateway(&cp).await;
    let client = client_container(&pin).await;
    write_client_file(&client, "/root/known_hosts_ca", &cert_authority_line(&cp)).await;
    write_client_file(
        &client,
        "/root/ssh_config",
        &proxyjump_ssh_config(gw_port, "/root/known_hosts_ca"),
    )
    .await;

    // Run a real agent locally and request forwarding (-A). The Gateway refuses the
    // auth-agent channel (FR-SESS-2), so the NODE sees no forwarded agent socket.
    let (code, stdout, stderr) = ssh_exec(
        &client,
        vec![
            "sh".into(),
            "-c".into(),
            "eval \"$(ssh-agent -s)\" >/dev/null 2>&1; ssh-add /root/pin_key >/dev/null 2>&1; \
             ssh -A -F /root/ssh_config web-01 'echo AGENT=${SSH_AUTH_SOCK:-none}'"
                .into(),
        ],
    )
    .await;
    assert_eq!(code, Some(0), "the session still runs; stderr={stderr}");
    assert!(
        stdout.contains("AGENT=none"),
        "agent forwarding must be refused on the ProxyJump path (no forwarded socket on the node); stdout={stdout:?}"
    );

    drop(node);
    Ok(())
}
